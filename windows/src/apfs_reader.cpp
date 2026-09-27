#define NOMINMAX
#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include "vphone/apfs_reader.hpp"

#include <cstring>
#include <set>
#include <limits>
#include <sstream>

namespace vphone {
namespace {

constexpr std::uint32_t kNxsbMagic = 0x4253584Eu; // 'NXSB'
constexpr std::uint32_t kApsbMagic = 0x42535041u; // 'APSB'
constexpr std::uint32_t kOmapType = 0x0000000Bu;
// APFS object types: OBJECT_TYPE_BTREE_NODE spans both observed
// encodings (2 and 3) in real fixtures; omap/fstree objects carry
// their own concrete kinds.
constexpr std::uint32_t kBtreeType = 0x00000002u;
constexpr std::uint32_t kBtreeTypeNode = 0x00000003u;
// Volume catalog root object subtype: FSTREE (apfs-fuse OBJ_FSTREE,
// linux-apfs-rw APFS_OBJ_FSTREE).
constexpr std::uint32_t kFstreeSubtype = 0x0000000Eu;
// Authoritative APFS object-type constants (apfs-fuse, linux-apfs-rw,
// Sleuth Kit): the concrete object kind occupies the low 16 bits;
// storage class and flags are separate bit fields above it.
constexpr std::uint32_t kObjectTypeMask = 0x0000FFFFu;
constexpr std::uint32_t kObjStorageTypeMask = 0xC0000000u;
constexpr std::uint32_t kObjVirtual = 0x00000000u;
constexpr std::uint32_t kObjPhysical = 0x40000000u;
constexpr std::uint32_t kObjEphemeral = 0x80000000u;
constexpr std::uint32_t kObjNoHeader = 0x20000000u;
constexpr std::uint32_t kObjEncrypted = 0x10000000u;
constexpr std::uint32_t kObjNonpersistent = 0x08000000u;

// B-tree node flags.
constexpr std::uint16_t kBtreeRoot = 0x0001;
constexpr std::uint16_t kBtreeLeaf = 0x0002;
constexpr std::uint16_t kBtreeFixedKvSize = 0x0004;
constexpr std::uint16_t kBtreeHashed = 0x0008;

// btree_node_phys_t geometry: obj_phys_t(0x20) + flags(2) + level(2)
// + nkeys(4) + table_space(4) + free_space(4) + key_free_list(4)
// + val_free_list(4) = 0x38-byte header; btn_data follows.
constexpr std::size_t kBtreeNodeHeaderSize = 0x38;
// btree_info_t footer is 0x28 bytes at the end of a root node.
constexpr std::size_t kBtreeInfoSize = 0x28;


std::uint32_t read_le32(const std::uint8_t* p) {
    return
        static_cast<std::uint32_t>(p[0]) |
        (static_cast<std::uint32_t>(p[1]) << 8) |
        (static_cast<std::uint32_t>(p[2]) << 16) |
        (static_cast<std::uint32_t>(p[3]) << 24);
}

std::uint64_t read_le64(const std::uint8_t* p) {
    std::uint64_t value = 0;
    for (int i = 7; i >= 0; --i) {
        value = (value << 8) | p[i];
    }
    return value;
}

// APFS Fletcher-64 block checksum: the first 8 bytes of the object
// header hold the checksum over the remaining block bytes in 32-bit
// words. Same algorithm as apfs_snapshot_portable's
// apfs_snapshot_checksum (obj_phys_t.o_cksum placement).
std::uint64_t apfs_fletcher64(
    const std::uint8_t* block,
    std::size_t block_size
) {
    constexpr std::uint64_t modulus = 0xFFFFFFFFull;
    std::uint64_t s1 = 0;
    std::uint64_t s2 = 0;

    for (std::size_t off = 8; off + 4 <= block_size; off += 4) {
        const std::uint64_t word = read_le32(block + off);
        s1 = (s1 + word) % modulus;
        s2 = (s2 + s1) % modulus;
    }

    const std::uint64_t c1 = modulus - ((s1 + s2) % modulus);
    const std::uint64_t c2 = modulus - ((s1 + c1) % modulus);
    return c1 | (c2 << 32);
}

bool apfs_block_checksum_ok(const std::vector<std::uint8_t>& block) {
    if (block.size() < 16) {
        return false;
    }
    return apfs_fletcher64(block.data(), block.size()) ==
           read_le64(block.data());
}

std::string win_error(const char* operation) {
    std::ostringstream out;
    out << operation << " failed with Win32 error " << GetLastError();
    return out.str();
}

bool read_block(
    HANDLE file,
    std::uint64_t block,
    std::uint32_t block_size,
    std::vector<std::uint8_t>& buffer,
    std::string& error
) {
    LARGE_INTEGER distance{};
    distance.QuadPart =
        static_cast<LONGLONG>(block) * static_cast<LONGLONG>(block_size);
    if (!SetFilePointerEx(file, distance, nullptr, FILE_BEGIN)) {
        error = win_error("SetFilePointerEx");
        return false;
    }

    DWORD read = 0;
    if (!ReadFile(
            file,
            buffer.data(),
            static_cast<DWORD>(buffer.size()),
            &read,
            nullptr
        )) {
        error = win_error("ReadFile");
        return false;
    }

    if (read != buffer.size()) {
        error = "short read";
        return false;
    }

    return true;
}

bool valid_block_geometry(
    std::uint32_t block_size,
    std::uint64_t block_count,
    std::uint64_t file_size,
    std::string& error
) {
    if (block_size == 0 || (block_size & (block_size - 1)) != 0) {
        error = "APFS block size is not a power of two";
        return false;
    }
    if (block_count == 0 || block_count > std::numeric_limits<std::uint32_t>::max()) {
        error = "APFS block count is out of range";
        return false;
    }

    const std::uint64_t data_size =
        static_cast<std::uint64_t>(block_count) * block_size;
    if (data_size > file_size) {
        error = "APFS block count exceeds file size";
        return false;
    }

    return true;
}

// Decode the btree_node_phys_t header and, for root nodes, the
// btree_info_t footer at block_size - 0x28. Fails closed when the
// declared geometry exceeds the block.
bool decode_btree_node(
    const std::vector<std::uint8_t>& block,
    std::uint32_t block_size,
    ApfsBtreeNodeInfo& node,
    std::string& error
) {
    if (block.size() < block_size ||
        block_size < kBtreeNodeHeaderSize + kBtreeInfoSize) {
        error = "block too small for B-tree node geometry";
        return false;
    }

    const std::uint8_t* p = block.data();

    node.flags =
        static_cast<std::uint16_t>(p[0x20]) |
        (static_cast<std::uint16_t>(p[0x21]) << 8);
    node.level =
        static_cast<std::uint16_t>(p[0x22]) |
        (static_cast<std::uint16_t>(p[0x23]) << 8);
    node.nkeys = read_le32(p + 0x24);

    const std::uint16_t table_off =
        static_cast<std::uint16_t>(p[0x28]) |
        (static_cast<std::uint16_t>(p[0x29]) << 8);
    const std::uint16_t table_len =
        static_cast<std::uint16_t>(p[0x2a]) |
        (static_cast<std::uint16_t>(p[0x2b]) << 8);

    // Table space is relative to btn_data (0x38-byte header end).
    const std::uint64_t toc_start =
        static_cast<std::uint64_t>(kBtreeNodeHeaderSize) + table_off;
    const std::uint64_t toc_end = toc_start + table_len;
    if (toc_end > block_size) {
        error = "B-tree table space exceeds block";
        return false;
    }

    // Geometry: fixed-KV TOC entries are 4-byte kvoff {k,v} pairs
    // (apfs-fuse BTreeNodeFix, linux-apfs-rw locate_key/locate_value);
    // variable-KV TOC entries are 8 bytes {k_off,k_len,v_off,v_len}.
    const std::size_t entry_size =
        (node.flags & kBtreeFixedKvSize) ? 4 : 8;
    if (node.nkeys > 0 &&
        table_len < node.nkeys * entry_size) {
        error = "B-tree table space too small for declared key count";
        return false;
    }

    // Root nodes carry a btree_info_t footer.
    if (node.flags & kBtreeRoot) {
        const std::size_t footer_off = block_size - kBtreeInfoSize;
        node.has_footer = true;
        node.bt_flags = read_le32(p + footer_off);
        node.node_size = read_le32(p + footer_off + 4);
        node.key_size = read_le32(p + footer_off + 8);
        node.val_size = read_le32(p + footer_off + 12);

        if (node.node_size != block_size) {
            error = "B-tree root footer node size does not match block size";
            return false;
        }
    }

    return true;
}

// Walk an OMAP B-tree and collect every {oid,xid} -> paddr mapping.
//
// Authoritative fixed-KV semantics (apfs-fuse BTreeNodeFix::GetEntry,
// linux-apfs-rw apfs_node_locate_key/locate_value):
//   - Every TOC entry is a 4-byte kvoff { uint16_t k; uint16_t v; }
//     at btn_data + table_space.off + i*4.
//   - key_ptr   = key_base + kvoff.k
//   - value_ptr = value_base - kvoff.v
//   - key_base  = 0x38 + table_space.off + table_space.len
//   - value_base = block_size - 0x28 (root) or block_size (non-root)
//   - OMAP key   = { oid u64, xid u64 }               (16 bytes)
//   - OMAP value = { flags u32, size u32, paddr u64 } (16 bytes, leaf)
//   - OMAP interior value = child OID u64             (8 bytes)
//
// Value offsets come only from the on-disk kvoff.v field; they are
// never synthesized from entry index.
bool omap_collect_entries(
    HANDLE file,
    std::uint32_t block_size,
    std::uint64_t block,
    std::uint64_t block_count,
    bool is_root,
    std::vector<ApfsOmapEntry>& out,
    std::set<std::uint64_t>& visited,
    std::string& error
) {
    if (block >= block_count) {
        error = "OMAP tree references block beyond container";
        return false;
    }
    if (!visited.insert(block).second) {
        error = "OMAP tree cycle detected";
        return false;
    }

    std::vector<std::uint8_t> buf(block_size, 0);
    if (!read_block(file, block, block_size, buf, error)) {
        return false;
    }

    if (!apfs_block_checksum_ok(buf)) {
        error = "OMAP node failed Fletcher-64 checksum";
        return false;
    }

    const std::uint32_t type = read_le32(buf.data() + 24);
    const std::uint32_t type_kind = type & kObjectTypeMask;
    if (type_kind != kBtreeType && type_kind != kBtreeTypeNode) {
        error = "OMAP tree node is not a B-tree object";
        return false;
    }

    ApfsBtreeNodeInfo node;
    if (!decode_btree_node(buf, block_size, node, error)) {
        return false;
    }

    const std::uint8_t* p = buf.data();
    const bool fixed_kv = (node.flags & kBtreeFixedKvSize) != 0;

    const std::uint16_t tofs =
        static_cast<std::uint16_t>(p[0x28]) |
        (static_cast<std::uint16_t>(p[0x29]) << 8);
    const std::uint16_t tlen =
        static_cast<std::uint16_t>(p[0x2a]) |
        (static_cast<std::uint16_t>(p[0x2b]) << 8);

    const std::uint64_t key_base =
        static_cast<std::uint64_t>(kBtreeNodeHeaderSize) + tofs + tlen;
    const std::uint64_t value_base = is_root
        ? static_cast<std::uint64_t>(block_size) - kBtreeInfoSize
        : static_cast<std::uint64_t>(block_size);

    for (std::uint32_t i = 0; i < node.nkeys; ++i) {
        if (!fixed_kv) {
            error = "variable-KV OMAP nodes are not supported yet";
            return false;
        }

        const std::uint64_t toc =
            static_cast<std::uint64_t>(kBtreeNodeHeaderSize) + tofs +
            static_cast<std::uint64_t>(i) * 4;
        if (toc + 4 > block_size) {
            error = "OMAP TOC entry exceeds block";
            return false;
        }

        const std::uint16_t key_off =
            static_cast<std::uint16_t>(p[toc]) |
            (static_cast<std::uint16_t>(p[toc + 1]) << 8);
        const std::uint16_t val_off =
            static_cast<std::uint16_t>(p[toc + 2]) |
            (static_cast<std::uint16_t>(p[toc + 3]) << 8);

        const std::uint64_t kp = key_base + key_off;
        const std::uint64_t vp = value_base - val_off;

        if (node.level > 0) {
            if (vp + 8 > block_size) {
                error = "OMAP interior value exceeds block";
                return false;
            }
            const std::uint64_t child = read_le64(p + vp);
            if (!omap_collect_entries(
                    file,
                    block_size,
                    child,
                    block_count,
                    false,
                    out,
                    visited,
                    error
                )) {
                return false;
            }
            continue;
        }

        if (kp + 16 > block_size || vp + 16 > block_size) {
            error = "OMAP leaf entry exceeds block bounds";
            return false;
        }

        ApfsOmapEntry entry;
        entry.oid = read_le64(p + kp);
        entry.xid = read_le64(p + kp + 8);
        entry.flags = read_le32(p + vp);
        entry.size = read_le32(p + vp + 4);
        entry.paddr = read_le64(p + vp + 8);
        out.push_back(entry);
    }

    return true;
}
// ---------------------------------------------------------------------------
// FSTREE catalog walk (variable-KV) with structural DIR_REC path lookup.
// ---------------------------------------------------------------------------

constexpr std::uint64_t kApfsRootDirCnid = 2;
constexpr std::uint64_t kObjIdMask = 0x0FFFFFFFFFFFFFFFull;
constexpr std::uint64_t kRecordTypeShift = 60;
constexpr std::uint64_t kApfsTypeDirRec = 9;
constexpr std::uint64_t kApfsTypeFileExtent = 8;
constexpr std::uint16_t kDrecValBaseSize = 18;
constexpr std::uint16_t kDrecFlagTypeMask = 0x000f;
constexpr std::uint16_t kDrecTypeDir = 4;
// APSB apfs_incompatible_features @ +0x38.
constexpr std::size_t kApsbIncompatOffset = 0x38;
constexpr std::uint64_t kIncompatCaseInsensitive = 0x1;
constexpr std::uint64_t kIncompatNormalizationInsensitive = 0x8;
constexpr std::uint32_t kHashedNameLenMask = 0x000003ff;

struct FstreeWalkCtx {
    HANDLE file = INVALID_HANDLE_VALUE;
    std::uint32_t block_size = 0;
    std::uint64_t block_count = 0;
    const std::vector<ApfsOmapEntry>* omap = nullptr;
    std::uint64_t volume_xid = 0;
    bool hashed_names = false;
    std::set<std::uint64_t> visited;
};

// Resolve a virtual OID through the volume OMAP (greatest xid <= vol xid).
bool omap_resolve(
    const FstreeWalkCtx& ctx,
    std::uint64_t oid,
    std::uint64_t& paddr,
    std::string& error
) {
    const ApfsOmapEntry* best = nullptr;
    for (const auto& e : *ctx.omap) {
        if (e.oid == oid && e.xid <= ctx.volume_xid &&
            e.paddr < ctx.block_count) {
            if (!best || e.xid > best->xid) {
                best = &e;
            }
        }
    }
    if (!best) {
        error = "OMAP could not resolve oid";
        return false;
    }
    paddr = best->paddr;
    return true;
}

// Visit every leaf DIR_REC record under a FSTREE node (recursing through
// OMAP-resolved interior children) and invoke match(parent_cnid, name,
// child_cnid). Returns false on any structural failure.
template <typename MatchFn>
bool fstree_visit_dir_records(
    FstreeWalkCtx& ctx,
    std::uint64_t node_oid,
    std::uint16_t expected_level,
    bool is_root,
    MatchFn match,
    std::string& error
) {
    std::uint64_t paddr = 0;
    if (!omap_resolve(ctx, node_oid, paddr, error)) {
        return false;
    }

    if (!ctx.visited.insert(node_oid).second) {
        error = "FSTREE cycle detected";
        return false;
    }

    std::vector<std::uint8_t> buf(ctx.block_size, 0);
    if (!read_block(ctx.file, paddr, ctx.block_size, buf, error)) {
        return false;
    }
    if (!apfs_block_checksum_ok(buf)) {
        error = "FSTREE node failed Fletcher-64 checksum";
        return false;
    }

    const std::uint32_t type = read_le32(buf.data() + 24);
    const std::uint32_t kind = type & kObjectTypeMask;
    if (kind != kBtreeType && kind != kBtreeTypeNode) {
        error = "FSTREE node is not a B-tree object";
        return false;
    }
    // Every FSTREE node (root, interior, leaf) must carry the FSTREE
    // subtype, not merely a generic B-tree kind.
    const std::uint32_t subtype = read_le32(buf.data() + 28);
    if (subtype != kFstreeSubtype) {
        error = "FSTREE child node subtype is not FSTREE";
        return false;
    }

    ApfsBtreeNodeInfo node;
    if (!decode_btree_node(buf, ctx.block_size, node, error)) {
        return false;
    }
    // Exact level contract: root equals root_level; every child equals
    // parent_level - 1; leaves are level 0. No level skipping.
    if (node.level != expected_level) {
        error = "FSTREE node level mismatch (expected exact descent)";
        return false;
    }

    const std::uint8_t* p = buf.data();
    if (node.flags & kBtreeFixedKvSize) {
        error = "FSTREE catalog nodes must be variable-KV";
        return false;
    }

    const std::uint16_t tofs =
        static_cast<std::uint16_t>(p[0x28]) |
        (static_cast<std::uint16_t>(p[0x29]) << 8);
    const std::uint16_t tlen =
        static_cast<std::uint16_t>(p[0x2a]) |
        (static_cast<std::uint16_t>(p[0x2b]) << 8);

    const std::uint64_t key_base =
        static_cast<std::uint64_t>(kBtreeNodeHeaderSize) + tofs + tlen;
    const std::uint64_t value_base = is_root
        ? static_cast<std::uint64_t>(ctx.block_size) - kBtreeInfoSize
        : static_cast<std::uint64_t>(ctx.block_size);

    for (std::uint32_t i = 0; i < node.nkeys; ++i) {
        // Variable-KV TOC: 8-byte kvloc {k_off, k_len, v_off, v_len}.
        const std::uint64_t toc =
            static_cast<std::uint64_t>(kBtreeNodeHeaderSize) + tofs +
            static_cast<std::uint64_t>(i) * 8;
        if (toc + 8 > ctx.block_size) {
            error = "FSTREE TOC entry exceeds block";
            return false;
        }

        const std::uint16_t k_off =
            static_cast<std::uint16_t>(p[toc]) |
            (static_cast<std::uint16_t>(p[toc + 1]) << 8);
        const std::uint16_t k_len =
            static_cast<std::uint16_t>(p[toc + 2]) |
            (static_cast<std::uint16_t>(p[toc + 3]) << 8);
        const std::uint16_t v_off =
            static_cast<std::uint16_t>(p[toc + 4]) |
            (static_cast<std::uint16_t>(p[toc + 5]) << 8);
        const std::uint16_t v_len =
            static_cast<std::uint16_t>(p[toc + 6]) |
            (static_cast<std::uint16_t>(p[toc + 7]) << 8);

        // Full bounds checks before any subtraction or pointer use:
        // key offset+length within the block, value offset within
        // value_base, value pointer+length within the block.
        if (k_off > ctx.block_size ||
            k_len > ctx.block_size - k_off) {
            error = "FSTREE key range exceeds block";
            return false;
        }
        const std::uint64_t kp = key_base + k_off;
        if (kp > ctx.block_size ||
            k_len > ctx.block_size - kp) {
            error = "FSTREE key base + range exceeds block";
            return false;
        }
        if (v_off > value_base) {
            error = "FSTREE value offset exceeds value base";
            return false;
        }
        const std::uint64_t vp = value_base - v_off;
        if (vp > ctx.block_size ||
            v_len > ctx.block_size - vp) {
            error = "FSTREE value range exceeds block";
            return false;
        }

        if (node.level > 0) {
            // Interior: recurse into OMAP-resolved child.
            if (v_len != 8 || vp + 8 > ctx.block_size) {
                error = "FSTREE interior value must be an 8-byte child OID";
                return false;
            }
            if (node.level < 1) {
                error = "FSTREE interior recursion underflow";
                return false;
            }
            const std::uint64_t child_oid = read_le64(p + vp);
            if (!fstree_visit_dir_records(
                    ctx,
                    child_oid,
                    node.level - 1,
                    false,
                    match,
                    error
                )) {
                return false;
            }
            continue;
        }

        // Leaf: decode DIR_REC key only when type matches.
        if (k_len < 10 || kp + k_len > ctx.block_size) {
            continue; // non-leaf-format or out-of-bounds; skip
        }

        const std::uint64_t hdr = read_le64(p + kp);
        const std::uint64_t parent_cnid = hdr & kObjIdMask;
        const std::uint64_t rec_type = hdr >> kRecordTypeShift;
        if (rec_type != kApfsTypeDirRec) {
            continue;
        }

        // Exact on-disk name validation: the embedded name_len must
        // equal key_len - header, the name must be non-empty, and the
        // final byte must be exactly NUL (one required terminator).
        std::uint64_t name_off = 0;
        std::size_t stored_len = 0;
        if (ctx.hashed_names) {
            if (k_len < 12) {
                continue;
            }
            const std::uint32_t len_hash = read_le32(p + kp + 8);
            stored_len = len_hash & kHashedNameLenMask;
            name_off = kp + 12;
        } else {
            stored_len =
                static_cast<std::uint16_t>(p[kp + 8]) |
                (static_cast<std::uint16_t>(p[kp + 9]) << 8);
            name_off = kp + 10;
        }

        const std::uint64_t header_size =
            ctx.hashed_names ? 12 : 10;
        if (stored_len < 1 ||
            stored_len != k_len - header_size) {
            continue;
        }

        if (name_off > ctx.block_size ||
            stored_len > ctx.block_size - name_off) {
            continue;
        }
        if (p[name_off + stored_len - 1] != '\0') {
            continue; // exactly one required terminator
        }
        const std::size_t logical_len = stored_len - 1;
        const char* name =
            reinterpret_cast<const char*>(p + name_off);

        // j_drec_val base: file_id u64 + date_added u64 + flags u16
        // = 18 bytes minimum before optional xfields.
        if (v_len < kDrecValBaseSize) {
            continue;
        }
        const std::uint64_t child_cnid = read_le64(p + vp);
        const std::uint16_t drec_flags =
            static_cast<std::uint16_t>(p[vp + 16]) |
            (static_cast<std::uint16_t>(p[vp + 17]) << 8);
        const std::uint16_t drec_type =
            drec_flags & kDrecFlagTypeMask;

        if (!match(
                parent_cnid,
                std::string(name, logical_len),
                child_cnid,
                drec_type
            )) {
            error = "path match callback failed";
            return false;
        }
    }

    return true;
}

// Structural path resolution: 2 -> System -> Library -> LaunchDaemons.
bool fstree_resolve_launchdaemons(
    FstreeWalkCtx& ctx,
    std::uint64_t root_oid,
    std::uint16_t root_level,
    std::uint64_t& out_cnid,
    std::string& error
) {
    std::uint64_t parent = kApfsRootDirCnid;
    static const char* const components[] = {"System", "Library", "LaunchDaemons"};

    for (int ci = 0; ci < 3; ++ci) {
        const std::string want = components[ci];
        bool found = false;
        std::uint64_t next = 0;

        // Fresh visited set per component (leaves may legitimately be
        // shared across lookups).
        ctx.visited.clear();

        auto matcher = [&](
            std::uint64_t p_cnid,
            const std::string& name,
            std::uint64_t c_cnid,
            std::uint16_t drec_type
        ) -> bool {
            if (found || p_cnid != parent || name != want ||
                drec_type != kDrecTypeDir) {
                return true; // keep scanning
            }
            found = true;
            next = c_cnid;
            return true;
        };

        if (!fstree_visit_dir_records(
                ctx,
                root_oid,
                root_level,
                true,
                matcher,
                error
            )) {
            return false;
        }

        if (!found) {
            error = "path component not found: " + want;
            return false;
        }
        parent = next;
    }

    out_cnid = parent;
    return true;
}
} // namespace

bool apfs_read_container(
    const std::string& path,
    ApfsReaderReport& report,
    std::string& error
) {
    report = {};
    error.clear();

    HANDLE file = CreateFileA(
        path.c_str(),
        GENERIC_READ,
        FILE_SHARE_READ,
        nullptr,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        nullptr
    );

    if (file == INVALID_HANDLE_VALUE) {
        error = win_error("CreateFileA");
        return false;
    }

    std::vector<std::uint8_t> block;

    do {
        LARGE_INTEGER file_size{};
        if (!GetFileSizeEx(file, &file_size)) {
            error = win_error("GetFileSizeEx");
            break;
        }

        if (file_size.QuadPart < 4096) {
            error = "file is smaller than one APFS block";
            break;
        }

        block.assign(4096, 0);
        if (!read_block(file, 0, 4096, block, error)) {
            break;
        }

        // Object header: cksum(8) oid(8) xid(8) type(4) subtype(4)
        // NXSB: magic(4) blocksize(4) blockcount(8) at offsets 32/36/40.
        if (read_le32(block.data() + 32) != kNxsbMagic) {
            error = "container superblock magic is not NXSB";
            break;
        }

        report.container.block_size = read_le32(block.data() + 36);
        report.container.block_count = read_le64(block.data() + 40);

        // nx_omap_oid follows the uuid + next-oid/xid + checkpoint area.
        // Observed layout for the known-good fixture: the omap pointer
        // table starts after the checkpoint descriptor/data arrays.
        // Decode from the field observed at offset 136 in this image
        // family; validated below by finding an OMAP object there.
        const std::uint64_t file_size_u =
            static_cast<std::uint64_t>(file_size.QuadPart);
        if (!valid_block_geometry(
                report.container.block_size,
                report.container.block_count,
                file_size_u,
                error
            )) {
            break;
        }

        block.assign(report.container.block_size, 0);

        // Scan for volume superblocks (APSB). The checkpoint area holds
        // multiple NXSB eras; the newest era's APSB is the active volume.
        // We scan every block once and keep all APSB objects found.
        for (std::uint64_t b = 0; b < report.container.block_count; ++b) {
            if (!read_block(
                    file,
                    b,
                    report.container.block_size,
                    block,
                    error
                )) {
                break;
            }

            if (read_le32(block.data() + 32) != kApsbMagic) {
                continue;
            }

            // Trust chain: verify the APSB checksum before reading any
            // field that drives volume resolution.
            if (!apfs_block_checksum_ok(block)) {
                continue;
            }

            ApfsVolumeInfo volume;
            volume.apsb_block = b;
            volume.apsb_oid = read_le64(block.data() + 8);
            volume.xid = read_le64(block.data() + 16);

            // Authoritative APSB offsets (apfs-fuse, linux-apfs-rw,
            // Sleuth Kit): omap @0x80, root_tree @0x88, extentref @0x90,
            // snap_meta_tree @0x98. The previous revision read the
            // extentref tree oid at +0x90 and mislabeled it the catalog
            // root; +0x88 is the real apfs_root_tree_oid.
            const std::uint64_t omap_block = read_le64(block.data() + 0x80);
            volume.root_tree_oid = read_le64(block.data() + 0x88);
            volume.extentref_tree_oid = read_le64(block.data() + 0x90);

            if (omap_block >= report.container.block_count) {
                continue;
            }

            std::vector<std::uint8_t> omap_block_buf(
                report.container.block_size,
                0
            );
            if (!read_block(
                    file,
                    omap_block,
                    report.container.block_size,
                    omap_block_buf,
                    error
                )) {
                break;
            }

            if ((read_le32(omap_block_buf.data() + 24) & kObjectTypeMask)
                    != kOmapType) {
                continue;
            }

            // Trust chain: verify omap_phys_t checksum before reading
            // om_tree_oid.
            if (!apfs_block_checksum_ok(omap_block_buf)) {
                continue;
            }

            // omap_phys_t: om_tree_oid at +0x30 (after obj header +
            // flags/snap_count/tree_type/snapshot_tree_type).
            const std::uint64_t om_tree_oid =
                read_le64(omap_block_buf.data() + 0x30);

            std::vector<std::uint8_t> root_block_buf(
                report.container.block_size,
                0
            );

            // Resolve the virtual root_tree_oid through the OMAP.
            // If the OMAP walk yields the oid, use its paddr as the
            // physical FSTREE root; otherwise fall back to treating the
            // value as a physical block only when storage type is
            // provably physical.
            std::vector<ApfsOmapEntry> omap_entries;
            std::set<std::uint64_t> visited;
            std::uint64_t resolved_root_block = 0;
            bool root_resolved = false;
            ApfsBtreeNodeInfo fstree_info;

            if (om_tree_oid > 0 && om_tree_oid < report.container.block_count) {
                std::string omap_error;
                if (omap_collect_entries(
                        file,
                        report.container.block_size,
                        om_tree_oid,
                        report.container.block_count,
                        true,
                        omap_entries,
                        visited,
                        omap_error
                    )) {
                    // OMAP lookup semantics (apfs-fuse ApfsNodeMapperBTree::
                    // Lookup): entries are ordered by (oid, xid); resolve
                    // the target oid at the newest xid <= the volume xid.
                    const ApfsOmapEntry* best = nullptr;
                    for (const auto& e : omap_entries) {
                        if (e.oid == volume.root_tree_oid &&
                            e.xid <= volume.xid &&
                            e.paddr < report.container.block_count) {
                            if (!best || e.xid > best->xid) {
                                best = &e;
                            }
                        }
                    }
                    if (best) {
                        resolved_root_block = best->paddr;
                        root_resolved = true;
                    }
                }
            }

            if (root_resolved) {
                if (!read_block(
                        file,
                        resolved_root_block,
                        report.container.block_size,
                        root_block_buf,
                        error
                    )) {
                    break;
                }

                if (!apfs_block_checksum_ok(root_block_buf)) {
                    continue;
                }

                // Verify the resolved block is the volume catalog root:
                // B-tree object kind, FSTREE subtype, root flag set,
                // footer present with node_size matching block size.
                const std::uint32_t root_type =
                    read_le32(root_block_buf.data() + 24);
                const std::uint32_t root_type_kind =
                    root_type & kObjectTypeMask;
                const std::uint32_t root_subtype =
                    read_le32(root_block_buf.data() + 28);

                if (root_type_kind != kBtreeType &&
                        root_type_kind != kBtreeTypeNode) {
                    continue;
                }
                if (root_subtype != kFstreeSubtype) {
                    continue;
                }

                std::string fstree_error;
                if (!decode_btree_node(
                        root_block_buf,
                        report.container.block_size,
                        fstree_info,
                        fstree_error
                    )) {
                    continue;
                }
                if (!(fstree_info.flags & kBtreeRoot) ||
                    !fstree_info.has_footer ||
                    fstree_info.node_size !=
                        report.container.block_size) {
                    continue;
                }
            } else {
                // OMAP did not resolve the oid; keep the raw oid in the
                // report and skip B-tree validation rather than guessing.
                volume.omap_block = omap_block;
                volume.root_tree_block = 0;

                if (0x2C0 + 256 <= block.size()) {
                    const char* name =
                        reinterpret_cast<const char*>(block.data() + 0x2C0);
                    const std::size_t max_len = strnlen(name, 256);
                    bool printable = max_len > 0;
                    for (std::size_t i = 0; i < max_len; ++i) {
                        const std::uint8_t ch =
                            static_cast<std::uint8_t>(name[i]);
                        if (ch < 0x20 || ch > 0x7e) {
                            printable = false;
                            break;
                        }
                    }
                    if (printable) {
                        volume.volume_name.assign(name, max_len);
                    }
                }

                report.volumes.push_back(volume);
                continue;
            }

            volume.omap_block = omap_block;
            volume.root_tree_block = resolved_root_block;
            volume.root_tree_info = fstree_info;

            // Structural /System/Library/LaunchDaemons resolution via
            // DIR_REC parent/child CNIDs (first successful volume wins).
            if (report.launchdaemons_cnid == 0) {
                FstreeWalkCtx walk_ctx;
                walk_ctx.file = file;
                walk_ctx.block_size = report.container.block_size;
                walk_ctx.block_count = report.container.block_count;
                walk_ctx.omap = &omap_entries;
                walk_ctx.volume_xid = volume.xid;

                const std::uint64_t incompat =
                    read_le64(block.data() + kApsbIncompatOffset);
                walk_ctx.hashed_names =
                    (incompat & kIncompatCaseInsensitive) != 0 ||
                    (incompat & kIncompatNormalizationInsensitive) != 0;

                std::uint64_t ld_cnid = 0;
                std::string walk_error;
                if (fstree_resolve_launchdaemons(
                        walk_ctx,
                        volume.root_tree_oid,
                        fstree_info.level,
                        ld_cnid,
                        walk_error
                    )) {
                    report.launchdaemons_cnid = ld_cnid;
                    report.launchdaemons_status = "RESOLVED";
                } else {
                    report.launchdaemons_status =
                        "NOT_RESOLVED: " + walk_error;
                }
            }

            // apfs_volname is a fixed 256-byte null-padded array in the
            // APSB; observed at offset 0x2C0 in this image family.
            if (0x2C0 + 256 <= block.size()) {
                const char* name =
                    reinterpret_cast<const char*>(block.data() + 0x2C0);
                const std::size_t max_len =
                    strnlen(name, 256);
                bool printable = max_len > 0;
                for (std::size_t i = 0; i < max_len; ++i) {
                    const std::uint8_t ch =
                        static_cast<std::uint8_t>(name[i]);
                    if (ch < 0x20 || ch > 0x7e) {
                        printable = false;
                        break;
                    }
                }
                if (printable) {
                    volume.volume_name.assign(name, max_len);
                }
            }

            report.volumes.push_back(volume);
        }

        error.clear();
        CloseHandle(file);
        return true;
    } while (false);

    CloseHandle(file);
    return false;
}

} // namespace vphone
