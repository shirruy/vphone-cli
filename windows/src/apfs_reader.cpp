#define NOMINMAX
#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include "vphone/apfs_reader.hpp"

#include <cstring>
#include <wincrypt.h>
#include <set>
#include <algorithm>
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

// Read an arbitrary byte range from the image file.
bool read_exact_range(
    HANDLE file,
    std::uint64_t offset,
    std::uint8_t* buffer,
    std::uint64_t size,
    std::string& error
) {
    LARGE_INTEGER distance{};
    distance.QuadPart =
        static_cast<LONGLONG>(offset);
    if (!SetFilePointerEx(file, distance, nullptr, FILE_BEGIN)) {
        error = win_error("SetFilePointerEx");
        return false;
    }

    std::uint64_t remaining = size;
    while (remaining > 0) {
        const DWORD chunk = static_cast<DWORD>(
            std::min<std::uint64_t>(remaining, 0x40000000ull)
        );
        DWORD read_bytes = 0;
        if (!ReadFile(
                file,
                buffer + (size - remaining),
                chunk,
                &read_bytes,
                nullptr
            ) || read_bytes != chunk) {
            error = "physical read short/failed";
            return false;
        }
        remaining -= chunk;
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
constexpr std::uint64_t kApfsTypeInode = 3;
constexpr std::uint16_t kInodeValBaseSize = 0x5c;
constexpr std::uint64_t kInoBsdCompressed = 0x20;
constexpr std::uint16_t kInoExtTypeDstream = 8;
constexpr std::uint16_t kDstreamSize = 40;
constexpr std::uint64_t kApfsTypeXattr = 4;
// apfs_xf_blob: xf_num_exts u16 + xf_used_data u16 = 4-byte header.
constexpr std::uint16_t kXfBlobHeaderSize = 4;
// apfs_x_field: x_type u8 + x_flags u8 + x_size u16 = 4-byte metadata.
constexpr std::uint16_t kXFieldMetaSize = 4;
// Decmpfs PLAIN_ATTR marker byte (apfs-fuse Decmpfs.cpp assert).
constexpr std::uint8_t kDecmpfsPlainMarker = 0xCC;
// Decmpfs magic signature ("cmpf").
constexpr std::uint32_t kDecmpfsSignature = 0x636D7066u;
// XATTR storage mode flags.
constexpr std::uint16_t kXattrDataStream = 0x0001;
constexpr std::uint16_t kXattrDataEmbedded = 0x0002;
// Decmpfs header: signature u32 + algo u32 + logical_size u64 = 16.
constexpr std::uint16_t kDecmpfsHeaderSize = 16;
// XATTR name "com.apple.decmpfs" = 17 chars + NUL = 18.
constexpr std::uint16_t kDecmpfsNameLen = 18;

constexpr std::uint64_t kExtentLenMask = 0x00FFFFFFFFFFFFFFull;
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

    // Exact level contract: root equals root_level; every child equals
    // parent_level - 1; leaves are level 0. No level skipping.
    const std::uint16_t raw_flags =
        static_cast<std::uint16_t>(buf[0x20]) |
        (static_cast<std::uint16_t>(buf[0x21]) << 8);
    const std::uint16_t raw_level =
        static_cast<std::uint16_t>(buf[0x22]) |
        (static_cast<std::uint16_t>(buf[0x23]) << 8);
    if (raw_level != expected_level) {
        error = "FSTREE node level mismatch (expected exact descent)";
        return false;
    }

    // Topology flag contract: root-ness and leaf-ness must match the
    // numeric level and the walk position. Value-base/footer geometry
    // depends on root-ness; record semantics depend on leaf-ness.
    const bool has_root_flag = (raw_flags & kBtreeRoot) != 0;
    const bool has_leaf_flag = (raw_flags & kBtreeLeaf) != 0;
    if (is_root && !has_root_flag) {
        error = "FSTREE root node missing ROOT flag";
        return false;
    }
    if (!is_root && has_root_flag) {
        error = "FSTREE non-root node carries ROOT flag";
        return false;
    }
    if (raw_level == 0 && !has_leaf_flag) {
        error = "FSTREE level-0 node missing LEAF flag";
        return false;
    }
    if (raw_level > 0 && has_leaf_flag) {
        error = "FSTREE interior node carries LEAF flag";
        return false;
    }

    ApfsBtreeNodeInfo node;
    if (!decode_btree_node(buf, ctx.block_size, node, error)) {
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

// ---------------------------------------------------------------------------
// Generic FSTREE record visitor for INODE / FILE_EXTENT lookups.
// Reuses the same hardened walker (checksums, topology, kvloc, OMAP)
// but exposes raw {record_type, obj_id, key_payload, key_len,
// value_ptr, value_len} to the callback.
// ---------------------------------------------------------------------------

struct FstreeRawRecord {
    std::uint64_t obj_id = 0;
    std::uint64_t record_type = 0;
    const std::uint8_t* key_extra = nullptr; // after the 8-byte header
    std::uint16_t key_extra_len = 0;
    const std::uint8_t* value = nullptr;
    std::uint16_t value_len = 0;
    // Physical provenance for structural mutation.
    std::uint64_t leaf_paddr = 0;
    std::uint16_t key_off_in_leaf = 0;
    std::uint16_t val_off_in_leaf = 0;
};

template <typename RawMatchFn>
bool fstree_visit_raw_records(
    FstreeWalkCtx& ctx,
    std::uint64_t node_oid,
    std::uint16_t expected_level,
    bool is_root,
    RawMatchFn match,
    std::string& error
) {
    if (node_oid == 0) {
        error = "FSTREE node OID is zero";
        return false;
    }

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
    const std::uint32_t subtype = read_le32(buf.data() + 28);
    if (subtype != kFstreeSubtype) {
        error = "FSTREE child node subtype is not FSTREE";
        return false;
    }

    const std::uint16_t raw_flags =
        static_cast<std::uint16_t>(buf[0x20]) |
        (static_cast<std::uint16_t>(buf[0x21]) << 8);
    const std::uint16_t raw_level =
        static_cast<std::uint16_t>(buf[0x22]) |
        (static_cast<std::uint16_t>(buf[0x23]) << 8);
    if (raw_level != expected_level) {
        error = "FSTREE node level mismatch (expected exact descent)";
        return false;
    }
    const bool has_root_flag = (raw_flags & kBtreeRoot) != 0;
    const bool has_leaf_flag = (raw_flags & kBtreeLeaf) != 0;
    if (is_root && !has_root_flag) {
        error = "FSTREE root node missing ROOT flag";
        return false;
    }
    if (!is_root && has_root_flag) {
        error = "FSTREE non-root node carries ROOT flag";
        return false;
    }
    if (raw_level == 0 && !has_leaf_flag) {
        error = "FSTREE level-0 node missing LEAF flag";
        return false;
    }
    if (raw_level > 0 && has_leaf_flag) {
        error = "FSTREE interior node carries LEAF flag";
        return false;
    }

    ApfsBtreeNodeInfo node;
    if (!decode_btree_node(buf, ctx.block_size, node, error)) {
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

        if (k_off > ctx.block_size || k_len > ctx.block_size - k_off) {
            error = "FSTREE key range exceeds block";
            return false;
        }
        const std::uint64_t kp = key_base + k_off;
        if (kp > ctx.block_size || k_len > ctx.block_size - kp) {
            error = "FSTREE key base + range exceeds block";
            return false;
        }
        if (v_off > value_base) {
            error = "FSTREE value offset exceeds value base";
            return false;
        }
        const std::uint64_t vp = value_base - v_off;
        if (vp > ctx.block_size || v_len > ctx.block_size - vp) {
            error = "FSTREE value range exceeds block";
            return false;
        }

        if (node.level > 0) {
            if (v_len != 8 || vp + 8 > ctx.block_size) {
                error = "FSTREE interior value must be an 8-byte child OID";
                return false;
            }
            if (node.level < 1) {
                error = "FSTREE interior recursion underflow";
                return false;
            }
            const std::uint64_t child_oid = read_le64(p + vp);
            if (!fstree_visit_raw_records(
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

        if (k_len < 8) {
            continue;
        }

        FstreeRawRecord rec;
        const std::uint64_t hdr = read_le64(p + kp);
        rec.obj_id = hdr & kObjIdMask;
        rec.record_type = hdr >> kRecordTypeShift;
        rec.key_extra = p + kp + 8;
        rec.key_extra_len = k_len - 8;
        rec.value = p + vp;
        rec.value_len = v_len;
        rec.leaf_paddr = paddr;
        rec.key_off_in_leaf = static_cast<std::uint16_t>(kp);
        rec.val_off_in_leaf = static_cast<std::uint16_t>(vp);

        if (!match(rec)) {
            error = "raw record match callback failed";
            return false;
        }
    }

    return true;
}

// Resolve a plist file end-to-end: DIR_REC under a parent CNID, INODE,
// dstream xfield, FILE_EXTENT chain, and byte reconstruction.
bool fstree_read_plist_file(
    FstreeWalkCtx& ctx,
    std::uint64_t root_oid,
    std::uint16_t root_level,
    std::uint64_t parent_cnid,
    ApfsReaderReport::PlistFileResult& result
) {
    // Phase 1: collect ALL plist DIR_REC candidates under the parent.
    struct Candidate {
        std::string name;
        std::uint64_t cnid;
    };
    std::vector<Candidate> candidates;

    ctx.visited.clear();
    auto drec_match = [&](
        std::uint64_t p_cnid,
        const std::string& name,
        std::uint64_t c_cnid,
        std::uint16_t drec_type
    ) -> bool {
        if (p_cnid == parent_cnid && drec_type != 4 &&
            name.size() > 6 &&
            name.compare(name.size() - 6, 6, ".plist") == 0) {
            candidates.push_back({name, c_cnid});
        }
        return true;
    };

    std::string error;
    if (!fstree_visit_dir_records(
            ctx,
            root_oid,
            root_level,
            true,
            drec_match,
            error
        )) {
        result.status = "FAIL";
        result.error = "DIR_REC scan: " + error;
        return false;
    }

    if (candidates.empty()) {
        result.status = "FAIL";
        result.error = "no regular .plist file found under parent CNID";
        return false;
    }

    // Phase 2: try each candidate until we find a non-compressed,
    // regular file with a dstream xfield.
    struct InodeInfo {
        bool found = false;
        std::uint64_t private_id = 0;
        std::uint64_t parent_id = 0;
        std::uint16_t mode = 0;
        bool compressed = false;
        std::uint64_t dstream_size = 0;
        bool has_dstream = false;
        std::string parse_error;
    } ino;

    bool inode_ok = false;
    std::uint64_t selected_cnid = 0;
    std::string selected_name;

    for (const auto& cand : candidates) {
        ino = InodeInfo{};
        ctx.visited.clear();

        auto inode_match = [&](const FstreeRawRecord& rec) -> bool {
            if (ino.found || rec.record_type != kApfsTypeInode ||
                rec.obj_id != cand.cnid) {
            return true;
        }
            if (rec.value_len < kInodeValBaseSize) {
                ino.parse_error =
                    "INODE value shorter than base structure";
                return false;
            }
            ino.found = true;
            ino.parent_id = read_le64(rec.value + 0x00);
            ino.private_id = read_le64(rec.value + 0x08);
            const std::uint32_t bsd_flags =
                read_le32(rec.value + 0x44);
            ino.mode =
                static_cast<std::uint16_t>(rec.value[0x50]) |
                (static_cast<std::uint16_t>(rec.value[0x51]) << 8);
            ino.compressed = (bsd_flags & kInoBsdCompressed) != 0;

            // Authoritative xfield layout (apfs_xf_blob):
            //   u16 xf_num_exts
            //   u16 xf_used_data
            //   apfs_x_field xf_data[]  (4-byte metadata entries)
            //   value data follows after ALL metadata entries
            // Each apfs_x_field: { x_type u8, x_flags u8, x_size u16 }
            // Each value consumes round_up(x_size, 8) bytes.
            const std::uint16_t xfields_off = 0x5c;
            if (rec.value_len == xfields_off) {
                // Base-only inode: valid, no xfields to parse.
            } else if (rec.value_len > xfields_off &&
                       rec.value_len < xfields_off + kXfBlobHeaderSize) {
                // Partial xf_blob header (0x5d..0x5f): malformed.
                ino.parse_error =
                    "xfield partial xf_blob header";
                return false;
            } else if (rec.value_len >=
                       xfields_off + kXfBlobHeaderSize) {
                const std::uint8_t* xf = rec.value + xfields_off;
                const std::uint16_t num_exts =
                    static_cast<std::uint16_t>(xf[0]) |
                    (static_cast<std::uint16_t>(xf[1]) << 8);
                const std::uint16_t used_data =
                    static_cast<std::uint16_t>(xf[2]) |
                    (static_cast<std::uint16_t>(xf[3]) << 8);
                const std::uint64_t meta_end =
                    xfields_off + kXfBlobHeaderSize +
                    static_cast<std::uint64_t>(num_exts) *
                        kXFieldMetaSize;

                // Metadata array must fit within the inode value.
                if (meta_end > rec.value_len) {
                    // Fail closed for the selected target inode.
                    ino.parse_error = "xfield metadata bounds exceeded";
                    return false;
                }

                    // Values start after all metadata entries.
                    std::uint64_t val_off = meta_end;
                    std::uint64_t consumed_padded = 0;

                    for (std::uint16_t xi = 0; xi < num_exts; ++xi) {
                        const std::uint8_t* meta =
                            xf + kXfBlobHeaderSize +
                            static_cast<std::uint64_t>(xi) *
                                kXFieldMetaSize;
                        const std::uint8_t x_type = meta[0];
                        const std::uint16_t x_size =
                            static_cast<std::uint16_t>(meta[2]) |
                            (static_cast<std::uint16_t>(meta[3]) << 8);

                        // Padded value size must fit remaining record.
                        const std::uint64_t padded =
                            (static_cast<std::uint64_t>(x_size) + 7) &
                            ~static_cast<std::uint64_t>(7);
                        if (val_off + padded > rec.value_len) {
                            ino.parse_error = "xfield value bounds exceeded";
                            return false;
                        }

                        if (x_type == kInoExtTypeDstream &&
                            x_size >= kDstreamSize &&
                            val_off + kDstreamSize <= rec.value_len) {
                            ino.has_dstream = true;
                            ino.dstream_size =
                                read_le64(rec.value + val_off);
                        } else if (x_type == kInoExtTypeDstream &&
                                   x_size < kDstreamSize) {
                            ino.parse_error =
                                "DSTREAM xfield value too short";
                            return false;
                        }

                        val_off += padded;
                        consumed_padded += padded;
                    }

                    // Cross-check: consumed padded values must equal
                    // xf_used_data.
                    if (consumed_padded != used_data) {
                        ino.parse_error =
                            "xfield xf_used_data mismatch: consumed " +
                            std::to_string(consumed_padded) +
                            " expected " + std::to_string(used_data);
                        return false;
                    }

                    // Collection-size contract: metadata area +
                    // consumed padded values must fill the inode
                    // value exactly (no silent trailing bytes).
                    if (meta_end + consumed_padded != rec.value_len) {
                        ino.parse_error =
                            "xfield collection-size mismatch: " +
                            std::to_string(meta_end + consumed_padded) +
                            " != " + std::to_string(rec.value_len);
                        return false;
                    }
            }
            return true;
        };

        const bool inode_walked = fstree_visit_raw_records(
                ctx,
                root_oid,
                root_level,
                true,
                inode_match,
                error
            );

        if (!inode_walked) {
            if (!ino.parse_error.empty()) {
                // Target inode parse failure: fail closed with the
                // exact error, do NOT continue to another candidate.
                result.status = "FAIL";
                result.error = "INODE parse: " + ino.parse_error;
                return false;
            }
            // Walker structural failure: also fail closed.
            result.status = "FAIL";
            result.error = "INODE walk: " + error;
            return false;
        }

        if (!ino.found) {
            continue;
        }

        if (ino.parent_id != parent_cnid) {            continue;
        }
        if ((ino.mode & 0xF000) != 0x8000) {            continue;
        }
        if (ino.compressed) {
            // Resolve com.apple.decmpfs XATTR for this candidate,
            // persist identity, extract PLAIN_ATTR bytes.
            struct DecmpfsInfo {
                bool found = false;
                std::uint16_t xattr_flags = 0;
                std::uint32_t signature = 0;
                std::uint32_t algo = 0;
                std::uint64_t logical_size = 0;
                std::vector<std::uint8_t> xdata;
                bool traversal_ok = false;
                std::string parse_error;
            } dcs;
            
            ctx.visited.clear();
            auto xattr_match = [&](
                const FstreeRawRecord& rec
            ) -> bool {
                if (dcs.found || rec.record_type != kApfsTypeXattr ||
                    rec.obj_id != cand.cnid) {
                    return true;
                }
                // Exact XATTR key validation: name_len >= 1,
                // key_extra_len == 2 + name_len, final name byte NUL.
                if (rec.key_extra_len < 3) {
                    return true;
                }
                const std::uint16_t name_len =
                    static_cast<std::uint16_t>(
                        rec.key_extra[0]) |
                    (static_cast<std::uint16_t>(
                         rec.key_extra[1]) << 8);
                if (name_len != kDecmpfsNameLen ||
                    rec.key_extra_len != 2 + kDecmpfsNameLen) {
                    return true;
                }
                // Final name byte must be NUL (name_len includes it).
                if (rec.key_extra[2 + kDecmpfsNameLen - 1] != 0) {
                    return true;
                }
                // Logical name = name_len - 1 = 17 chars.
                if (std::memcmp(
                        rec.key_extra + 2,
                        "com.apple.decmpfs",
                        kDecmpfsNameLen - 1) != 0) {
                    return true;
                }

                // Full XATTR value validation before accepting.
                // apfs_xattr_val: flags u16 + xdata_len u16 + xdata[].
                if (rec.value_len < 4) {
                    return true;
                }
                dcs.xattr_flags =
                    static_cast<std::uint16_t>(rec.value[0]) |
                    (static_cast<std::uint16_t>(rec.value[1]) << 8);
                const std::uint16_t xdata_len =
                    static_cast<std::uint16_t>(rec.value[2]) |
                    (static_cast<std::uint16_t>(rec.value[3]) << 8);

                // xdata_len must exactly fill the remaining value.
                if (xdata_len != rec.value_len - 4) {
                    dcs.parse_error = "XATTR xdata_len mismatch";
                    return false;
                }
                // Algo 9 proof requires header + marker + >=1 byte.
                if (xdata_len < kDecmpfsHeaderSize + 1 + 1) {
                    dcs.parse_error = "XATTR xdata too short for decmpfs";
                    return false;
                }

                const std::uint8_t* xd = rec.value + 4;
                dcs.signature = read_le32(xd);
                dcs.algo = read_le32(xd + 4);
                dcs.logical_size = read_le64(xd + 8);

                // Enforce XATTR storage mode: only DATA_EMBEDDED for
                // the algo-9 inline proof. Reject DATA_STREAM and
                // ambiguous modes before interpreting inline xdata.
                if (dcs.xattr_flags & kXattrDataStream) {
                    dcs.parse_error = "XATTR DATA_STREAM not supported";
                    return false;
                }
                if (!(dcs.xattr_flags & kXattrDataEmbedded)) {
                    dcs.parse_error = "XATTR missing DATA_EMBEDDED";
                    return false;
                }

                // Enforce decmpfs magic signature.
                if (dcs.signature != kDecmpfsSignature) {
                    dcs.parse_error = "XATTR bad cmpf signature";
                    return false;
                }

                // Only algo 9 (PLAIN_ATTR) is proven for this gate.
                if (dcs.algo == 9) {
                    // Verify marker byte at xdata[16].
                    if (xd[kDecmpfsHeaderSize] != kDecmpfsPlainMarker) {
                        dcs.parse_error = "XATTR bad 0xCC marker";
                        return false;
                    }
                    // logical_size == xdata_len - 17 (header + marker).
                    if (dcs.logical_size !=
                        xdata_len - kDecmpfsHeaderSize - 1) {
                        dcs.parse_error = "XATTR logical-size mismatch";
                        return false;
                    }
                    dcs.xdata.assign(
                        xd + kDecmpfsHeaderSize + 1,
                        xd + kDecmpfsHeaderSize + 1 + dcs.logical_size
                    );
                }
                dcs.found = true;
                // Record physical provenance for mutation.
                result.xattr_leaf_paddr = rec.leaf_paddr;
                result.xattr_key_off = rec.key_off_in_leaf;
                result.xattr_val_off = rec.val_off_in_leaf;
                // Plist data starts at value + 4 (flags+len) +
                // 16 (decmpfs header) + 1 (marker) = value + 21.
                result.xattr_data_start_off =
                    rec.val_off_in_leaf + 4 +
                    kDecmpfsHeaderSize + 1;
                return true;
            };

            std::string xa_error;
            dcs.traversal_ok = fstree_visit_raw_records(
                ctx,
                root_oid,
                root_level,
                true,
                xattr_match,
                xa_error
            );

            if (!dcs.traversal_ok && !dcs.parse_error.empty()) {
                result.status = "FAIL";
                result.error = "XATTR parse: " + dcs.parse_error;
                return false;
            }
            if (!dcs.traversal_ok) {
                result.status = "FAIL";
                result.error = "XATTR walk: " + xa_error;
                return false;
            }

            if (dcs.traversal_ok && dcs.found && !dcs.xdata.empty()) {
                // Persist the deterministic candidate identity.
                result.name = cand.name;
                result.drec_cnid = cand.cnid;
                result.inode_cnid = cand.cnid;
                result.private_id = ino.private_id;
                result.file_size = dcs.logical_size;
                result.decmpfs_found = true;
                result.xattr_flags = dcs.xattr_flags;
                result.decmpfs_signature = dcs.signature;
                result.decmpfs_algo = dcs.algo;
                result.decmpfs_logical_size = dcs.logical_size;
                result.xattr_embedded =
                    (dcs.xattr_flags & 0x2) != 0;
                result.needs_resource_fork =
                    (dcs.algo % 2) == 0;
                // PLAIN_ATTR: xdata bytes ARE the file content.
                result.bytes = std::move(dcs.xdata);

                // Format detection on extracted bytes.
                if (result.bytes.size() >= 8 &&
                    std::memcmp(
                        result.bytes.data(), "bplist00", 8) == 0) {
                    result.format = "binary-plist";
                } else if (result.bytes.size() >= 5 &&
                           std::memcmp(
                               result.bytes.data(), "<?xml", 5) == 0) {
                    result.format = "xml-plist";
                } else {
                    result.format = "unknown";
                }
                result.status = "READ_OK";
                return true;
            }
            continue; // skip compressed for byte-read gate
        }
        if (!ino.has_dstream) {            continue;
        }

        // Found a valid non-compressed regular file with dstream.
        inode_ok = true;
        selected_cnid = cand.cnid;
        selected_name = cand.name;
        break;
    }

    if (!inode_ok) {
        result.status = "FAIL";
        result.error =
            "no readable plist candidate: " +
            std::to_string(candidates.size()) +
            " evaluated, none produced a supported " +
            "uncompressed dstream-backed or decmpfs-PLAIN file";
        return false;
    }

    result.name = selected_name;
    result.drec_cnid = selected_cnid;
    result.inode_cnid = selected_cnid;
    result.private_id = ino.private_id;

    // Authoritative file size: dstream.size when present.
    const std::uint64_t file_size = ino.dstream_size;
    result.file_size = file_size;

    // Phase 3: collect FILE_EXTENT records for private_id.
    struct Extent {
        std::uint64_t logical = 0;
        std::uint64_t length = 0;
        std::uint64_t phys = 0;
    };
    std::vector<Extent> extents;
    std::string extent_parse_error;

    ctx.visited.clear();
    auto extent_match = [&](const FstreeRawRecord& rec) -> bool {
        if (rec.record_type != kApfsTypeFileExtent ||
            rec.obj_id != ino.private_id) {
            return true;
        }
        if (rec.key_extra_len != 8 || rec.value_len != 24) {
            extent_parse_error =
                "FILE_EXTENT malformed size: key=" +
                std::to_string(rec.key_extra_len) +
                " value=" + std::to_string(rec.value_len);
            return false;
        }
        Extent e;
        e.logical = read_le64(rec.key_extra);
        const std::uint64_t len_flags = read_le64(rec.value);
        e.length = len_flags & kExtentLenMask;
        e.phys = read_le64(rec.value + 8);
        extents.push_back(e);
        return true;
    };

    if (!fstree_visit_raw_records(
            ctx,
            root_oid,
            root_level,
            true,
            extent_match,
            error
        )) {
        if (!extent_parse_error.empty()) {
            result.status = "FAIL";
            result.error = "FILE_EXTENT parse: " + extent_parse_error;
            return false;
        }
        result.status = "FAIL";
        result.error = "FILE_EXTENT scan: " + error;
        return false;
    }

    if (extents.empty()) {
        result.status = "FAIL";
        result.error = "no FILE_EXTENT records found";
        return false;
    }

    // Sort by logical address.
    std::sort(
        extents.begin(),
        extents.end(),
        [](const Extent& a, const Extent& b) {
            return a.logical < b.logical;
        }
    );

    // Validate: no zero-length, no overlap, phys in range.
    for (std::size_t i = 0; i < extents.size(); ++i) {
        const auto& e = extents[i];
        if (e.length == 0) {
            result.status = "FAIL";
            result.error = "zero-length extent";
            return false;
        }
        // Overflow-safe ceiling division for block count.
        const std::uint64_t blocks_needed =
            e.length / ctx.block_size +
            ((e.length % ctx.block_size) != 0 ? 1 : 0);
        if (e.phys != 0 &&
            (e.phys >= ctx.block_count ||
             blocks_needed > ctx.block_count - e.phys)) {
            result.status = "FAIL";
            result.error = "extent physical range exceeds container";
            return false;
        }
        if (i > 0) {
            const auto& prev = extents[i - 1];
            // Overflow-safe logical end check.
            if (prev.length >
                    std::numeric_limits<std::uint64_t>::max() -
                    prev.logical ||
                e.logical < prev.logical + prev.length) {
                result.status = "FAIL";
                result.error = "overlapping extents";
                return false;
            }

        }
    }

    result.extent_count = extents.size();

    // Reconstruct bytes up to file_size using a coverage cursor.
    // Every byte range [0, file_size) must be explicitly covered by an
    // extent (phys==0 holes leave zeros but still advance the cursor).
    result.bytes.assign(file_size, 0);
    std::uint64_t expected = 0;
    for (const auto& e : extents) {
        if (e.logical >= file_size) {
            break; // beyond authoritative size
        }
        if (e.logical > expected) {
            result.status = "FAIL";
            result.error = "extent coverage gap at logical offset " +
                std::to_string(expected) + " (next extent at " +
                std::to_string(e.logical) + ")";
            return false;
        }
        if (e.logical < expected) {
            // Overlap already rejected above; defensive.
            result.status = "FAIL";
            result.error = "extent underlap detected";
            return false;
        }
        const std::uint64_t chunk =
            std::min(e.length, file_size - e.logical);
        if (e.phys == 0) {
            // Hole: leave zeros, advance cursor.
            expected = e.logical + chunk;
            continue;
        }

        const std::uint64_t phys_offset = e.phys * ctx.block_size;
        std::uint64_t remaining = chunk;
        std::uint64_t src = phys_offset;
        std::uint64_t dst = e.logical;

        while (remaining > 0 && dst < file_size) {
            const std::uint64_t bytes_this =
                std::min<std::uint64_t>(
                    remaining,
                    ctx.block_size - (src % ctx.block_size)
                );
            if (!read_exact_range(
                    ctx.file,
                    src,
                    result.bytes.data() + dst,
                    bytes_this,
                    result.error
                )) {
                result.status = "FAIL";
                result.error = "physical read failed";
                return false;
            }
            src += bytes_this;
            dst += bytes_this;
            remaining -= bytes_this;
        }
        expected = e.logical + chunk;
    }

    if (expected < file_size) {
        result.status = "FAIL";
        result.error =
            "extent coverage incomplete: " +
            std::to_string(expected) + "/" +
            std::to_string(file_size);
        return false;
    }

    // Format detection: binary plist (bplist00) or XML plist.
    if (file_size >= 8 &&
        std::memcmp(result.bytes.data(), "bplist00", 8) == 0) {
        result.format = "binary-plist";
    } else if (file_size >= 5 &&
               std::memcmp(result.bytes.data(), "<?xml", 5) == 0) {
        result.format = "xml-plist";
    } else {
        result.format = "unknown";
    }

    result.status = "READ_OK";
    return true;
}

// Rooted checkpoint-authoritative APSB resolution.
//
// The ONLY legal authority chain is:
//   active NXSB (block 0, checksum-verified)
//   -> nx_omap_oid (offset 0xA0 = 160, per linux-apfs-rw apfs_raw.h
//      struct apfs_nx_superblock: nx_spaceman_oid@0x98,
//      nx_omap_oid@0xA0, nx_reaper_oid@0xA8)
//   -> omap_phys block (checksum/type/xid verified)
//   -> om_tree_oid (offset 0x30)
//   -> OMAP B-tree traversal rooted at that exact tree
//   -> {volume oid, greatest xid <= nxsb_xid} -> APSB paddr
//
// There is NO global OMAP-leaf scan and NO APSB-scan fallback. A
// rogue OMAP leaf that the rooted tree does not reference has zero
// influence, no matter how valid its checksum is.
struct CheckpointOmapResolution {
    bool found = false;
    std::uint64_t checkpoint_map_block = 0;
    std::uint64_t omap_phys_block = 0;
    std::uint64_t omap_tree_root_block = 0;
    std::uint64_t entry_xid = 0;
    std::uint64_t apsb_paddr = 0;
};

bool resolve_checkpoint_apsb_paddr(
    HANDLE file,
    std::uint32_t block_size,
    std::uint64_t block_count,
    const std::vector<std::uint8_t>& nxsb_block,
    std::uint64_t target_oid,
    CheckpointOmapResolution& out,
    std::string& error
) {
    out = CheckpointOmapResolution{};
    error.clear();

    const std::uint64_t nxsb_xid =
        read_le64(nxsb_block.data() + 16);
    const std::uint64_t nx_omap_oid =
        read_le64(nxsb_block.data() + 160);
    const std::uint64_t xp_desc_base =
        read_le64(nxsb_block.data() + 112);

    if (nx_omap_oid == 0) {
        error = "NXSB has no container omap oid";
        return false;
    }
    if (xp_desc_base == 0 ||
        xp_desc_base >= block_count) {
        error = "NXSB checkpoint descriptor base invalid";
        return false;
    }

    // Descriptor bounds come from the NXSB checkpoint geometry
    // (xp_desc_blocks at offset 104), not a hardcoded constant.
    // Find the active checkpoint map: checksum-valid, type
    // checkpoint-map, xid exactly matching the active NXSB era.
    std::vector<std::uint8_t> cp(block_size, 0);
    bool map_found = false;
    std::uint64_t map_block = 0;
    const std::uint32_t xp_desc_blocks =
        read_le32(nxsb_block.data() + 104);
    if (xp_desc_blocks == 0 ||
        xp_desc_blocks > block_count ||
        xp_desc_base > block_count - xp_desc_blocks) {
        error = "NXSB checkpoint descriptor geometry invalid";
        return false;
    }
    for (std::uint64_t b = xp_desc_base;
         b < xp_desc_base + xp_desc_blocks;
         ++b) {
        if (!read_block(
                file, b, block_size, cp, error)) {
            error =
                "checkpoint descriptor read failed: " + error;
            return false;
        }
        if (!apfs_block_checksum_ok(cp)) {
            continue;
        }
        const std::uint32_t type =
            read_le32(cp.data() + 24);
        if ((type & kObjectTypeMask) != 0x0000000Cu) {
            continue;
        }
        if (read_le64(cp.data() + 16) != nxsb_xid) {
            continue;
        }
        map_block = b;
        map_found = true;
        break;
    }
    if (!map_found) {
        error =
            "no checkpoint map matches the active NXSB era";
        return false;
    }
    const std::uint32_t cp_count =
        read_le32(cp.data() + 0x24);
    if (cp_count == 0 ||
        cp_count > (block_size - 0x40) / 40) {
        error = "checkpoint map entry count invalid";
        return false;
    }
    out.checkpoint_map_block = map_block;

    // Resolve the container omap_phys object from nx_omap_oid
    // (offset 0xA0, per linux-apfs-rw apfs_raw.h). The field uses
    // APFS object addressing: a plain in-geometry value is a
    // direct physical block reference (real fixture: 1462); a
    // value with storage-class/virtual bits set is a virtual oid
    // that must be resolved through the active checkpoint map.
    // Out-of-geometry or unresolvable values FAIL CLOSED. No
    // container-wide omap scan exists in either path.
    std::uint64_t omap_phys_block = 0;
    if (nx_omap_oid < block_count) {
        // Plain physical reference. Fully validated as an OMAP
        // object below; a wrong pointer fails closed.
        omap_phys_block = nx_omap_oid;
    } else {
        // Virtual/ephemeral oid: resolve through the checkpoint
        // map entries. No match fails closed.
        for (std::uint32_t e = 0; e < cp_count; ++e) {
            const std::uint64_t off =
                0x40 + static_cast<std::uint64_t>(e) * 40;
            const std::uint64_t oid_v =
                read_le64(cp.data() + off);
            const std::uint64_t paddr =
                read_le64(cp.data() + off + 8);
            const std::uint32_t flags =
                static_cast<std::uint32_t>(
                    read_le64(cp.data() + off + 16));
            const std::uint32_t size =
                static_cast<std::uint32_t>(
                    read_le64(cp.data() + off + 24));
            if (oid_v != nx_omap_oid) {
                continue;
            }
            if (paddr == 0 ||
                paddr >= block_count ||
                size != block_size) {
                error =
                    "checkpoint map OMAP entry geometry invalid";
                return false;
            }
            if ((flags & 0x80000000u) != 0) {
                error =
                    "checkpoint map OMAP entry uses unsupported "
                    "storage class";
                return false;
            }
            omap_phys_block = paddr;
            break;
        }
        if (omap_phys_block == 0) {
            error =
                "nx_omap_oid is virtual and the checkpoint map "
                "has no matching entry";
            return false;
        }
    }
    out.omap_phys_block = omap_phys_block;

    // Verify the omap_phys object.
    std::vector<std::uint8_t> om(block_size, 0);
    if (!read_block(
            file, omap_phys_block, block_size, om, error)) {
        error = "container omap object read failed: " + error;
        return false;
    }
    if (!apfs_block_checksum_ok(om)) {
        error =
            "container omap object failed Fletcher-64 checksum";
        return false;
    }
    if ((read_le32(om.data() + 24) & kObjectTypeMask) !=
        kOmapType) {
        error =
            "container omap object type is not OMAP";
        return false;
    }
    const std::uint64_t om_xid =
        read_le64(om.data() + 16);
    if (om_xid > nxsb_xid) {
        error =
            "container omap object xid exceeds NXSB era";
        return false;
    }

    // om_tree_oid: treat in-geometry values as physical tree
    // blocks (small images); out-of-geometry virtual references
    // fail closed.
    const std::uint64_t om_tree_oid =
        read_le64(om.data() + 0x30);
    if (om_tree_oid == 0 ||
        om_tree_oid >= block_count) {
        error =
            "container omap tree oid is not a supported "
            "physical block";
        return false;
    }
    out.omap_tree_root_block = om_tree_oid;

    // Traverse ONLY this rooted OMAP B-tree.
    std::vector<ApfsOmapEntry> entries;
    std::set<std::uint64_t> visited;
    if (!omap_collect_entries(
            file,
            block_size,
            om_tree_oid,
            block_count,
            true,
            entries,
            visited,
            error
        )) {
        error = "rooted container OMAP walk failed: " + error;
        return false;
    }

    const ApfsOmapEntry* best = nullptr;
    for (const auto& e : entries) {
        if (e.oid == target_oid &&
            e.xid <= nxsb_xid &&
            e.paddr < block_count) {
            if (!best || e.xid > best->xid) {
                best = &e;
            }
        }
    }
    if (!best) {
        error =
            "rooted container OMAP has no in-era mapping for "
            "the requested volume oid";
        return false;
    }
    out.found = true;
    out.entry_xid = best->xid;
    out.apsb_paddr = best->paddr;
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

        // Trust chain: verify the NXSB checksum before reading any
        // field that drives active-era selection. A corrupted NXSB
        // must fail closed rather than supply a stale/forged xid.
        if (!apfs_block_checksum_ok(block)) {
            error = "container superblock failed Fletcher-64 checksum";
            break;
        }

        report.container.block_size = read_le32(block.data() + 36);
        report.container.block_count = read_le64(block.data() + 40);

        // Container omap authority uses nx_omap_oid at offset 0xA0
        // (160) per the documented apfs_nx_superblock layout; see
        // resolve_checkpoint_apsb_paddr for the full chain.
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

        // The NXSB object xid is the active container checkpoint era
        // bound. Capture it before the block buffer is reused.
        std::vector<std::uint8_t> nxsb_block = block;
        const std::uint64_t nxsb_xid = read_le64(block.data() + 16);
        report.container.nxsb_xid = nxsb_xid;

        block.assign(report.container.block_size, 0);

        // Scan for volume superblocks (APSB). The checkpoint area holds
        // multiple NXSB eras; keep every valid APSB, then select the
        // newest era per apsb_oid that does not exceed the active
        // NXSB checkpoint xid.
        std::vector<ApfsVolumeInfo> scanned_volumes;
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
                // OMAP did not resolve the oid; keep the raw oid in
                // the candidate. Active-era filtering happens later.
                volume.omap_block = omap_block;
                volume.root_tree_block = 0;
                scanned_volumes.push_back(volume);
                continue;
            }

            volume.omap_block = omap_block;
            volume.root_tree_block = resolved_root_block;
            volume.root_tree_info = fstree_info;

            scanned_volumes.push_back(volume);
        }

        // Active-era selection: per apsb_oid, only the greatest xid
        // <= nxsb_xid is active. Stale APSBs with the same oid remain
        // intentionally excluded from the report and cannot win the
        // LaunchDaemons/plist race by appearing earlier on disk.
        std::set<std::uint64_t> seen_oids;
        std::vector<ApfsVolumeInfo> active_era_volumes;
        for (const auto& candidate : scanned_volumes) {
            if (candidate.xid > nxsb_xid) {
                continue;
            }
            bool newer_exists = false;
            for (const auto& other : scanned_volumes) {
                if (other.apsb_oid == candidate.apsb_oid &&
                    other.xid > candidate.xid &&
                    other.xid <= nxsb_xid) {
                    newer_exists = true;
                    break;
                }
            }
            if (!newer_exists) {
                active_era_volumes.push_back(candidate);
            }
        }
        // Stable disk order for deterministic reporting.
        std::sort(
            active_era_volumes.begin(),
            active_era_volumes.end(),
            [](const ApfsVolumeInfo& a,
               const ApfsVolumeInfo& b) {
                return a.apsb_block < b.apsb_block;
            }
        );
        report.volumes = std::move(active_era_volumes);

        // Rooted checkpoint-authoritative selection. The container
        // OMAP chain (NXSB -> checkpoint map -> omap_phys -> rooted
        // OMAP B-tree) is the ONLY authority. There is no APSB-scan
        // fallback: if the rooted chain cannot resolve a volume, the
        // reader fails closed.
        {
            std::vector<ApfsVolumeInfo> authoritative;
            std::set<std::uint64_t> resolved_oids;
            for (const auto& volume : report.volumes) {
                if (!resolved_oids.insert(volume.apsb_oid)
                         .second) {
                    continue; // already resolved once via OMAP
                }
                CheckpointOmapResolution resolution;
                std::string resolve_error;
                if (!resolve_checkpoint_apsb_paddr(
                        file,
                        report.container.block_size,
                        report.container.block_count,
                        nxsb_block, // verified NXSB copy
                        volume.apsb_oid,
                        resolution,
                        resolve_error
                    )) {
                    error =
                        "checkpoint-authoritative resolution "
                        "failed: " +
                        resolve_error;
                    break;
                }
                if (resolution.apsb_paddr != volume.apsb_block) {
                    continue; // OMAP points at another APSB copy
                }
                if (report.container.checkpoint_map_block == 0) {
                    report.container.checkpoint_map_block =
                        resolution.checkpoint_map_block;
                    report.container
                        .container_omap_phys_block =
                        resolution.omap_phys_block;
                    report.container
                        .container_omap_tree_root_block =
                        resolution.omap_tree_root_block;
                }
                authoritative.push_back(volume);
            }
            if (!error.empty()) {
                break;
            }
            report.volumes = std::move(authoritative);
        }

        // Pass B: structural resolution on ACTIVE volumes only.
        // LaunchDaemons traversal and plist reconstruction can no
        // longer observe a stale candidate: the candidate set is
        // final before any FSTREE walk runs.
        for (std::size_t vi = 0; vi < report.volumes.size();
             ++vi) {
            const ApfsVolumeInfo& volume = report.volumes[vi];
            // apfs_volname is a fixed 256-byte null-padded array in
            // the APSB; observed at offset 0x2C0 in this image family.
            std::vector<std::uint8_t> apsb_buf(
                report.container.block_size, 0);
            if (!read_block(
                    file,
                    volume.apsb_block,
                    report.container.block_size,
                    apsb_buf,
                    error
                )) {
                break;
            }
            {
                const char* name =
                    reinterpret_cast<const char*>(
                        apsb_buf.data() + 0x2C0);
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
                    report.volumes[vi].volume_name.assign(
                        name, max_len);
                }
            }

            if (volume.root_tree_block == 0 ||
                report.launchdaemons_cnid != 0) {
                continue;
            }

            // Re-resolve the OMAP entries for this active volume so
            // the walk context uses the same era the filter chose.
            std::vector<std::uint8_t> omap_buf(
                report.container.block_size, 0);
            if (!read_block(
                    file,
                    volume.omap_block,
                    report.container.block_size,
                    omap_buf,
                    error
                )) {
                break;
            }
            const std::uint64_t om_tree_oid =
                read_le64(omap_buf.data() + 0x30);

            std::vector<ApfsOmapEntry> omap_entries;
            std::set<std::uint64_t> visited;
            if (om_tree_oid > 0 &&
                om_tree_oid < report.container.block_count) {
                std::string omap_error;
                if (!omap_collect_entries(
                        file,
                        report.container.block_size,
                        om_tree_oid,
                        report.container.block_count,
                        true,
                        omap_entries,
                        visited,
                        omap_error
                    )) {
                    // Keep going: an unresolvable OMAP simply means
                    // this volume cannot win the plist race.
                    continue;
                }
            }

            FstreeWalkCtx walk_ctx;
            walk_ctx.file = file;
            walk_ctx.block_size = report.container.block_size;
            walk_ctx.block_count = report.container.block_count;
            walk_ctx.omap = &omap_entries;
            walk_ctx.volume_xid = volume.xid;

            const std::uint64_t incompat =
                read_le64(apsb_buf.data() + kApsbIncompatOffset);
            walk_ctx.hashed_names =
                (incompat & kIncompatCaseInsensitive) != 0 ||
                (incompat & kIncompatNormalizationInsensitive) != 0;

            std::uint64_t ld_cnid = 0;
            std::string walk_error;
            if (fstree_resolve_launchdaemons(
                    walk_ctx,
                    volume.root_tree_oid,
                    volume.root_tree_info.level,
                    ld_cnid,
                    walk_error
                )) {
                report.launchdaemons_cnid = ld_cnid;
                report.launchdaemons_status = "RESOLVED";
            } else {
                report.launchdaemons_status =
                    "NOT_RESOLVED: " + walk_error;
                continue;
            }

            // Read one real plist from LaunchDaemons end-to-end.
            // owner_volume_index is recorded against the FINAL
            // active-era volume list, so it can never point at a
            // filtered-out stale candidate.
            if (report.plist_file.status == "NOT_ATTEMPTED") {
                FstreeWalkCtx plist_ctx = walk_ctx;
                report.plist_file.owner_volume_index = vi;
                fstree_read_plist_file(
                    plist_ctx,
                    volume.root_tree_oid,
                    volume.root_tree_info.level,
                    report.launchdaemons_cnid,
                    report.plist_file
                );
            }
        }

        error.clear();
        CloseHandle(file);
        return true;
    } while (false);

    CloseHandle(file);
    return false;
}

// ---------------------------------------------------------------------------
// Structural mutation: single-byte change through the certified read chain.
// ---------------------------------------------------------------------------

namespace {

std::string compute_sha256_hex(
    const std::uint8_t* data,
    std::size_t size
) {
    HCRYPTPROV prov = 0;
    HCRYPTHASH hash = 0;
    std::string out;
    if (!CryptAcquireContextW(
            &prov, nullptr, nullptr, PROV_RSA_AES,
            CRYPT_VERIFYCONTEXT)) {
        return "";
    }
    if (CryptCreateHash(prov, CALG_SHA_256, 0, 0, &hash)) {
        if (CryptHashData(
                hash, const_cast<BYTE*>(data),
                static_cast<DWORD>(size), 0)) {
            BYTE buf[32];
            DWORD len = 32;
            if (CryptGetHashParam(
                    hash, HP_HASHVAL, buf, &len, 0) &&
                len == 32) {
                char hex[65];
                for (DWORD i = 0; i < 32; ++i) {
                    std::snprintf(
                        hex + i * 2, 3, "%02x", buf[i]);
                }
                hex[64] = '\0';
                out = hex;
            }
        }
        CryptDestroyHash(hash);
    }
    CryptReleaseContext(prov, 0);
    return out;
}

std::string format_u64_hex(std::uint64_t v) {
    char buf[32];
    std::snprintf(
        buf, sizeof(buf), "0x%016llx",
        static_cast<unsigned long long>(v));
    return buf;
}

} // namespace

bool apfs_mutate_plist_byte(
    const std::string& image_path,
    const std::string& expected_source_sha256,
    std::uint64_t target_cnid,
    std::uint64_t plist_byte_offset,
    std::uint8_t expected_old_byte,
    std::uint8_t new_byte,
    ApfsMutationResult& result,
    std::string& error
) {
    result = {};
    error.clear();

    // Precondition: refuse if expected source hash is empty.
    if (expected_source_sha256.empty()) {
        error = "REFUSED: expected source SHA-256 is required";
        return false;
    }

    // Open the image for read/write.
    HANDLE file = CreateFileA(
        image_path.c_str(),
        GENERIC_READ | GENERIC_WRITE,
        FILE_SHARE_READ,
        nullptr,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        nullptr
    );
    if (file == INVALID_HANDLE_VALUE) {
        error = "REFUSED: cannot open image for read/write";
        return false;
    }

    // Run the certified reader to resolve the structural chain.
    ApfsReaderReport report;
    std::string read_error;
    {
        // Open a read-only handle with full sharing for the
        // reader, then close it before writing.
        HANDLE reader_handle = CreateFileA(
            image_path.c_str(),
            GENERIC_READ,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            nullptr,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            nullptr
        );
        if (reader_handle == INVALID_HANDLE_VALUE) {
            CloseHandle(file);
            error = "REFUSED: cannot open reader handle";
            return false;
        }
        CloseHandle(reader_handle);

        // apfs_read_container opens its own handle with
        // FILE_SHARE_READ; this conflicts with our writer handle.
        // Close our writer handle temporarily during the read.
        CloseHandle(file);

        if (!apfs_read_container(
                image_path, report, read_error)) {
            error = "REFUSED: reader failed: " + read_error;
            return false;
        }

        // Re-open for writing.
        file = CreateFileA(
            image_path.c_str(),
            GENERIC_READ | GENERIC_WRITE,
            FILE_SHARE_READ,
            nullptr,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            nullptr
        );
        if (file == INVALID_HANDLE_VALUE) {
            error = "REFUSED: cannot reopen for writing";
            return false;
        }
    }

    // Verify plist was found and matches target CNID.
    if (report.plist_file.status != "READ_OK") {
        CloseHandle(file);
        error = "REFUSED: plist not readable: " +
            report.plist_file.status;
        return false;
    }
    if (report.plist_file.drec_cnid != target_cnid) {
        CloseHandle(file);
        error = "REFUSED: target CNID mismatch: expected " +
            std::to_string(target_cnid) + " got " +
            std::to_string(
                report.plist_file.drec_cnid);
        return false;
    }

    // Verify source plist hash matches expectation.
    const std::string actual_hash = compute_sha256_hex(
        report.plist_file.bytes.data(),
        report.plist_file.bytes.size()
    );
    if (actual_hash != expected_source_sha256) {
        CloseHandle(file);
        error = "REFUSED: source plist hash mismatch: expected " +
            expected_source_sha256 + " got " + actual_hash;
        return false;
    }

    // Verify byte offset is within the plist.
    if (plist_byte_offset >=
        report.plist_file.bytes.size()) {
        CloseHandle(file);
        error = "REFUSED: byte offset beyond plist size";
        return false;
    }

    // Verify expected old byte.
    if (report.plist_file.bytes[plist_byte_offset] !=
        expected_old_byte) {
        CloseHandle(file);
        error = "REFUSED: expected old byte mismatch: expected 0x" +
            std::to_string(expected_old_byte) + " got 0x" +
            std::to_string(
                report.plist_file.bytes[plist_byte_offset]);
        return false;
    }

    // Record era/identity from the reader's resolution.
    // Use the first volume with a resolved root tree.
    for (const auto& vol : report.volumes) {
        if (vol.root_tree_block != 0) {
            result.apsb_block = vol.apsb_block;
            result.apsb_oid = vol.apsb_oid;
            result.volume_xid = vol.xid;
            result.root_tree_oid = vol.root_tree_oid;
            result.resolved_root_block = vol.root_tree_block;
            break;
        }
    }
    result.target_cnid = target_cnid;
    result.old_plist_sha256 = actual_hash;
    result.old_byte = expected_old_byte;
    result.new_byte = new_byte;

    // Now we need to find the physical block and offset of the
    // plist byte. The reader found it via the XATTR; we need to
    // locate the FSTREE leaf block containing the XATTR record.
    //
    // We scan for the XATTR record by walking the same FSTREE
    // chain and recording the physical paddr of the leaf node
    // that contains the decmpfs XATTR for target_cnid.
    //
    // For now, we use a focused search: scan blocks that are
    // valid FSTREE leaf nodes containing the XATTR key for the
    // target CNID.

    std::uint64_t target_block = 0;
    std::uint64_t plist_data_block_offset = 0;
    std::uint64_t plist_size = report.plist_file.bytes.size();

    // Read blocks to find the one containing the decmpfs XATTR
    // for the target CNID. We check for the exact XATTR key bytes.
    const std::uint64_t xattr_key = (4ull << 60) | target_cnid;

    for (std::uint64_t b = 0;
         b < report.container.block_count; ++b) {
        std::vector<std::uint8_t> blk(
            report.container.block_size, 0);
        if (!read_block(
                file, b,
                report.container.block_size, blk, error)) {
            continue;
        }

        // Check B-tree + FSTREE.
        const std::uint32_t type =
            read_le32(blk.data() + 24);
        const std::uint32_t kind = type & kObjectTypeMask;
        const std::uint32_t sub =
            read_le32(blk.data() + 28);
        if ((kind != kBtreeType &&
             kind != kBtreeTypeNode) ||
            sub != kFstreeSubtype) {
            continue;
        }

        // Check for our XATTR key bytes in the block.
        // Key is 8 bytes LE.
        for (std::size_t i = 0;
             i + 8 <= blk.size(); ++i) {
            if (read_le64(blk.data() + i) == xattr_key) {
                // Verify this is actually within a key area (not
                // a random data match). Check if the next bytes
                // after the key header look like the XATTR name.
                if (i + 8 + 2 + 18 <= blk.size()) {
                    const std::uint16_t name_len =
                        static_cast<std::uint16_t>(
                            blk[i + 8]) |
                        (static_cast<std::uint16_t>(
                             blk[i + 9]) << 8);
                    if (name_len == 18 &&
                        std::memcmp(
                            blk.data() + i + 10,
                            "com.apple.decmpfs",
                            17) == 0 &&
                        blk[i + 10 + 17] == 0) {
                        // Found it. Now find the plist data
                        // (bplist00 magic) after the XATTR value.
                        for (std::size_t j = i;
                             j + 8 <= blk.size(); ++j) {
                            if (std::memcmp(
                                    blk.data() + j,
                                    "bplist00", 8) == 0) {
                                target_block = b;
                                plist_data_block_offset = j;
                                break;
                            }
                        }
                        if (target_block != 0) break;
                    }
                }
            }
        }
        if (target_block != 0) break;
    }

    if (target_block == 0) {
        CloseHandle(file);
        error =
            "REFUSED: could not structurally locate target block";
        return false;
    }

    result.target_leaf_block = target_block;
    result.data_offset_in_block =
        plist_data_block_offset + plist_byte_offset;

    // Verify block checksum before writing.
    std::vector<std::uint8_t> blk(
        report.container.block_size, 0);
    if (!read_block(
            file, target_block,
            report.container.block_size, blk, error)) {
        CloseHandle(file);
        error = "REFUSED: target block read failed";
        return false;
    }
    if (!apfs_block_checksum_ok(blk)) {
        CloseHandle(file);
        error = "REFUSED: target block checksum mismatch";
        return false;
    }

    result.old_block_checksum = format_u64_hex(
        read_le64(blk.data()));

    // Verify the byte at the target offset matches.
    if (blk[result.data_offset_in_block] !=
        expected_old_byte) {
        CloseHandle(file);
        error =
            "REFUSED: byte at structural offset mismatch";
        return false;
    }

    // Apply mutation.
    blk[result.data_offset_in_block] = new_byte;

    // Recompute checksum.
    const std::uint64_t new_checksum =
        apfs_fletcher64(
            blk.data(), blk.size());
    for (int i = 0; i < 8; ++i) {
        blk[i] = static_cast<std::uint8_t>(
            (new_checksum >> (i * 8)) & 0xFF);
    }

    result.new_block_checksum =
        format_u64_hex(new_checksum);

    // Write block.
    LARGE_INTEGER distance{};
    distance.QuadPart = static_cast<LONGLONG>(
        target_block * report.container.block_size);
    if (!SetFilePointerEx(
            file, distance, nullptr, FILE_BEGIN)) {
        CloseHandle(file);
        error = "REFUSED: seek failed";
        return false;
    }
    DWORD written = 0;
    if (!WriteFile(
            file, blk.data(),
            static_cast<DWORD>(blk.size()),
            &written, nullptr) ||
        written != blk.size()) {
        CloseHandle(file);
        error = "REFUSED: write failed";
        return false;
    }
    if (!FlushFileBuffers(file)) {
        CloseHandle(file);
        error = "REFUSED: flush failed";
        return false;
    }

    // Reread and verify.
    std::vector<std::uint8_t> verify_blk(
        report.container.block_size, 0);
    if (!read_block(
            file, target_block,
            report.container.block_size,
            verify_blk, error) ||
        !apfs_block_checksum_ok(verify_blk) ||
        verify_blk[result.data_offset_in_block] !=
            new_byte) {
        CloseHandle(file);
        error =
            "REFUSED: post-write reread verification failed";
        return false;
    }

    CloseHandle(file);

    // Compute new plist hash (simulate: original with one byte
    // changed).
    std::vector<std::uint8_t> new_plist =
        report.plist_file.bytes;
    new_plist[plist_byte_offset] = new_byte;
    result.new_plist_sha256 = compute_sha256_hex(
        new_plist.data(), new_plist.size());

    result.success = true;
    return true;
}

bool apfs_mutate_plist_byte_safe(
    const std::string& source_image_path,
    const std::string& output_image_path,
    const std::string& expected_source_sha256,
    std::uint64_t target_cnid,
    std::uint64_t plist_byte_offset,
    std::uint8_t expected_old_byte,
    std::uint8_t new_byte,
    ApfsMutationResult& result,
    std::string& error
) {
    result = {};
    error.clear();

    // Safety: source and output must be distinct underlying files.
    // Raw string equality misses path aliases, case variants, and
    // links that resolve to the same file. Compare volume serial
    // numbers plus file indices from both opened handles.
    {
        HANDLE sa = CreateFileA(
            source_image_path.c_str(), GENERIC_READ,
            FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr,
            OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
        HANDLE sb = CreateFileA(
            output_image_path.c_str(), GENERIC_READ,
            FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr,
            OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
        bool same_file = false;
        if (sa != INVALID_HANDLE_VALUE &&
            sb != INVALID_HANDLE_VALUE) {
            BY_HANDLE_FILE_INFORMATION ia {};
            BY_HANDLE_FILE_INFORMATION ib {};
            if (GetFileInformationByHandle(sa, &ia) &&
                GetFileInformationByHandle(sb, &ib)) {
                same_file =
                    ia.dwVolumeSerialNumber ==
                        ib.dwVolumeSerialNumber &&
                    ia.nFileIndexHigh ==
                        ib.nFileIndexHigh &&
                    ia.nFileIndexLow ==
                        ib.nFileIndexLow;
            }
        }
        if (sa != INVALID_HANDLE_VALUE) CloseHandle(sa);
        if (sb != INVALID_HANDLE_VALUE) CloseHandle(sb);
        // Distinct strings that are the same file must refuse.
        // A missing output is expected on first run and is not
        // treated as same-file.
        if (same_file) {
            error =
                "REFUSED: source and output must be distinct paths";
            return false;
        }
    }

    // Safety: source hash must be provided.
    if (expected_source_sha256.empty()) {
        error =
            "REFUSED: expected source SHA-256 is required";
        return false;
    }

    // Step 1: Read the SOURCE image through the certified reader
    // (never opens for writing). This resolves the structural chain
    // and gives us physical provenance for the target XATTR record.
    ApfsReaderReport report;
    if (!apfs_read_container(
            source_image_path, report, error)) {
        error = "REFUSED: source reader failed: " + error;
        return false;
    }

    // Verify plist resolved from the source.
    if (report.plist_file.status != "READ_OK") {
        error = "REFUSED: source plist not readable: " +
            report.plist_file.status;
        return false;
    }
    if (report.plist_file.drec_cnid != target_cnid) {
        error = "REFUSED: target CNID mismatch";
        return false;
    }

    // Verify source plist hash.
    const std::string actual_hash = compute_sha256_hex(
        report.plist_file.bytes.data(),
        report.plist_file.bytes.size());
    if (actual_hash != expected_source_sha256) {
        error = "REFUSED: source hash mismatch";
        return false;
    }

    // Verify byte offset and expected old byte.
    if (plist_byte_offset >=
        report.plist_file.bytes.size()) {
        error = "REFUSED: byte offset beyond plist";
        return false;
    }
    if (report.plist_file.bytes[plist_byte_offset] !=
        expected_old_byte) {
        error = "REFUSED: old byte mismatch at offset";
        return false;
    }

    // Verify structural provenance was recorded.
    if (report.plist_file.xattr_leaf_paddr == 0) {
        error =
            "REFUSED: XATTR leaf provenance not recorded";
        return false;
    }

    // Era binding: use the exact volume that resolved the plist.
    // This binds the write to one deterministic APSB/oid/xid/OMAP
    // chain instead of the first volume with a root tree.
    if (report.plist_file.owner_volume_index >=
            report.volumes.size()) {
        error =
            "REFUSED: plist owner volume not recorded";
        return false;
    }
    const ApfsVolumeInfo& owner_vol =
        report.volumes[
            report.plist_file.owner_volume_index];
    if (owner_vol.root_tree_block == 0 ||
        owner_vol.apsb_oid == 0) {
        error = "REFUSED: plist owner volume chain incomplete";
        return false;
    }
    result.apsb_block = owner_vol.apsb_block;
    result.apsb_oid = owner_vol.apsb_oid;
    result.volume_xid = owner_vol.xid;
    result.root_tree_oid = owner_vol.root_tree_oid;
    result.resolved_root_block = owner_vol.root_tree_block;
    result.target_cnid = target_cnid;
    result.target_leaf_block =
        report.plist_file.xattr_leaf_paddr;
    result.xattr_key_off_in_leaf =
        report.plist_file.xattr_key_off;
    result.xattr_val_off_in_leaf =
        report.plist_file.xattr_val_off;
    result.old_plist_sha256 = actual_hash;
    result.old_byte = expected_old_byte;
    result.new_byte = new_byte;

    // Derive the exact write offset from structural provenance.
    const std::uint64_t write_off_in_leaf =
        report.plist_file.xattr_data_start_off +
        plist_byte_offset;
    result.data_offset_in_block = write_off_in_leaf;

    // Step 2: Copy source to output (the only write target).
    if (!CopyFileA(
            source_image_path.c_str(),
            output_image_path.c_str(),
            FALSE)) {
        error = "REFUSED: copy source to output failed";
        return false;
    }

    // Pre-write reread: the copied output must resolve through the
    // certified reader to the SAME structural provenance before any
    // write handle is opened. This catches a torn/partial copy and
    // proves the copy inherited the exact active-era chain.
    {
        ApfsReaderReport copy_report;
        std::string copy_error;
        if (!apfs_read_container(
                output_image_path, copy_report, copy_error)) {
            error =
                "REFUSED: pre-write reread failed: " +
                copy_error;
            return false;
        }
        if (copy_report.plist_file.status != "READ_OK" ||
            copy_report.plist_file.drec_cnid != target_cnid ||
            copy_report.volumes.empty() ||
            copy_report.volumes[0].apsb_block !=
                result.apsb_block ||
            copy_report.volumes[0].apsb_oid !=
                result.apsb_oid ||
            copy_report.volumes[0].xid != result.volume_xid ||
            copy_report.volumes[0].root_tree_block !=
                result.resolved_root_block ||
            copy_report.plist_file.xattr_leaf_paddr !=
                result.target_leaf_block ||
            copy_report.plist_file.xattr_key_off !=
                result.xattr_key_off_in_leaf ||
            copy_report.plist_file.xattr_val_off !=
                result.xattr_val_off_in_leaf) {
            error =
                "REFUSED: pre-write reread provenance mismatch";
            return false;
        }
    }

    // Step 3: Open output for writing.
    HANDLE out = CreateFileA(
        output_image_path.c_str(),
        GENERIC_READ | GENERIC_WRITE,
        0,
        nullptr,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        nullptr);
    if (out == INVALID_HANDLE_VALUE) {
        error = "REFUSED: cannot open output for writing";
        return false;
    }

    // Step 4: Read and verify the target block on the output copy.
    std::vector<std::uint8_t> blk(
        report.container.block_size, 0);
    if (!read_block(
            out, result.target_leaf_block,
            report.container.block_size, blk, error)) {
        CloseHandle(out);
        error = "REFUSED: target block read failed";
        return false;
    }
    if (!apfs_block_checksum_ok(blk)) {
        CloseHandle(out);
        error = "REFUSED: block checksum mismatch pre-write";
        return false;
    }
    result.old_block_checksum = format_u64_hex(
        read_le64(blk.data()));

    // Verify the byte at the structural offset.
    if (blk[write_off_in_leaf] != expected_old_byte) {
        CloseHandle(out);
        error =
            "REFUSED: byte at structural offset mismatch";
        return false;
    }

    // Step 5: Apply mutation + recompute checksum.
    blk[write_off_in_leaf] = new_byte;
    const std::uint64_t new_ck =
        apfs_fletcher64(blk.data(), blk.size());
    for (int i = 0; i < 8; ++i) {
        blk[i] = static_cast<std::uint8_t>(
            (new_ck >> (i * 8)) & 0xFF);
    }
    result.new_block_checksum = format_u64_hex(new_ck);

    // Step 6: Write block, flush, verify.
    LARGE_INTEGER dist{};
    dist.QuadPart = static_cast<LONGLONG>(
        result.target_leaf_block *
        report.container.block_size);
    if (!SetFilePointerEx(
            out, dist, nullptr, FILE_BEGIN) ||
        !WriteFile(
            out, blk.data(),
            static_cast<DWORD>(blk.size()),
            nullptr, nullptr) ||
        !FlushFileBuffers(out)) {
        CloseHandle(out);
        error = "REFUSED: write/flush failed";
        return false;
    }

    // Reread block and verify.
    std::vector<std::uint8_t> vblk(
        report.container.block_size, 0);
    if (!read_block(
            out, result.target_leaf_block,
            report.container.block_size, vblk, error) ||
        !apfs_block_checksum_ok(vblk) ||
        vblk[write_off_in_leaf] != new_byte) {
        CloseHandle(out);
        error = "REFUSED: post-write block verify failed";
        return false;
    }
    CloseHandle(out);

    // Step 7: Certified reread of the OUTPUT image.
    ApfsReaderReport verify_report;
    std::string verify_error;
    if (!apfs_read_container(
            output_image_path,
            verify_report, verify_error)) {
        error =
            "REFUSED: certified reread failed: " +
            verify_error;
        return false;
    }
    if (verify_report.plist_file.status != "READ_OK" ||
        verify_report.plist_file.drec_cnid !=
            target_cnid) {
        error =
            "REFUSED: certified reread identity mismatch";
        return false;
    }
    if (verify_report.volumes.empty() ||
        verify_report.volumes[0].apsb_block !=
            result.apsb_block ||
        verify_report.volumes[0].apsb_oid !=
            result.apsb_oid ||
        verify_report.volumes[0].xid != result.volume_xid ||
        verify_report.volumes[0].root_tree_block !=
            result.resolved_root_block ||
        verify_report.plist_file.xattr_leaf_paddr !=
            result.target_leaf_block) {
        error =
            "REFUSED: certified reread provenance mismatch";
        return false;
    }
    if (plist_byte_offset >=
            verify_report.plist_file.bytes.size() ||
        verify_report.plist_file.bytes[plist_byte_offset] !=
            new_byte) {
        error =
            "REFUSED: reread logical byte mismatch";
        return false;
    }

    // Compute new plist hash from actual reread bytes.
    result.new_plist_sha256 = compute_sha256_hex(
        verify_report.plist_file.bytes.data(),
        verify_report.plist_file.bytes.size());
    result.reread_plist_sha256 = result.new_plist_sha256;
    result.reread_verified = true;

    if (result.new_plist_sha256 ==
        expected_source_sha256) {
        error =
            "REFUSED: reread hash unchanged after mutation";
        return false;
    }

    result.success = true;
    return true;
}

bool apfs_replace_plist_payload_safe(
    const std::string& source_image_path,
    const std::string& output_image_path,
    const std::string& expected_source_sha256,
    std::uint64_t target_cnid,
    const std::vector<std::uint8_t>& new_payload,
    ApfsMutationResult& result,
    std::string& error
) {
    return apfs_replace_plist_payload_safe_with_hook(
        source_image_path, output_image_path,
        expected_source_sha256, target_cnid, new_payload,
        nullptr, result, error);
}

bool apfs_replace_plist_payload_safe_with_hook(
    const std::string& source_image_path,
    const std::string& output_image_path,
    const std::string& expected_source_sha256,
    std::uint64_t target_cnid,
    const std::vector<std::uint8_t>& new_payload,
    void (*post_copy_hook)(const std::string& output_path),
    ApfsMutationResult& result,
    std::string& error
) {
    result = {};
    error.clear();

    // Safety: distinct underlying files (same identity check as
    // the single-byte gate).
    {
        HANDLE sa = CreateFileA(
            source_image_path.c_str(), GENERIC_READ,
            FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr,
            OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
        HANDLE sb = CreateFileA(
            output_image_path.c_str(), GENERIC_READ,
            FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr,
            OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
        bool same_file = false;
        if (sa != INVALID_HANDLE_VALUE &&
            sb != INVALID_HANDLE_VALUE) {
            BY_HANDLE_FILE_INFORMATION ia {};
            BY_HANDLE_FILE_INFORMATION ib {};
            if (GetFileInformationByHandle(sa, &ia) &&
                GetFileInformationByHandle(sb, &ib)) {
                same_file =
                    ia.dwVolumeSerialNumber ==
                        ib.dwVolumeSerialNumber &&
                    ia.nFileIndexHigh == ib.nFileIndexHigh &&
                    ia.nFileIndexLow == ib.nFileIndexLow;
            }
        }
        if (sa != INVALID_HANDLE_VALUE) CloseHandle(sa);
        if (sb != INVALID_HANDLE_VALUE) CloseHandle(sb);
        if (same_file) {
            error =
                "REFUSED: source and output must be distinct paths";
            return false;
        }
    }

    if (expected_source_sha256.empty()) {
        error = "REFUSED: expected source SHA-256 is required";
        return false;
    }
    if (new_payload.empty()) {
        error = "REFUSED: replacement payload is empty";
        return false;
    }

    // Certified read of the source.
    ApfsReaderReport report;
    if (!apfs_read_container(
            source_image_path, report, error)) {
        error = "REFUSED: source reader failed: " + error;
        return false;
    }
    if (report.plist_file.status != "READ_OK" ||
        report.plist_file.drec_cnid != target_cnid) {
        error =
            "REFUSED: source plist not readable or CNID mismatch";
        return false;
    }
    const std::string actual_hash = compute_sha256_hex(
        report.plist_file.bytes.data(),
        report.plist_file.bytes.size());
    if (actual_hash != expected_source_sha256) {
        error = "REFUSED: source hash mismatch";
        return false;
    }
    if (new_payload.size() !=
        report.plist_file.bytes.size()) {
        error =
            "REFUSED: size-changing replacement not supported "
 "in this gate (expected same-size payload)";
        return false;
    }
    if (report.plist_file.xattr_leaf_paddr == 0) {
        error =
            "REFUSED: XATTR leaf provenance not recorded";
        return false;
    }

    // Record provenance from the owner volume.
    if (report.plist_file.owner_volume_index >=
        report.volumes.size()) {
        error = "REFUSED: plist owner volume not recorded";
        return false;
    }
    const ApfsVolumeInfo& owner_vol =
        report.volumes[
            report.plist_file.owner_volume_index];
    result.apsb_block = owner_vol.apsb_block;
    result.apsb_oid = owner_vol.apsb_oid;
    result.volume_xid = owner_vol.xid;
    result.root_tree_oid = owner_vol.root_tree_oid;
    result.resolved_root_block = owner_vol.root_tree_block;
    result.target_cnid = target_cnid;
    result.target_leaf_block =
        report.plist_file.xattr_leaf_paddr;
    result.xattr_key_off_in_leaf =
        report.plist_file.xattr_key_off;
    result.xattr_val_off_in_leaf =
        report.plist_file.xattr_val_off;
    result.old_plist_sha256 = actual_hash;
    result.data_offset_in_block =
        report.plist_file.xattr_data_start_off;

    // Copy source → output.
    if (!CopyFileA(
            source_image_path.c_str(),
            output_image_path.c_str(),
            FALSE)) {
        error = "REFUSED: copy source to output failed";
        return false;
    }

    // Test seam: allow tests to tamper with the copied output
    // before the pre-write provenance reread validates it.
    if (post_copy_hook) {
        post_copy_hook(output_image_path);
    }

    // Pre-write reread provenance check (identical to single-byte).
    {
        ApfsReaderReport copy_report;
        std::string copy_error;
        if (!apfs_read_container(
                output_image_path, copy_report, copy_error)) {
            error =
                "REFUSED: pre-write reread failed: " +
                copy_error;
            return false;
        }
        if (copy_report.plist_file.status != "READ_OK" ||
            copy_report.plist_file.drec_cnid != target_cnid ||
            copy_report.plist_file.owner_volume_index >=
                copy_report.volumes.size()) {
            error =
                "REFUSED: pre-write reread owner volume invalid";
            return false;
        }
        const ApfsVolumeInfo& copy_owner =
            copy_report.volumes[
                copy_report.plist_file.owner_volume_index];
        if (copy_owner.apsb_block != result.apsb_block ||
            copy_owner.apsb_oid != result.apsb_oid ||
            copy_owner.xid != result.volume_xid ||
            copy_owner.root_tree_block !=
                result.resolved_root_block ||
            copy_report.plist_file.xattr_leaf_paddr !=
                result.target_leaf_block ||
            copy_report.plist_file.xattr_key_off !=
                result.xattr_key_off_in_leaf ||
            copy_report.plist_file.xattr_val_off !=
                result.xattr_val_off_in_leaf) {
            error =
                "REFUSED: pre-write reread provenance mismatch";
            return false;
        }
    }

    // Open output, read leaf, replace payload in place.
    HANDLE out = CreateFileA(
        output_image_path.c_str(),
        GENERIC_READ | GENERIC_WRITE,
        0, nullptr, OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL, nullptr);
    if (out == INVALID_HANDLE_VALUE) {
        error = "REFUSED: cannot open output for writing";
        return false;
    }

    std::vector<std::uint8_t> blk(
        report.container.block_size, 0);
    if (!read_block(
            out, result.target_leaf_block,
            report.container.block_size, blk, error)) {
        CloseHandle(out);
        error = "REFUSED: target leaf read failed";
        return false;
    }
    if (!apfs_block_checksum_ok(blk)) {
        CloseHandle(out);
        error =
            "REFUSED: target leaf checksum mismatch pre-write";
        return false;
    }
    result.old_block_checksum = format_u64_hex(
        read_le64(blk.data()));

    // Verify the decmpfs header fields at the value offset.
    // Bounds-check the full XATTR header region before any field
    // access: {flags u16, xdata_len u16} at val_off..val_off+4,
    // then the 16-byte decmpfs header (sig, algo, logical_size)
    // at val_off+4..val_off+20, then the 1-byte marker at
    // val_off+20.
    const std::uint64_t val_off =
        result.xattr_val_off_in_leaf;
    if (val_off + 21 > blk.size()) {
        CloseHandle(out);
        error =
            "REFUSED: XATTR header exceeds leaf bounds";
        return false;
    }
    const std::uint16_t stored_xdata_len =
        static_cast<std::uint16_t>(blk[val_off + 2]) |
        (static_cast<std::uint16_t>(
             blk[val_off + 3]) << 8);
    const std::uint64_t payload_off = val_off + 21;
    if (stored_xdata_len != 17 + new_payload.size() ||
        payload_off + new_payload.size() > blk.size()) {
        CloseHandle(out);
        error =
            "REFUSED: decmpfs payload geometry mismatch";
        return false;
    }

    // Replace the payload bytes.
    std::memcpy(
        blk.data() + payload_off,
        new_payload.data(),
        new_payload.size());
    // Update logical_size (xdata+8) and keep marker (xdata+16).
    const std::uint64_t new_logical =
        new_payload.size();
    for (int i = 0; i < 8; ++i) {
        blk[val_off + 4 + 8 + i] =
            static_cast<std::uint8_t>(
                (new_logical >> (i * 8)) & 0xFF);
    }

    // Reseal.
    const std::uint64_t new_ck =
        apfs_fletcher64(blk.data(), blk.size());
    for (int i = 0; i < 8; ++i) {
        blk[i] = static_cast<std::uint8_t>(
            (new_ck >> (i * 8)) & 0xFF);
    }
    result.new_block_checksum = format_u64_hex(new_ck);

    // Write + flush + verify block.
    LARGE_INTEGER dist {};
    dist.QuadPart = static_cast<LONGLONG>(
        result.target_leaf_block *
        report.container.block_size);
    DWORD written = 0;
    if (!SetFilePointerEx(
            out, dist, nullptr, FILE_BEGIN) ||
        !WriteFile(
            out, blk.data(),
            static_cast<DWORD>(blk.size()),
            &written, nullptr) ||
        written != blk.size() ||
        !FlushFileBuffers(out)) {
        CloseHandle(out);
        error = "REFUSED: write/flush failed";
        return false;
    }
    std::vector<std::uint8_t> vblk(
        report.container.block_size, 0);
    if (!read_block(
            out, result.target_leaf_block,
            report.container.block_size, vblk, error) ||
        !apfs_block_checksum_ok(vblk)) {
        CloseHandle(out);
        error =
            "REFUSED: post-write block verify failed";
        return false;
    }
    CloseHandle(out);

    // Certified reread of the output.
    ApfsReaderReport verify_report;
    std::string verify_error;
    if (!apfs_read_container(
            output_image_path,
            verify_report, verify_error)) {
        error =
            "REFUSED: certified reread failed: " +
            verify_error;
        return false;
    }
    if (verify_report.plist_file.status != "READ_OK" ||
        verify_report.plist_file.drec_cnid != target_cnid ||
        verify_report.plist_file.owner_volume_index >=
            verify_report.volumes.size()) {
        error =
            "REFUSED: certified reread owner volume invalid";
        return false;
    }
    const ApfsVolumeInfo& verify_owner =
        verify_report.volumes[
            verify_report.plist_file.owner_volume_index];
    if (verify_owner.apsb_block != result.apsb_block ||
        verify_owner.apsb_oid != result.apsb_oid ||
        verify_owner.xid != result.volume_xid ||
        verify_owner.root_tree_block !=
            result.resolved_root_block ||
        verify_report.plist_file.xattr_leaf_paddr !=
            result.target_leaf_block) {
        error =
            "REFUSED: certified reread provenance mismatch";
        return false;
    }
    if (verify_report.plist_file.bytes.size() !=
            new_payload.size() ||
        std::memcmp(
            verify_report.plist_file.bytes.data(),
            new_payload.data(),
            new_payload.size()) != 0) {
        error =
            "REFUSED: reread payload mismatch";
        return false;
    }
    result.new_plist_sha256 = compute_sha256_hex(
        verify_report.plist_file.bytes.data(),
        verify_report.plist_file.bytes.size());
    result.reread_plist_sha256 = result.new_plist_sha256;
    result.reread_verified = true;
    if (result.new_plist_sha256 ==
        expected_source_sha256) {
        error =
            "REFUSED: reread hash unchanged after replacement";
        return false;
    }
    result.success = true;
    return true;
}

bool apfs_parse_leaf_geometry(
    const std::vector<std::uint8_t>& leaf_block,
    std::uint64_t leaf_paddr,
    ApfsLeafGeometry& out,
    std::string& error
) {
    out = ApfsLeafGeometry{};
    error.clear();

    if (leaf_block.size() < 64) {
        error = "leaf block too small for geometry";
        return false;
    }
    const std::uint32_t block_size =
        static_cast<std::uint32_t>(leaf_block.size());

    out.leaf_paddr = leaf_paddr;
    out.block_size = block_size;
    out.node_flags =
        static_cast<std::uint16_t>(leaf_block[0x20]) |
        (static_cast<std::uint16_t>(leaf_block[0x21]) << 8);
    out.node_level =
        static_cast<std::uint16_t>(leaf_block[0x22]) |
        (static_cast<std::uint16_t>(leaf_block[0x23]) << 8);
    out.nkeys = read_le32(leaf_block.data() + 0x24);
    out.table_space_off =
        static_cast<std::uint16_t>(leaf_block[0x28]) |
        (static_cast<std::uint16_t>(leaf_block[0x29]) << 8);
    out.table_space_len =
        static_cast<std::uint16_t>(leaf_block[0x2a]) |
        (static_cast<std::uint16_t>(leaf_block[0x2b]) << 8);

    if (out.node_flags & kBtreeFixedKvSize) {
        error = "fixed-KV leaf not supported for reflow";
        return false;
    }
    if (out.node_level != 0) {
        error = "only level-0 leaves supported for reflow";
        return false;
    }
    if (!(out.node_flags & kBtreeLeaf)) {
        error = "target node is not a leaf";
        return false;
    }

    out.key_base =
        0x38 + out.table_space_off + out.table_space_len;
    out.has_root_footer = (out.node_flags & kBtreeRoot) != 0;
    out.value_base = out.has_root_footer
        ? block_size - 0x28
        : block_size;
    if (out.has_root_footer) {
        out.footer_offset = block_size - 0x28;
    }

    if (out.nkeys == 0) {
        error = "leaf has no records";
        return false;
    }
    const std::uint64_t toc_end =
        0x38 + out.table_space_off + out.table_space_len;
    if (toc_end > block_size) {
        error = "TOC exceeds leaf bounds";
        return false;
    }

    // Parse each record's geometry.
    out.records.resize(out.nkeys);
    std::uint64_t max_key_end = out.key_base;
    std::uint64_t total_value_bytes = 0;
    for (std::uint32_t i = 0; i < out.nkeys; ++i) {
        const std::uint64_t toc_off =
            0x38 + out.table_space_off +
            static_cast<std::uint64_t>(i) * 8;
        if (toc_off + 8 > toc_end) {
            error = "TOC entry exceeds table space";
            return false;
        }
        auto& rec = out.records[i];
        rec.key_off =
            static_cast<std::uint16_t>(leaf_block[toc_off]) |
            (static_cast<std::uint16_t>(leaf_block[toc_off + 1]) << 8);
        rec.key_len =
            static_cast<std::uint16_t>(leaf_block[toc_off + 2]) |
            (static_cast<std::uint16_t>(leaf_block[toc_off + 3]) << 8);
        rec.val_off =
            static_cast<std::uint16_t>(leaf_block[toc_off + 4]) |
            (static_cast<std::uint16_t>(leaf_block[toc_off + 5]) << 8);
        rec.val_len =
            static_cast<std::uint16_t>(leaf_block[toc_off + 6]) |
            (static_cast<std::uint16_t>(leaf_block[toc_off + 7]) << 8);

        rec.abs_key_start = out.key_base + rec.key_off;
        rec.abs_key_end = rec.abs_key_start + rec.key_len;
        // P2-4: Validate BEFORE unsigned subtraction.
        if (rec.val_off > out.value_base) {
            error = "value offset exceeds value_base";
            return false;
        }
        rec.abs_val_start = out.value_base - rec.val_off;
        // P2-4: Validate key offset is within the legal key
        // region before computing absolute endpoints.
        if (rec.key_off > block_size - out.key_base) {
            error = "key offset beyond legal key region";
            return false;
        }
        rec.abs_val_end = rec.abs_val_start + rec.val_len;

        // BLOCKER 5: Individual span validation.
        if (rec.abs_key_end > block_size) {
            error = "key span exceeds leaf bounds";
            return false;
        }
        if (rec.abs_val_end > out.value_base) {
            error = "value span crosses value_base";
            return false;
        }
        if (rec.abs_val_end > block_size) {
            error = "value span exceeds leaf bounds";
            return false;
        }
        if (rec.key_len == 0 && rec.val_len == 0) {
            error = "zero-length key and value";
            return false;
        }

        total_value_bytes += rec.val_len;
        if (rec.abs_key_end > max_key_end) {
            max_key_end = rec.abs_key_end;
        }
    }

    // BLOCKER 5: Cross-record interval validation.
    for (std::uint32_t i = 0; i < out.nkeys; ++i) {
        for (std::uint32_t j = i + 1; j < out.nkeys; ++j) {
            const auto& a = out.records[i];
            const auto& b = out.records[j];
            // Key overlap check (keys must be disjoint).
            if (a.abs_key_start < b.abs_key_end &&
                b.abs_key_start < a.abs_key_end) {
                error = "overlapping key spans";
                return false;
            }
            // Value overlap check (values must be disjoint).
            if (a.abs_val_start < b.abs_val_end &&
                b.abs_val_start < a.abs_val_end) {
                error = "overlapping value spans";
                return false;
            }
        }
        // Key/value region collision.
        if (out.records[i].abs_key_end >
                out.records[i].abs_val_start &&
            out.records[i].abs_key_start <
                out.records[i].abs_val_start) {
            error = "key/value region collision";
            return false;
        }
    }

    // BLOCKER 4: True reflow capacity from value region minus
    // actual value bytes (repack reclaims fragmentation).
    out.key_region_end = max_key_end;
    const std::uint64_t available_value_region =
        out.value_base > max_key_end
            ? out.value_base - max_key_end
            : 0;
    out.free_bytes =
        available_value_region > total_value_bytes
            ? available_value_region - total_value_bytes
            : 0;
    out.packed_values_start =
        out.value_base - total_value_bytes;

    // P1-2: Track the ACTUAL lowest value address (differs from
    // packed_values_start when the leaf is fragmented).
    std::uint64_t actual_min_val = out.value_base;
    for (const auto& rec : out.records) {
        if (rec.abs_val_start < actual_min_val) {
            actual_min_val = rec.abs_val_start;
        }
    }
    out.actual_values_start = actual_min_val;

    // P2-3: Global key/value collision — ALL keys must end
    // before ALL values begin.
    if (max_key_end > actual_min_val) {
        error = "key/value regions overlap";
        return false;
    }

    out.valid = true;
    return true;
}

bool apfs_reflow_leaf_value(
    const std::vector<std::uint8_t>& old_leaf,
    std::uint32_t target_toc_index,
    const std::vector<std::uint8_t>& new_value,
    std::vector<std::uint8_t>& new_leaf,
    ApfsLeafGeometry& geometry_out,
    std::string& error
) {
    error.clear();
    new_leaf.clear();

    ApfsLeafGeometry geo;
    if (!apfs_parse_leaf_geometry(old_leaf, 0, geo, error)) {
        return false;
    }
    if (target_toc_index >= geo.nkeys) {
        error = "target TOC index out of range";
        return false;
    }

    const std::uint64_t old_target_vlen =
        geo.records[target_toc_index].val_len;

    // BLOCKER 4: Compute new total value bytes using the true
    // reflow capacity model. The delta approach is wrong for
    // fragmented leaves where repacking reclaims holes.
    std::uint64_t new_total = new_value.size();
    for (std::uint32_t i = 0; i < geo.nkeys; ++i) {
        if (i != target_toc_index) {
            new_total += geo.records[i].val_len;
        }
    }
    const std::uint64_t available_region =
        geo.value_base > geo.key_region_end
            ? geo.value_base - geo.key_region_end
            : 0;
    if (new_total > available_region) {
        error =
            "REFUSED: resized XATTR does not fit target leaf";
        return false;
    }

    // Copy all current values to independent buffers.
    const std::uint32_t n = geo.nkeys;
    std::vector<std::vector<std::uint8_t>> values(n);
    for (std::uint32_t i = 0; i < n; ++i) {
        const auto& rec = geo.records[i];
        values[i].assign(
            old_leaf.begin() + static_cast<std::ptrdiff_t>(rec.abs_val_start),
            old_leaf.begin() + static_cast<std::ptrdiff_t>(rec.abs_val_end));
    }
    values[target_toc_index] = new_value;

    // BLOCKER 3: Preserve original packing order: record 0 is
    // nearest value_base, record 1 below it, etc. Pack forward.
    std::vector<std::uint64_t> new_val_start(n);
    std::uint64_t cursor = geo.value_base;
    for (std::uint32_t i = 0; i < n; ++i) {
        cursor -= values[i].size();
        new_val_start[i] = cursor;
    }

    const std::uint64_t new_packed_start = cursor;
    // Validate: packed region must not overlap key/TOC region.
    if (new_packed_start < geo.key_region_end) {
        error = "REFUSED: resized XATTR does not fit target leaf";
        return false;
    }
    // BLOCKER 2: Root footer occupies [value_base, block_size).
    // Packed values are entirely BELOW value_base, which is below
    // the footer. The only requirement is: packed_start > key_end.
    // No additional footer check needed because value_base IS the
    // footer start boundary, and values never cross it.

    // Build the new leaf.
    new_leaf = old_leaf;
    // BLOCKER 6: Clear the union of old and new packed regions.
    // P1-2: Use ACTUAL lowest value address, not theoretical
    // packed position, to catch fragmented leaves where values
    // exist below the computed packed region.
    const std::uint64_t old_actual_start = geo.actual_values_start;
    const std::uint64_t clear_start =
        old_actual_start < new_packed_start
            ? old_actual_start
            : new_packed_start;
    std::fill(
        new_leaf.begin() + static_cast<std::ptrdiff_t>(clear_start),
        new_leaf.begin() + static_cast<std::ptrdiff_t>(geo.value_base),
        0);
    // Write each value at its new position.
    for (std::uint32_t i = 0; i < n; ++i) {
        std::memcpy(
            new_leaf.data() + new_val_start[i],
            values[i].data(),
            values[i].size());
    }
    // Update TOC value offsets and lengths.
    for (std::uint32_t i = 0; i < n; ++i) {
        const std::uint64_t toc_off =
            0x38 + geo.table_space_off +
            static_cast<std::uint64_t>(i) * 8;
        // Validate before narrowing: value length must fit
        // uint16_t TOC val_len field.
        if (values[i].size() >
            static_cast<std::size_t>(
                std::numeric_limits<
                    std::uint16_t>::max())) {
            error =
                "REFUSED: record value length exceeds TOC limit";
            return false;
        }
        // Validate before narrowing: value offset must fit
        // uint16_t TOC v_off field.
        const std::uint64_t off_check =
            geo.value_base - new_val_start[i];
        if (off_check >
            static_cast<std::uint64_t>(
                std::numeric_limits<
                    std::uint16_t>::max())) {
            error =
                "REFUSED: value offset exceeds TOC limit";
            return false;
        }
        const std::uint16_t new_v_off =
            static_cast<std::uint16_t>(geo.value_base - new_val_start[i]);
        const std::uint16_t new_v_len =
            static_cast<std::uint16_t>(values[i].size());
        new_leaf[toc_off + 4] = static_cast<std::uint8_t>(new_v_off & 0xff);
        new_leaf[toc_off + 5] = static_cast<std::uint8_t>(new_v_off >> 8);
        new_leaf[toc_off + 6] = static_cast<std::uint8_t>(new_v_len & 0xff);
        new_leaf[toc_off + 7] = static_cast<std::uint8_t>(new_v_len >> 8);
    }

    // Reseal Fletcher-64.
    const std::uint64_t ck = apfs_fletcher64(new_leaf.data(), new_leaf.size());
    for (int i = 0; i < 8; ++i) {
        new_leaf[i] = static_cast<std::uint8_t>((ck >> (i * 8)) & 0xFF);
    }

    geometry_out = geo;
    return true;
}

bool apfs_resize_plist_payload_safe(
    const std::string& source_image_path,
    const std::string& output_image_path,
    const std::string& expected_source_sha256,
    std::uint64_t target_cnid,
    const std::vector<std::uint8_t>& new_payload,
    ApfsMutationResult& result,
    std::string& error
) {
    result = {};
    error.clear();

    if (new_payload.empty()) {
        error = "REFUSED: replacement payload is empty";
        return false;
    }
    if (expected_source_sha256.empty()) {
        error = "REFUSED: expected source SHA-256 is required";
        return false;
    }

    // File identity safety.
    {
        HANDLE sa = CreateFileA(
            source_image_path.c_str(), GENERIC_READ,
            FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr,
            OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
        HANDLE sb = CreateFileA(
            output_image_path.c_str(), GENERIC_READ,
            FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr,
            OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
        bool same_file = false;
        if (sa != INVALID_HANDLE_VALUE &&
            sb != INVALID_HANDLE_VALUE) {
            BY_HANDLE_FILE_INFORMATION ia {};
            BY_HANDLE_FILE_INFORMATION ib {};
            if (GetFileInformationByHandle(sa, &ia) &&
                GetFileInformationByHandle(sb, &ib)) {
                same_file =
                    ia.dwVolumeSerialNumber ==
                        ib.dwVolumeSerialNumber &&
                    ia.nFileIndexHigh == ib.nFileIndexHigh &&
                    ia.nFileIndexLow == ib.nFileIndexLow;
            }
        }
        if (sa != INVALID_HANDLE_VALUE) CloseHandle(sa);
        if (sb != INVALID_HANDLE_VALUE) CloseHandle(sb);
        if (same_file) {
            error =
                "REFUSED: source and output must be distinct paths";
            return false;
        }
    }

    // Certified source read.
    ApfsReaderReport report;
    if (!apfs_read_container(
            source_image_path, report, error)) {
        error = "REFUSED: source reader failed: " + error;
        return false;
    }
    if (report.plist_file.status != "READ_OK" ||
        report.plist_file.drec_cnid != target_cnid) {
        error =
            "REFUSED: source plist not readable or CNID mismatch";
        return false;
    }
    const std::string actual_hash = compute_sha256_hex(
        report.plist_file.bytes.data(),
        report.plist_file.bytes.size());
    if (actual_hash != expected_source_sha256) {
        error = "REFUSED: source hash mismatch";
        return false;
    }
    if (report.plist_file.xattr_leaf_paddr == 0) {
        error =
            "REFUSED: XATTR leaf provenance not recorded";
        return false;
    }

    // Capture provenance.
    if (report.plist_file.owner_volume_index >=
        report.volumes.size()) {
        error = "REFUSED: plist owner volume not recorded";
        return false;
    }
    const ApfsVolumeInfo& owner_vol =
        report.volumes[
            report.plist_file.owner_volume_index];
    result.apsb_block = owner_vol.apsb_block;
    result.apsb_oid = owner_vol.apsb_oid;
    result.volume_xid = owner_vol.xid;
    result.root_tree_oid = owner_vol.root_tree_oid;
    result.resolved_root_block = owner_vol.root_tree_block;
    result.target_cnid = target_cnid;
    result.target_leaf_block =
        report.plist_file.xattr_leaf_paddr;
    result.xattr_key_off_in_leaf =
        report.plist_file.xattr_key_off;
    result.xattr_val_off_in_leaf =
        report.plist_file.xattr_val_off;
    result.old_plist_sha256 = actual_hash;

    // BLOCKER 1: Embedded XATTR value length overflow check.
    // The complete XATTR record value is: 4-byte wrapper +
    // 16-byte decmpfs header + 1-byte marker + payload. Both the
    // xdata_len field AND the B-tree TOC val_len field are
    // uint16_t, so the FULL value (4 + 17 + payload) must fit.
    {
        constexpr std::size_t kXattrValueHeaderSize = 4;
        constexpr std::size_t kDecmpfsOverhead = 17;
        constexpr std::size_t kMaxEmbeddedPayload =
            static_cast<std::size_t>(
                std::numeric_limits<
                    std::uint16_t>::max()) -
            kXattrValueHeaderSize - kDecmpfsOverhead;
        if (new_payload.size() >
            kMaxEmbeddedPayload) {
            error =
                "REFUSED: replacement payload exceeds "
                "embedded XATTR value length limit";
            return false;
        }
    }

    // Copy source → output.
    if (!CopyFileA(
            source_image_path.c_str(),
            output_image_path.c_str(),
            FALSE)) {
        error = "REFUSED: copy source to output failed";
        return false;
    }

    // Pre-write provenance reread (owner-index based).
    {
        ApfsReaderReport copy_report;
        std::string copy_error;
        if (!apfs_read_container(
                output_image_path, copy_report, copy_error)) {
            error =
                "REFUSED: pre-write reread failed: " +
                copy_error;
            return false;
        }
        if (copy_report.plist_file.status != "READ_OK" ||
            copy_report.plist_file.drec_cnid != target_cnid ||
            copy_report.plist_file.owner_volume_index >=
                copy_report.volumes.size()) {
            error =
                "REFUSED: pre-write reread owner volume invalid";
            return false;
        }
        const ApfsVolumeInfo& copy_owner =
            copy_report.volumes[
                copy_report.plist_file.owner_volume_index];
        if (copy_owner.apsb_block != result.apsb_block ||
            copy_owner.apsb_oid != result.apsb_oid ||
            copy_owner.xid != result.volume_xid ||
            copy_owner.root_tree_block !=
                result.resolved_root_block ||
            copy_report.plist_file.xattr_leaf_paddr !=
                result.target_leaf_block ||
            copy_report.plist_file.xattr_key_off !=
                result.xattr_key_off_in_leaf ||
            copy_report.plist_file.xattr_val_off !=
                result.xattr_val_off_in_leaf) {
            error =
                "REFUSED: pre-write reread provenance mismatch";
            return false;
        }
    }

    // Read the target leaf from the output.
    HANDLE out = CreateFileA(
        output_image_path.c_str(),
        GENERIC_READ | GENERIC_WRITE,
        0, nullptr, OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL, nullptr);
    if (out == INVALID_HANDLE_VALUE) {
        error = "REFUSED: cannot open output for writing";
        return false;
    }
    std::vector<std::uint8_t> old_leaf(
        report.container.block_size, 0);
    if (!read_block(
            out, result.target_leaf_block,
            report.container.block_size, old_leaf, error)) {
        CloseHandle(out);
        error = "REFUSED: target leaf read failed";
        return false;
    }
    if (!apfs_block_checksum_ok(old_leaf)) {
        CloseHandle(out);
        error =
            "REFUSED: target leaf checksum mismatch pre-write";
        return false;
    }
    result.old_block_checksum = format_u64_hex(
        read_le64(old_leaf.data()));

    // Parse leaf geometry.
    ApfsLeafGeometry geo;
    if (!apfs_parse_leaf_geometry(
            old_leaf, result.target_leaf_block, geo, error)) {
        CloseHandle(out);
        error = "REFUSED: " + error;
        return false;
    }

    // Find the target XATTR record's TOC index. Match by key
    // offset (the reader recorded xattr_key_off).
    std::uint32_t target_toc = UINT32_MAX;
    for (std::uint32_t i = 0; i < geo.nkeys; ++i) {
        if (geo.records[i].abs_key_start ==
            report.plist_file.xattr_key_off) {
            target_toc = i;
            break;
        }
    }
    if (target_toc == UINT32_MAX) {
        CloseHandle(out);
        error = "REFUSED: target XATTR TOC index not found";
        return false;
    }

    // Construct the resized XATTR value:
    // {flags u16, xdata_len u16, sig u32, algo u32, logical u64,
    //  [pad to 16], marker u8, payload[]}
    const std::uint16_t old_flags = 0x0002; // DATA_EMBEDDED
    const std::uint32_t sig = kDecmpfsSignature;
    const std::uint32_t algo = 9;
    const std::uint64_t logical = new_payload.size();

    const std::uint16_t new_xdata_len =
        static_cast<std::uint16_t>(16 + 1 + new_payload.size());
    std::vector<std::uint8_t> new_value(4 + new_xdata_len, 0);
    new_value[0] = old_flags & 0xff;
    new_value[1] = old_flags >> 8;
    new_value[2] = new_xdata_len & 0xff;
    new_value[3] = new_xdata_len >> 8;
    new_value[4] = sig & 0xff;
    new_value[5] = (sig >> 8) & 0xff;
    new_value[6] = (sig >> 16) & 0xff;
    new_value[7] = (sig >> 24) & 0xff;
    new_value[8] = algo & 0xff;
    new_value[9] = (algo >> 8) & 0xff;
    new_value[10] = (algo >> 16) & 0xff;
    new_value[11] = (algo >> 24) & 0xff;
    for (int i = 0; i < 8; ++i) {
        new_value[12 + i] =
            static_cast<std::uint8_t>(
                (logical >> (i * 8)) & 0xFF);
    }
    new_value[4 + 16] = kDecmpfsPlainMarker; // 0xCC
    std::memcpy(
        new_value.data() + 4 + 16 + 1,
        new_payload.data(),
        new_payload.size());

    // Reflow the leaf.
    std::vector<std::uint8_t> new_leaf;
    ApfsLeafGeometry new_geo;
    if (!apfs_reflow_leaf_value(
            old_leaf, target_toc, new_value,
            new_leaf, new_geo, error)) {
        CloseHandle(out);
        // Reflow errors already have REFUSED: prefix or are
        // capacity/geometry errors.
        if (error.find("REFUSED:") != 0) {
            error = "REFUSED: " + error;
        }
        return false;
    }
    result.new_block_checksum = format_u64_hex(
        read_le64(new_leaf.data()));

    // Write the complete new leaf.
    LARGE_INTEGER dist {};
    dist.QuadPart = static_cast<LONGLONG>(
        result.target_leaf_block *
        report.container.block_size);
    DWORD written = 0;
    if (!SetFilePointerEx(
            out, dist, nullptr, FILE_BEGIN) ||
        !WriteFile(
            out, new_leaf.data(),
            static_cast<DWORD>(new_leaf.size()),
            &written, nullptr) ||
        written != new_leaf.size() ||
        !FlushFileBuffers(out)) {
        CloseHandle(out);
        error = "REFUSED: write/flush failed";
        return false;
    }
    CloseHandle(out);

    // Certified reread.
    ApfsReaderReport verify_report;
    std::string verify_error;
    if (!apfs_read_container(
            output_image_path,
            verify_report, verify_error)) {
        error =
            "REFUSED: certified reread failed: " +
            verify_error;
        DeleteFileA(output_image_path.c_str());
        return false;
    }
    if (verify_report.plist_file.status != "READ_OK" ||
        verify_report.plist_file.drec_cnid != target_cnid ||
        verify_report.plist_file.owner_volume_index >=
            verify_report.volumes.size()) {
        error =
            "REFUSED: certified reread identity mismatch";
        DeleteFileA(output_image_path.c_str());
        return false;
    }
    const ApfsVolumeInfo& verify_owner =
        verify_report.volumes[
            verify_report.plist_file.owner_volume_index];
    if (verify_owner.apsb_block != result.apsb_block ||
        verify_owner.apsb_oid != result.apsb_oid ||
        verify_owner.xid != result.volume_xid ||
        verify_owner.root_tree_block !=
            result.resolved_root_block ||
        verify_report.plist_file.xattr_leaf_paddr !=
            result.target_leaf_block) {
        error =
            "REFUSED: certified reread provenance mismatch";
        DeleteFileA(output_image_path.c_str());
        return false;
    }
    if (verify_report.plist_file.bytes.size() !=
            new_payload.size() ||
        std::memcmp(
            verify_report.plist_file.bytes.data(),
            new_payload.data(),
            new_payload.size()) != 0) {
        error =
            "REFUSED: reread payload mismatch";
        DeleteFileA(output_image_path.c_str());
        return false;
    }
    result.new_plist_sha256 = compute_sha256_hex(
        verify_report.plist_file.bytes.data(),
        verify_report.plist_file.bytes.size());
    result.reread_plist_sha256 = result.new_plist_sha256;
    result.reread_verified = true;
    if (result.new_plist_sha256 ==
        expected_source_sha256) {
        error =
            "REFUSED: reread hash unchanged after replacement";
        DeleteFileA(output_image_path.c_str());
        return false;
    }
    result.success = true;
    return true;
}

} // namespace vphone
