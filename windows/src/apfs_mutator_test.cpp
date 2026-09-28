#include "vphone/apfs_reader.hpp"

#include <windows.h>

#include <wincrypt.h>

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <array>
#include <string>
#include <vector>

namespace {

constexpr std::uint32_t kBlockSize = 4096;
constexpr std::uint64_t kBlockCount = 20;
constexpr std::uint64_t kApsbOid = 42;
constexpr std::uint64_t kApsbXid = 3;
constexpr std::uint64_t kOmapPhys = 4;
constexpr std::uint64_t kOmapTreeOid = 5;
constexpr std::uint64_t kRootOid = 300;
constexpr std::uint64_t kLeafOid = 301;
constexpr std::uint64_t kFileCnid = 50;
constexpr std::uint64_t kLaunchDaemonsCnid = 5;
// Rooted checkpoint authority chain blocks.
constexpr std::uint64_t kCheckpointMapBlock = 15;
constexpr std::uint64_t kContainerOmapPhysBlock = 16;
constexpr std::uint64_t kRogueOmapBlock = 17;
constexpr std::uint64_t kRogueOmapPhysBlock = 2;
constexpr std::uint64_t kRogueOmapPhysTreeBlock = 18;

std::uint64_t fletcher64(const std::vector<std::uint8_t>& b) {
    constexpr std::uint64_t modulus = 0xFFFFFFFFull;
    std::uint64_t s1 = 0;
    std::uint64_t s2 = 0;
    for (std::size_t i = 8; i + 4 <= b.size(); i += 4) {
        const std::uint32_t v =
            static_cast<std::uint32_t>(b[i]) |
            (static_cast<std::uint32_t>(b[i + 1]) << 8) |
            (static_cast<std::uint32_t>(b[i + 2]) << 16) |
            (static_cast<std::uint32_t>(b[i + 3]) << 24);
        s1 = (s1 + v) % modulus;
        s2 = (s2 + s1) % modulus;
    }
    const std::uint64_t c1 =
        modulus - ((s1 + s2) % modulus);
    const std::uint64_t c2 =
        modulus - ((s1 + c1) % modulus);
    return c1 | (c2 << 32);
}

void put_le16(
    std::vector<std::uint8_t>& b, std::size_t off,
    std::uint16_t v) {
    b[off] = static_cast<std::uint8_t>(v & 0xff);
    b[off + 1] = static_cast<std::uint8_t>(v >> 8);
}

void put_le32(
    std::vector<std::uint8_t>& b, std::size_t off,
    std::uint32_t v) {
    for (int i = 0; i < 4; ++i) {
        b[off + i] =
            static_cast<std::uint8_t>((v >> (i * 8)) & 0xff);
    }
}

void put_le64(
    std::vector<std::uint8_t>& b, std::size_t off,
    std::uint64_t v) {
    for (int i = 0; i < 8; ++i) {
        b[off + i] =
            static_cast<std::uint8_t>((v >> (i * 8)) & 0xff);
    }
}

void seal(std::vector<std::uint8_t>& b) {
    put_le64(b, 0, fletcher64(b));
}

bool write_all(
    const std::string& path,
    const std::vector<std::uint8_t>& data) {
    HANDLE f = CreateFileA(
        path.c_str(), GENERIC_WRITE, 0, nullptr,
        CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (f == INVALID_HANDLE_VALUE) return false;
    DWORD written = 0;
    const BOOL ok = WriteFile(
        f, data.data(), static_cast<DWORD>(data.size()),
        &written, nullptr);
    CloseHandle(f);
    return ok && written == data.size();
}

bool read_all(
    const std::string& path, std::vector<std::uint8_t>& out) {
    HANDLE f = CreateFileA(
        path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr,
        OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (f == INVALID_HANDLE_VALUE) return false;
    out.resize(GetFileSize(f, nullptr));
    DWORD n = 0;
    const BOOL ok = ReadFile(
        f, out.data(), static_cast<DWORD>(out.size()), &n,
        nullptr);
    CloseHandle(f);
    return ok && n == out.size();
}

std::string sha256_hex(const std::vector<std::uint8_t>& data) {
    HCRYPTPROV prov = 0;
    HCRYPTHASH hash = 0;
    std::string out;
    if (!CryptAcquireContextW(
            &prov, nullptr, nullptr, PROV_RSA_AES,
            CRYPT_VERIFYCONTEXT)) {
        return out;
    }
    if (CryptCreateHash(
            prov, CALG_SHA_256, 0, 0, &hash)) {
        if (CryptHashData(
                hash, const_cast<BYTE*>(data.data()),
                static_cast<DWORD>(data.size()), 0)) {
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
                out = hex;
            }
        }
        CryptDestroyHash(hash);
    }
    CryptReleaseContext(prov, 0);
    return out;
}

std::vector<std::uint8_t> build_image() {
    std::vector<std::uint8_t> img(
        static_cast<std::size_t>(kBlockCount) * kBlockSize, 0);

    auto put = [&](
        std::uint64_t block,
        const std::vector<std::uint8_t>& blk) {
        std::memcpy(
            img.data() +
                static_cast<std::size_t>(block) * kBlockSize,
            blk.data(), kBlockSize);
    };

    // FSTREE leaf at block 8.
    {
        std::vector<std::uint8_t> blk(kBlockSize, 0);
        put_le64(blk, 8, kLeafOid);
        put_le64(blk, 16, kApsbXid);
        put_le32(blk, 24, 0x40000003u);
        put_le32(blk, 28, 0x0000000Eu);
        blk[0x20] = 0x02;
        blk[0x22] = 0x00;

        const std::uint16_t tlen = 8 * 8;
        const std::uint64_t kb = 0x38 + tlen;
        const std::uint64_t vb = kBlockSize;
        std::uint16_t nkeys = 0;
        std::uint16_t cur_key = 0;
        std::uint64_t cur_val_end = vb;

        auto add_rec = [&](
            std::uint64_t hdr,
            const std::vector<std::uint8_t>& key_extra,
            std::uint16_t val_len,
            const std::vector<std::uint8_t>& val) {
            const std::uint16_t k_len =
                8 + static_cast<std::uint16_t>(
                        key_extra.size());
            const std::uint64_t toc = 0x38 + nkeys * 8;
            put_le16(blk, toc, cur_key);
            put_le16(blk, toc + 2, k_len);
            const std::uint16_t v_off =
                static_cast<std::uint16_t>(
                    vb - (cur_val_end - val_len));
            put_le16(blk, toc + 4, v_off);
            put_le16(blk, toc + 6, val_len);

            const std::uint64_t kp = kb + cur_key;
            put_le64(blk, kp, hdr);
            if (!key_extra.empty()) {
                std::memcpy(
                    blk.data() + kp + 8, key_extra.data(),
                    key_extra.size());
            }
            const std::uint64_t vp = vb - v_off;
            if (!val.empty()) {
                std::memcpy(
                    blk.data() + vp, val.data(), val.size());
            }
            cur_key += k_len;
            cur_val_end -= val_len;
            ++nkeys;
        };

        {
            const char* names[] = {
                "System", "Library", "LaunchDaemons"};
            const std::uint64_t parents[] = {2, 3, 4};
            const std::uint64_t children[] = {
                3, 4, kLaunchDaemonsCnid};
            for (int i = 0; i < 3; ++i) {
                const std::string n = names[i];
                const std::uint16_t stored =
                    static_cast<std::uint16_t>(n.size()) + 1;
                std::vector<std::uint8_t> ke(2 + stored);
                ke[0] = stored & 0xff;
                ke[1] = stored >> 8;
                std::memcpy(ke.data() + 2, n.c_str(), n.size());
                std::vector<std::uint8_t> v(18, 0);
                put_le64(v, 0, children[i]);
                put_le32(v, 16, 4);
                add_rec(
                    (9ull << 60) | parents[i], ke, 18, v);
            }
        }

        {
            const std::string n = "test.plist";
            const std::uint16_t stored =
                static_cast<std::uint16_t>(n.size()) + 1;
            std::vector<std::uint8_t> ke(2 + stored);
            ke[0] = stored & 0xff;
            ke[1] = stored >> 8;
            std::memcpy(ke.data() + 2, n.c_str(), n.size());
            std::vector<std::uint8_t> v(18, 0);
            put_le64(v, 0, kFileCnid);
            put_le32(v, 16, 8);
            add_rec(
                (9ull << 60) | kLaunchDaemonsCnid, ke, 18, v);
        }

        {
            std::vector<std::uint8_t> v(0x64, 0);
            put_le64(v, 0, kLaunchDaemonsCnid);
            put_le64(v, 8, kFileCnid);
            put_le32(v, 0x44, 0x20);
            put_le32(v, 0x50, 0x81a4);
            put_le16(v, 0x5c, 1);
            put_le16(v, 0x5e, 0);
            add_rec((3ull << 60) | kFileCnid, {},
                static_cast<std::uint16_t>(v.size()), v);
        }

        {
            constexpr std::uint16_t kNameLen = 18;
            std::vector<std::uint8_t> ke(2 + kNameLen);
            ke[0] = kNameLen & 0xff;
            ke[1] = kNameLen >> 8;
            std::memcpy(
                ke.data() + 2, "com.apple.decmpfs", 17);
            ke[2 + 17] = 0;

            std::vector<std::uint8_t> xd(28, 0);
            put_le32(xd, 0, 0x636D7066u);
            put_le32(xd, 4, 9);
            put_le64(xd, 8, 11);
            xd[16] = 0xCC;
            const char* payload = "bplist00XY";
            std::memcpy(xd.data() + 17, payload, 10);
            xd[27] = 'Z';

            std::vector<std::uint8_t> xv(4 + xd.size(), 0);
            put_le16(xv, 0, 0x0002);
            put_le16(xv, 2, static_cast<std::uint16_t>(xd.size()));
            std::memcpy(xv.data() + 4, xd.data(), xd.size());
            add_rec(
                (4ull << 60) | kFileCnid, ke,
                static_cast<std::uint16_t>(xv.size()), xv);
        }

        put_le32(blk, 0x24, nkeys);
        put_le32(blk, 0x28,
            static_cast<std::uint32_t>(tlen) << 16);
        seal(blk);
        put(8, blk);
    }

    // OMAP tree leaf at block 5.
    {
        std::vector<std::uint8_t> blk(kBlockSize, 0);
        put_le64(blk, 8, kOmapTreeOid);
        put_le64(blk, 16, kApsbXid);
        put_le32(blk, 24, 0x40000003u);
        put_le32(blk, 0x20, 0x00000006u);
        put_le32(blk, 0x24, 2);
        put_le32(blk, 0x28, 0x00100000u);
        blk[0x38] = 0x00; blk[0x39] = 0x00;
        blk[0x3a] = 0x10; blk[0x3b] = 0x00;
        blk[0x3c] = 0x10; blk[0x3d] = 0x00;
        blk[0x3e] = 0x20; blk[0x3f] = 0x00;
        blk[0x40] = 0x20; blk[0x41] = 0x00;
        blk[0x42] = 0x30; blk[0x43] = 0x00;
        put_le64(blk, 0x48, kRootOid);
        put_le64(blk, 0x50, kApsbXid);
        put_le64(blk, 0x58, kLeafOid);
        put_le64(blk, 0x60, kApsbXid);
        put_le64(blk, 0xfc8 + 8, 6);
        put_le64(blk, 0xfb8 + 8, 8);
        seal(blk);
        put(5, blk);
    }

    // Container OMAP fixed-KV leaf at block 3: maps the volume's
    // virtual APSB oid (42) to the authoritative physical block (1).
    // This is the checkpoint-authoritative reference the reader uses
    // to reject orphan/stale APSB copies.
    {
        std::vector<std::uint8_t> blk(kBlockSize, 0);
        put_le64(blk, 8, 3);
        put_le64(blk, 16, kApsbXid);
        put_le32(blk, 24, 0x40000003u);   // btree node
        put_le32(blk, 28, 0x0000000Bu);   // subtype OMAP
        put_le32(blk, 0x20, 0x00000007u); // root+leaf+fixed
        put_le32(blk, 0x24, 1);           // 1 entry
        put_le32(blk, 0x28, 0x00100000u); // tofs=0, tlen=0x10
        blk[0x38] = 0x00; blk[0x39] = 0x00;
        blk[0x3a] = 0x10; blk[0x3b] = 0x00;
        put_le64(blk, 0x48, kApsbOid);    // key oid
        put_le64(blk, 0x50, kApsbXid);    // key xid
        // Root-leaf value at value_base(0xfd8) - 0x10 = 0xfc8:
        // flags=0, size=block, paddr=1.
        put_le32(blk, 0xfc8, 0);
        put_le32(blk, 0xfcc, kBlockSize);
        put_le64(blk, 0xfd0, 1);
        // btree_info footer at 0xfd8: node_size = block size.
        put_le32(blk, 0xfd8 + 4, kBlockSize);
        seal(blk);
        put(3, blk);
    }

    // Container omap_phys object at block 16. Its om_tree_oid
    // points at the rooted OMAP B-tree leaf (block 3).
    {
        std::vector<std::uint8_t> blk(kBlockSize, 0);
        put_le64(blk, 8, 1000);
        put_le64(blk, 16, kApsbXid);
        put_le32(blk, 24, 0x4000000Bu); // omap_phys type
        put_le64(blk, 0x30, 3);         // om_tree_oid -> block 3
        seal(blk);
        put(kContainerOmapPhysBlock, blk);
    }

    // Checkpoint map at block 15: single entry mapping the
    // container OMAP object (oid 1000) to block 16.
    {
        std::vector<std::uint8_t> blk(kBlockSize, 0);
        put_le64(blk, 8, 1001);
        put_le64(blk, 16, kApsbXid);
        put_le32(blk, 24, 0x4000000Cu); // checkpoint map type
        put_le32(blk, 0x24, 1);          // 1 entry
        // Entry layout (authoritative 40 bytes):
        // {oid, paddr, flags, size, pad} at 0x40.
        put_le64(blk, 0x40, 1000);       // omap object oid
        put_le64(blk, 0x48, kContainerOmapPhysBlock);
        put_le64(blk, 0x50, 0);           // flags: physical
        put_le64(blk, 0x58, kBlockSize);  // size
        put_le64(blk, 0x60, 0);           // pad
        seal(blk);
        put(kCheckpointMapBlock, blk);
    }

    // FSTREE root at block 6.
    {
        std::vector<std::uint8_t> blk(kBlockSize, 0);
        put_le64(blk, 8, kRootOid);
        put_le64(blk, 16, kApsbXid);
        put_le32(blk, 24, 0x40000003u);
        put_le32(blk, 28, 0x0000000Eu);
        blk[0x20] = 0x01;
        blk[0x22] = 0x01;
        put_le32(blk, 0x24, 1);
        put_le32(blk, 0x28, 0x00100000u);
        blk[0x38] = 0x00; blk[0x39] = 0x00;
        blk[0x3a] = 0x10; blk[0x3b] = 0x00;
        blk[0x3c] = 0x10; blk[0x3d] = 0x00;
        blk[0x3e] = 0x08; blk[0x3f] = 0x00;
        put_le64(blk, 0x48, (9ull << 60) | 1ull);
        put_le64(blk, 0xfc8, kLeafOid);
        put_le32(blk, kBlockSize - 0x28, 0);
        put_le32(blk, kBlockSize - 0x28 + 4, kBlockSize);
        seal(blk);
        put(6, blk);
    }

    // OMAP object at block 4.
    {
        std::vector<std::uint8_t> blk(kBlockSize, 0);
        put_le64(blk, 8, kOmapPhys);
        put_le64(blk, 16, kApsbXid);
        put_le32(blk, 24, 0x4000000Bu);
        put_le64(blk, 0x30, kOmapTreeOid);
        seal(blk);
        put(4, blk);
    }

    // APSB at block 1.
    {
        std::vector<std::uint8_t> blk(kBlockSize, 0);
        put_le64(blk, 8, kApsbOid);
        put_le64(blk, 16, kApsbXid);
        put_le32(blk, 24, 0x80000009u);
        put_le32(blk, 32, 0x42535041u);
        put_le64(blk, 0x80, kOmapPhys);
        put_le64(blk, 0x88, kRootOid);
        put_le64(blk, 0x90, 3);
        std::memcpy(blk.data() + 0x2C0, "mutvol", 6);
        seal(blk);
        put(1, blk);
    }

    // NXSB at block 0.
    {
        std::vector<std::uint8_t> blk(kBlockSize, 0);
        put_le64(blk, 8, 1);
        put_le64(blk, 16, kApsbXid);
        put_le32(blk, 24, 0x80000001u);
        put_le32(blk, 32, 0x4253584Eu);
        put_le32(blk, 36, kBlockSize);
        put_le64(blk, 40, kBlockCount);
        // Rooted authority pointers.
        // offset 136 = desc_index/len (not omap; documented)
        put_le32(blk, 104, 1);     // xp_desc area = 1 checkpoint pair
        put_le64(blk, 112, kCheckpointMapBlock); // xp_desc_base
        put_le64(blk, 160, kContainerOmapPhysBlock); // omap ref
        seal(blk);
        put(0, blk);
    }

    return img;
}

// Build a two-era image proving active-era selection:
// - block 7: stale APSB/xid-6-owned leaf with a valid-looking
//   identical XATTR record (appears EARLIER on disk)
// - block 8: active xid-9 leaf reachable via root 6 -> OMAP 5
// The stale leaf is deliberately unreachable from the active
// root tree but byte-pattern-identical in the XATTR key region.
std::vector<std::uint8_t> build_two_era_image() {
    std::vector<std::uint8_t> img = build_image();

    auto put = [&](
        std::uint64_t block,
        const std::vector<std::uint8_t>& blk) {
        std::memcpy(
            img.data() +
                static_cast<std::size_t>(block) * kBlockSize,
            blk.data(), kBlockSize);
    };
    auto get = [&](std::uint64_t block) {
        std::vector<std::uint8_t> blk(kBlockSize, 0);
        std::memcpy(
            blk.data(),
            img.data() +
                static_cast<std::size_t>(block) * kBlockSize,
            kBlockSize);
        return blk;
    };

    // CRITICAL RACE LAYOUT: move the ACTIVE APSB to block 13. The
    // STALE APSB (block 9, xid 2) is physically before it on disk,
    // and the orphan APSB (block 14) is physically after it. Both
    // orderings are therefore covered: stale-first scan attacks and
    // later-block orphan attacks.
    {
        std::vector<std::uint8_t> active_apsb = get(1);
        put(13, active_apsb);
        std::vector<std::uint8_t> blank(kBlockSize, 0);
        put(1, blank);
    }
    // Point the container OMAP entry at the active APSB's new
    // physical block (13).
    {
        std::vector<std::uint8_t> cont_omap = get(3);
        put_le64(cont_omap, 0xfd0, 13);
        seal(cont_omap);
        put(3, cont_omap);
    }
    // Force Path B: remove the checkpoint map's literal
    // nx_omap_oid entry so omap_phys resolution must come from the
    // NXSB direct reference (offset 160), not a map lookup.
    {
        std::vector<std::uint8_t> cmap = get(kCheckpointMapBlock);
        // Entry for an unrelated oid so the map stays structurally
        // valid but Path A cannot resolve the container omap.
        put_le64(cmap, 0x40, 4242);
        put_le32(cmap, 0x24, 1);
        seal(cmap);
        put(kCheckpointMapBlock, cmap);
    }
    // Orphan APSB: same oid, same xid as active, valid checksum,
    // physically before the active APSB — but NOT referenced by the
    // container OMAP. A "newest valid wins" selector would pick it;
    // the checkpoint-authoritative filter must reject it.
    {
        std::vector<std::uint8_t> orphan = get(13);
        // Give the orphan its own OMAP so it looks self-consistent.
        put_le64(orphan, 0x80, 10);
        seal(orphan);
        put(14, orphan);
    }

    // Rogue OMAP leaf: checksum-valid, OMAP-subtype, fixed-KV B-tree
    // with the SAME key {oid=42, xid=3} as the legitimate rooted
    // mapping, but pointing at the orphan APSB (block 14). It is
    // NOT reachable from the container omap_phys at block 16 (whose
    // om_tree_oid is block 3). A global OMAP-leaf scanner with a
    // later-tree tie-break would select block 17 and hijack
    // authority toward the orphan; the rooted resolver must ignore
    // it entirely.
    {
        std::vector<std::uint8_t> rogue(kBlockSize, 0);
        put_le64(rogue, 8, 1002);
        put_le64(rogue, 16, kApsbXid);
        put_le32(rogue, 24, 0x40000003u);   // btree node
        put_le32(rogue, 28, 0x0000000Bu);   // subtype OMAP
        put_le32(rogue, 0x20, 0x00000007u); // root+leaf+fixed
        put_le32(rogue, 0x24, 1);
        put_le32(rogue, 0x28, 0x00100000u);
        rogue[0x38] = 0x00; rogue[0x39] = 0x00;
        rogue[0x3a] = 0x10; rogue[0x3b] = 0x00;
        put_le64(rogue, 0x48, kApsbOid);
        put_le64(rogue, 0x50, kApsbXid);
        // Root-leaf value at value_base(0xfd8) - 0x10 = 0xfc8.
        put_le32(rogue, 0xfc8, 0);
        put_le32(rogue, 0xfcc, kBlockSize);
        put_le64(rogue, 0xfd0, 14); // -> orphan APSB
        put_le32(rogue, 0xfd8 + 4, kBlockSize);
        seal(rogue);
        put(kRogueOmapBlock, rogue);
    }

    // Same-XID rogue omap_phys: physically EARLIER (block 2) than
    // the legitimate omap_phys (block 16), checksum-valid, OMAP
    // type, IDENTICAL xid to the active era — but its tree maps
    // oid 42 to the ORPHAN APSB (block 14), and the NXSB's direct
    // omap reference (offset 160) points at the legitimate block
    // 16, NOT this rogue. A "first OMAP-type object at matching
    // xid wins" scan would select this rogue and hijack authority;
    // the pointer-rooted resolver must ignore it entirely.
    {
        std::vector<std::uint8_t> rogue_phys(kBlockSize, 0);
        put_le64(rogue_phys, 8, 999);
        put_le64(rogue_phys, 16, kApsbXid); // SAME xid as active
        put_le32(rogue_phys, 24, 0x4000000Bu);
        put_le64(
            rogue_phys, 0x30,
            kRogueOmapPhysTreeBlock); // om_tree_oid -> 18
        seal(rogue_phys);
        put(kRogueOmapPhysBlock, rogue_phys);

        // Rogue omap_phys tree at block 18: maps oid 42 -> 14
        // (the orphan APSB).
        std::vector<std::uint8_t> rogue_tree(kBlockSize, 0);
        put_le64(rogue_tree, 8, 998);
        put_le64(rogue_tree, 16, kApsbXid);
        put_le32(rogue_tree, 24, 0x40000002u);
        put_le32(rogue_tree, 28, 0x0000000Bu); // OMAP subtype
        put_le32(rogue_tree, 0x20, 0x00000007u); // root+leaf+fixed
        put_le32(rogue_tree, 0x24, 1);
        put_le32(rogue_tree, 0x28, 0x00100000u);
        rogue_tree[0x38] = 0x00; rogue_tree[0x39] = 0x00;
        rogue_tree[0x3a] = 0x10; rogue_tree[0x3b] = 0x00;
        put_le64(rogue_tree, 0x48, kApsbOid);
        put_le64(rogue_tree, 0x50, kApsbXid);
        put_le32(rogue_tree, 0xfc8, 0);
        put_le32(rogue_tree, 0xfcc, kBlockSize);
        put_le64(rogue_tree, 0xfd0, 14); // -> orphan APSB
        put_le32(rogue_tree, 0xfd8 + 4, kBlockSize);
        seal(rogue_tree);
        put(kRogueOmapPhysTreeBlock, rogue_tree);
    }

    // Copy the active leaf (block 8) to block 7, retag it as a
    // stale xid-6 object with a different leaf OID. Its payload
    // differs in one byte ('S' at plist offset 9 instead of 'Y')
    // so a stale write is detectable by hash/byte inspection.
    {
        std::vector<std::uint8_t> stale = get(8);
        put_le64(stale, 8, 999);       // stale leaf OID
        put_le64(stale, 16, 2);        // stale xid (< active 3)
        // Locate the decmpfs payload marker 'Y' (plist byte 9)
        // and flip it to 'S'.
        bool flipped = false;
        for (std::size_t i = 0; i + 1 < stale.size(); ++i) {
            if (stale[i] == 0xCC &&
                i + 10 < stale.size() &&
                stale[i + 10] == 'Y') {
                stale[i + 10] = 'S';
                flipped = true;
                break;
            }
        }
        if (!flipped) {
            std::fprintf(
                stderr,
                "two-era builder: payload marker not found\n");
            std::exit(1);
        }
        seal(stale);
        put(7, stale);
    }

    // Add a stale APSB with the same oid (42) but xid 6 at block 9.
    // It is fully valid and points at a stale OMAP that resolves
    // the same root oid to the stale leaf (block 7).
    {
        // Stale APSB at block 9.
        std::vector<std::uint8_t> apsb(kBlockSize, 0);
        put_le64(apsb, 8, kApsbOid);   // same volume oid
        put_le64(apsb, 16, 2);         // stale xid (< active 3)
        put_le32(apsb, 24, 0x80000009u);
        put_le32(apsb, 32, 0x42535041u);
        put_le64(apsb, 0x80, 10);      // stale omap block
        put_le64(apsb, 0x88, kRootOid);
        put_le64(apsb, 0x90, 3);
        std::memcpy(apsb.data() + 0x2C0, "mutvol", 6);
        seal(apsb);
        put(9, apsb);

        // Stale OMAP object at block 10.
        std::vector<std::uint8_t> omap(kBlockSize, 0);
        put_le64(omap, 8, 10);
        put_le64(omap, 16, 2);
        put_le32(omap, 24, 0x4000000Bu);
        put_le64(omap, 0x30, 11);      // stale omap tree
        seal(omap);
        put(10, omap);

        // Stale OMAP tree at block 11 mapping kRootOid -> block 12.
        std::vector<std::uint8_t> tree(kBlockSize, 0);
        put_le64(tree, 8, 11);
        put_le64(tree, 16, 2);
        put_le32(tree, 24, 0x40000003u);
        put_le32(tree, 0x20, 0x00000006u);
        put_le32(tree, 0x24, 2);
        put_le32(tree, 0x28, 0x00100000u);
        tree[0x38] = 0x00; tree[0x39] = 0x00;
        tree[0x3a] = 0x10; tree[0x3b] = 0x00;
        tree[0x3c] = 0x10; tree[0x3d] = 0x00;
        tree[0x3e] = 0x20; tree[0x3f] = 0x00;
        tree[0x40] = 0x20; tree[0x41] = 0x00;
        tree[0x42] = 0x30; tree[0x43] = 0x00;
        put_le64(tree, 0x48, kRootOid);
        put_le64(tree, 0x50, 2);
        put_le64(tree, 0x58, 999);     // stale leaf oid
        put_le64(tree, 0x60, 2);
        put_le64(tree, 0xfc8 + 8, 12);
        put_le64(tree, 0xfb8 + 8, 7);
        seal(tree);
        put(11, tree);

        // Stale root at block 12 pointing at stale leaf block 7.
        std::vector<std::uint8_t> root(kBlockSize, 0);
        put_le64(root, 8, kRootOid);
        put_le64(root, 16, 2);
        put_le32(root, 24, 0x40000003u);
        put_le32(root, 28, 0x0000000Eu);
        root[0x20] = 0x01;
        root[0x22] = 0x01;
        put_le32(root, 0x24, 1);
        put_le32(root, 0x28, 0x00100000u);
        root[0x38] = 0x00; root[0x39] = 0x00;
        root[0x3a] = 0x10; root[0x3b] = 0x00;
        root[0x3c] = 0x10; root[0x3d] = 0x00;
        root[0x3e] = 0x08; root[0x3f] = 0x00;
        put_le64(root, 0x48, (9ull << 60) | 1ull);
        put_le64(root, 0xfc8, 999);
        put_le32(root, kBlockSize - 0x28, 0);
        put_le32(root, kBlockSize - 0x28 + 4, kBlockSize);
        seal(root);
        put(12, root);
    }

    return img;
}

} // namespace

int main() {
    char temp[MAX_PATH] = {};
    if (!GetTempPathA(MAX_PATH, temp)) {
        std::fprintf(stderr, "GetTempPathA failed\n");
        return 1;
    }
    const std::string dir(temp);
    const std::string source = dir + "apfs_mut_source.img";
    const std::string output = dir + "apfs_mut_output.img";
    const std::string variant =
        dir + "apfs_mut_variant.img";
    const std::string variant_out =
        dir + "apfs_mut_variant_out.img";

    const auto base = build_image();
    if (!write_all(source, base)) {
        std::fprintf(stderr, "source write failed\n");
        return 1;
    }

    std::string plist_sha;
    {
        vphone::ApfsReaderReport rpt;
        std::string err;
        if (!vphone::apfs_read_container(source, rpt, err)) {
            std::fprintf(
                stderr, "reader failed: %s\n", err.c_str());
            return 1;
        }
        if (rpt.plist_file.status != "READ_OK" ||
            rpt.plist_file.drec_cnid != kFileCnid ||
            rpt.plist_file.format != "binary-plist" ||
            rpt.plist_file.bytes.size() != 11) {
            std::fprintf(
                stderr,
                "unexpected plist resolution: status=%s "
                "cnid=%llu size=%zu\n",
                rpt.plist_file.status.c_str(),
                static_cast<unsigned long long>(
                    rpt.plist_file.drec_cnid),
                rpt.plist_file.bytes.size());
            return 1;
        }
        if (rpt.plist_file.bytes[0] != 'b' ||
            rpt.plist_file.bytes[9] != 'Y' ||
            rpt.plist_file.bytes[10] != 'Z') {
            std::fprintf(
                stderr, "unexpected plist payload\n");
            return 1;
        }
        plist_sha = sha256_hex(rpt.plist_file.bytes);
    }

    // Positive: mutate byte 9 'Y' -> 'Q'; verify reread and
    // source immutability.
    DeleteFileA(output.c_str());
    {
        vphone::ApfsMutationResult r;
        std::string err;
        if (!vphone::apfs_mutate_plist_byte_safe(
                source, output, plist_sha, kFileCnid, 9,
                'Y', 'Q', r, err) ||
            !r.success || !r.reread_verified ||
            r.reread_plist_sha256.empty() ||
            r.reread_plist_sha256 == plist_sha) {
            std::fprintf(
                stderr, "positive safe mutation failed: %s\n",
                err.c_str());
            return 1;
        }

        vphone::ApfsReaderReport out;
        std::string rerr;
        if (!vphone::apfs_read_container(
                output, out, rerr)) {
            std::fprintf(
                stderr, "output reread failed: %s\n",
                rerr.c_str());
            return 1;
        }
        if (out.plist_file.status != "READ_OK" ||
            out.plist_file.bytes.size() != 11 ||
            out.plist_file.bytes[9] != 'Q' ||
            out.plist_file.bytes[10] != 'Z' ||
            sha256_hex(out.plist_file.bytes) !=
                r.reread_plist_sha256) {
            std::fprintf(
                stderr, "certified reread mismatch\n");
            return 1;
        }

        std::vector<std::uint8_t> after;
        if (!read_all(source, after) || after != base) {
            std::fprintf(
                stderr, "SOURCE IMAGE WAS MODIFIED\n");
            return 1;
        }
    }

    // Refusal: source == output.
    {
        vphone::ApfsMutationResult r;
        std::string err;
        if (vphone::apfs_mutate_plist_byte_safe(
                source, source, plist_sha, kFileCnid, 9,
                'Y', 'Q', r, err) ||
            err != "REFUSED: source and output must be "
                   "distinct paths") {
            std::fprintf(
                stderr,
                "[same_source_output] expected refusal, "
                "got '%s'\n", err.c_str());
            return 1;
        }
    }

    // Refusal: wrong source hash.
    DeleteFileA(variant_out.c_str());
    if (!write_all(variant, base)) {
        std::fprintf(stderr, "variant write failed\n");
        return 1;
    }
    {
        vphone::ApfsMutationResult r;
        std::string err;
        if (vphone::apfs_mutate_plist_byte_safe(
                variant, variant_out, "deadbeef", kFileCnid,
                9, 'Y', 'Q', r, err) ||
            err != "REFUSED: source hash mismatch") {
            std::fprintf(
                stderr,
                "[wrong_source_hash] expected refusal, "
                "got '%s'\n", err.c_str());
            return 1;
        }
    }

    // Refusal: wrong CNID.
    DeleteFileA(variant_out.c_str());
    {
        vphone::ApfsMutationResult r;
        std::string err;
        if (vphone::apfs_mutate_plist_byte_safe(
                variant, variant_out, plist_sha, 999, 9,
                'Y', 'Q', r, err) ||
            err != "REFUSED: target CNID mismatch") {
            std::fprintf(
                stderr,
                "[wrong_cnid] expected refusal, got '%s'\n",
                err.c_str());
            return 1;
        }
    }

    // Refusal: old-byte mismatch.
    DeleteFileA(variant_out.c_str());
    {
        vphone::ApfsMutationResult r;
        std::string err;
        if (vphone::apfs_mutate_plist_byte_safe(
                variant, variant_out, plist_sha, kFileCnid,
                9, 'X', 'Q', r, err) ||
            err !=
                "REFUSED: old byte mismatch at offset") {
            std::fprintf(
                stderr,
                "[old_byte_mismatch] expected refusal, "
                "got '%s'\n", err.c_str());
            return 1;
        }
    }

    // Refusal: XATTR absent (reader fails closed on the
    // only candidate). Locate the decmpfs signature in the
    // leaf and corrupt it, then reseal nothing so the reader
    // rejects the record structurally.
    {
        std::vector<std::uint8_t> bad = base;
        const std::size_t leaf_off =
            static_cast<std::size_t>(8) * kBlockSize;
        bool found = false;
        const std::array<std::uint8_t, 4> sig = {
            0x66, 0x70, 0x6D, 0x63}; // "cmpf" LE
        for (std::size_t i = leaf_off;
             i + 4 < leaf_off + kBlockSize; ++i) {
            if (bad[i] == sig[0] && bad[i + 1] == sig[1] &&
                bad[i + 2] == sig[2] &&
                bad[i + 3] == sig[3]) {
                bad[i] = 0xEE;
                found = true;
                break;
            }
        }
        if (!found) {
            std::fprintf(
                stderr, "could not locate decmpfs sig\n");
            return 1;
        }
        if (!write_all(variant, bad)) {
            std::fprintf(stderr, "bad variant write\n");
            return 1;
        }
        DeleteFileA(variant_out.c_str());
        vphone::ApfsMutationResult r;
        std::string err;
        if (vphone::apfs_mutate_plist_byte_safe(
                variant, variant_out, plist_sha, kFileCnid,
                9, 'Y', 'Q', r, err) ||
            err !=
                "REFUSED: source plist not readable: "
                "NOT_ATTEMPTED") {
            std::fprintf(
                stderr,
                "[xattr_absent] expected reader refusal, "
                "got '%s'\n", err.c_str());
            return 1;
        }
    }

    // Refusal: bad block checksum pre-write.
    {
        std::vector<std::uint8_t> bad = base;
        const std::size_t leaf_off =
            static_cast<std::size_t>(8) * kBlockSize;
        bad[leaf_off + 0x100] ^= 0xFF;
        if (!write_all(variant, bad)) {
            std::fprintf(stderr, "bad cksum write\n");
            return 1;
        }
        DeleteFileA(variant_out.c_str());
        vphone::ApfsMutationResult r;
        std::string err;
        if (vphone::apfs_mutate_plist_byte_safe(
                variant, variant_out, plist_sha, kFileCnid,
                9, 'Y', 'Q', r, err) ||
            err !=
                "REFUSED: source plist not readable: "
                "NOT_ATTEMPTED") {
            std::fprintf(
                stderr,
                "[bad_block_checksum] expected refusal, "
                "got '%s'\n", err.c_str());
            return 1;
        }
    }

    // Two-era active-checkpoint proof: stale matching leaf appears
    // EARLIER on disk (block 7) but the active era (NXSB xid 9)
    // resolves to block 8. The mutation must write ONLY block 8;
    // block 7 must remain byte-identical.
    {
        const auto two_era = build_two_era_image();
        const std::string era_source =
            dir + "apfs_mut_two_era_source.img";
        const std::string era_output =
            dir + "apfs_mut_two_era_output.img";
        if (!write_all(era_source, two_era)) {
            std::fprintf(
                stderr, "two-era source write failed\n");
            return 1;
        }
        DeleteFileA(era_output.c_str());

        vphone::ApfsReaderReport rpt;
        std::string rerr;
        if (!vphone::apfs_read_container(
                era_source, rpt, rerr)) {
            std::fprintf(
                stderr, "two-era reader failed: %s\n",
                rerr.c_str());
            return 1;
        }
        // Exactly one active volume (the xid-9 APSB at block 1);
        // the stale xid-6 APSB at block 9 must be excluded.
        if (rpt.volumes.size() != 1 ||
            rpt.volumes[0].xid != kApsbXid ||
            rpt.volumes[0].apsb_block != 13) {
            std::fprintf(
                stderr,
                "two-era active selection wrong: %zu volumes, "
                "first xid=%llu block=%llu\n",
                rpt.volumes.size(),
                rpt.volumes.empty() ? 0ull :
                    static_cast<unsigned long long>(
                        rpt.volumes[0].xid),
                rpt.volumes.empty() ? 0ull :
                    static_cast<unsigned long long>(
                        rpt.volumes[0].apsb_block));
            return 1;
        }

        const std::string era_sha =
            sha256_hex(rpt.plist_file.bytes);
        vphone::ApfsMutationResult r;
        std::string err;
        if (!vphone::apfs_mutate_plist_byte_safe(
                era_source, era_output, era_sha, kFileCnid,
                9, 'Y', 'Q', r, err) ||
            !r.success || !r.reread_verified) {
            std::fprintf(
                stderr,
                "two-era safe mutation failed: %s\n",
                err.c_str());
            return 1;
        }

        // The write must target the ACTIVE leaf (block 8), never
        // the stale leaf (block 7).
        if (r.target_leaf_block != 8) {
            std::fprintf(
                stderr,
                "two-era wrote wrong leaf: %llu (expected 8)\n",
                static_cast<unsigned long long>(
                    r.target_leaf_block));
            return 1;
        }

        // Stale leaf byte-identity proof.
        std::vector<std::uint8_t> after;
        if (!read_all(era_output, after) ||
            after.size() != two_era.size()) {
            std::fprintf(
                stderr, "two-era output read failed\n");
            return 1;
        }
        const std::size_t stale_off =
            static_cast<std::size_t>(7) * kBlockSize;
        for (std::size_t i = 0; i < kBlockSize; ++i) {
            if (after[stale_off + i] !=
                    two_era[stale_off + i]) {
                std::fprintf(
                    stderr,
                    "two-era STALE LEAF MODIFIED at +%zu\n", i);
                return 1;
            }
        }

        // Active leaf must contain exactly one changed data byte
        // plus the checksum word.
        const std::size_t active_off =
            static_cast<std::size_t>(8) * kBlockSize;
        std::size_t changed = 0;
        for (std::size_t i = 0; i < kBlockSize; ++i) {
            if (after[active_off + i] !=
                    two_era[active_off + i]) {
                ++changed;
            }
        }
        // 1 data byte + up to 8 checksum bytes (word may collide)
        if (changed == 0 || changed > 9) {
            std::fprintf(
                stderr,
                "two-era active leaf change count %zu "
                "out of range\n", changed);
            return 1;
        }

        // Era provenance on the reread must match the same
        // APSB/xid/root chain.
        vphone::ApfsReaderReport out_rpt;
        std::string oerr;
        if (!vphone::apfs_read_container(
                era_output, out_rpt, oerr) ||
            out_rpt.volumes.size() != 1 ||
            out_rpt.volumes[0].xid != kApsbXid ||
            out_rpt.volumes[0].apsb_block != 13 ||
            out_rpt.volumes[0].root_tree_block != 6) {
            std::fprintf(
                stderr,
                "two-era output provenance mismatch: %s\n",
                oerr.c_str());
            return 1;
        }

        DeleteFileA(era_source.c_str());
        DeleteFileA(era_output.c_str());
    }

    // Negative: corrupted NXSB checksum must fail closed before any
    // era selection or traversal.
    {
        std::vector<std::uint8_t> bad = build_image();
        bad[0x200] ^= 0xFF; // corrupt after checksum seal
        const std::string bad_path =
            dir + "apfs_mut_bad_nxsb.img";
        if (!write_all(bad_path, bad)) {
            std::fprintf(stderr, "bad nxsb write failed\n");
            return 1;
        }
        vphone::ApfsReaderReport rpt;
        std::string rerr;
        if (vphone::apfs_read_container(bad_path, rpt, rerr)) {
            std::fprintf(
                stderr,
                "[bad_nxsb_checksum] expected reader failure\n");
            return 1;
        }
        if (rerr !=
            "container superblock failed Fletcher-64 checksum") {
            std::fprintf(
                stderr,
                "[bad_nxsb_checksum] error mismatch: '%s'\n",
                rerr.c_str());
            return 1;
        }
        DeleteFileA(bad_path.c_str());
    }

    // Falsification: a value at nx_omap_oid (0xA0/160) that is NOT
    // a plausible physical block — for example a value dominated by
    // high bits the way a misread nx_max_file_systems/fs_index pair
    // would be — must never be reinterpreted as a paddr. The
    // resolver must fail closed, not scan.
    {
        std::vector<std::uint8_t> bad = build_image();
        // 0x100000000 = high-bit-only value (out of geometry).
        const std::size_t nxsb_off = 0;
        put_le64(bad, nxsb_off + 160, 0x100000000ull);
        // Reseal the NXSB so only the omap oid is semantically bad.
        {
            std::vector<std::uint8_t> blk(kBlockSize, 0);
            std::memcpy(
                blk.data(),
                bad.data() + nxsb_off,
                kBlockSize);
            // Clear old checksum then reseal.
            put_le64(blk, 0, 0);
            // Re-seal via fletcher64.
            blk.assign(kBlockSize, 0);
            std::memcpy(
                blk.data(),
                bad.data() + nxsb_off,
                kBlockSize);
            put_le64(blk, 0, 0);
            seal(blk);
            std::memcpy(
                bad.data() + nxsb_off,
                blk.data(),
                kBlockSize);
        }
        const std::string bad_path =
            dir + "apfs_mut_bad_omap_oid.img";
        if (!write_all(bad_path, bad)) {
            std::fprintf(
                stderr, "bad omap oid write failed\n");
            return 1;
        }
        vphone::ApfsReaderReport rpt;
        std::string rerr;
        if (vphone::apfs_read_container(bad_path, rpt, rerr)) {
            std::fprintf(
                stderr,
                "[bad_omap_oid] expected reader failure\n");
            return 1;
        }
        if (rerr !=
            "checkpoint-authoritative resolution failed: "
            "nx_omap_oid is virtual and the checkpoint map has "
            "no matching entry") {
            std::fprintf(
                stderr,
                "[bad_omap_oid] error mismatch: '%s'\n",
                rerr.c_str());
            return 1;
        }
        DeleteFileA(bad_path.c_str());
    }

    DeleteFileA(source.c_str());
    DeleteFileA(output.c_str());
    DeleteFileA(variant.c_str());
    DeleteFileA(variant_out.c_str());

    std::printf("APFS_MUTATOR_TEST_PASS\n");
    return 0;
}
