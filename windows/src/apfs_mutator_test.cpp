#include "vphone/apfs_reader.hpp"

#include <windows.h>

#include <wincrypt.h>

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <array>
#include <fstream>
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
    // 16, NOT this rogue. A "first OMAP-type object at matching\n// xid wins" scan would select this rogue and hijack authority;
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

    // Full payload replacement (same-size): replace the entire
    // 11-byte synthetic plist payload with different bytes of the
    // same length, then verify certified reread returns exactly
    // the new payload.
    {
        DeleteFileA(output.c_str());
        std::vector<std::uint8_t> replacement;
        replacement.push_back('b');
        replacement.push_back('p');
        replacement.push_back('l');
        replacement.push_back('i');
        replacement.push_back('s');
        replacement.push_back('t');
        replacement.push_back('0');
        replacement.push_back('0');
        replacement.push_back('X');
        replacement.push_back('Q');
        replacement.push_back('Z');
        vphone::ApfsMutationResult r;
        std::string err;
        if (!vphone::apfs_replace_plist_payload_safe(
                source, output, plist_sha, kFileCnid,
                replacement, r, err) ||
            !r.success || !r.reread_verified) {
            std::fprintf(
                stderr,
                "full payload replacement failed: %s\n",
                err.c_str());
            return 1;
        }
        vphone::ApfsReaderReport out;
        std::string rerr;
        if (!vphone::apfs_read_container(
                output, out, rerr)) {
            std::fprintf(
                stderr,
                "replacement reread failed: %s\n",
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
                stderr,
                "replacement reread mismatch\n");
            return 1;
        }

        // Size-change refusal.
        if (!write_all(variant, base)) {
            std::fprintf(
                stderr, "size-change variant write failed\n");
            return 1;
        }
        DeleteFileA(variant_out.c_str());
        std::vector<std::uint8_t> wrong_size(12, 'A');
        vphone::ApfsMutationResult r2;
        std::string err2;
        if (vphone::apfs_replace_plist_payload_safe(
                variant, variant_out, plist_sha, kFileCnid,
                wrong_size, r2, err2) ||
            err2.find("size-changing") == std::string::npos) {
            std::fprintf(
                stderr,
                "[size_change] expected refusal, got '%s'\n",
                err2.c_str());
            return 1;
        }
    }

    // Genuine nonzero-owner multi-volume counterexample: the
    // NON-OWNER volume (oid 43) sits at block 1 (LOWER block), the
    // OWNER (oid 42, has the plist) at block 13 (HIGHER block).
    // After disk-order sorting, owner_volume_index == 1.
    {
        std::vector<std::uint8_t> multi =
            build_two_era_image();

        auto put = [&](
            std::uint64_t block,
            const std::vector<std::uint8_t>& blk) {
            std::memcpy(
                multi.data() +
                    static_cast<std::size_t>(block) * kBlockSize,
                blk.data(), kBlockSize);
        };
        auto get = [&](std::uint64_t block) {
            std::vector<std::uint8_t> blk(kBlockSize, 0);
            std::memcpy(
                blk.data(),
                multi.data() +
                    static_cast<std::size_t>(block) * kBlockSize,
                kBlockSize);
            return blk;
        };

        // Non-owner APSB at block 1: oid 43, valid checksum,
        // root_tree_oid that resolves to nothing (unique oid 999
        // not in any OMAP) so it has no LaunchDaemons and no
        // plist. Its low block number guarantees index 0 after
        // sorting.
        {
            std::vector<std::uint8_t> apsb(kBlockSize, 0);
            put_le64(apsb, 8, 43);           // oid 43
            put_le64(apsb, 16, kApsbXid);
            put_le32(apsb, 24, 0x80000009u);
            put_le32(apsb, 32, 0x42535041u);
            put_le64(apsb, 0x80, 4);         // volume omap
            put_le64(apsb, 0x88, 999);       // unique root oid
            put_le64(apsb, 0x90, 3);
            std::memcpy(apsb.data() + 0x2C0, "novol", 5);
            seal(apsb);
            put(1, apsb);
        }

        // Register oid 43 in the container OMAP tree (block 3).
        {
            std::vector<std::uint8_t> omap_blk = get(3);
            put_le32(omap_blk, 0x24, 2); // 2 entries
            // TOC entry 1 at 0x3c: {k=0x10, v=0x20}
            omap_blk[0x3c] = 0x10; omap_blk[0x3d] = 0x00;
            omap_blk[0x3e] = 0x20; omap_blk[0x3f] = 0x00;
            // Key 1 at 0x48 + 0x10 = 0x58: {43, 3}
            put_le64(omap_blk, 0x58, 43);
            put_le64(omap_blk, 0x60, kApsbXid);
            // Value 1 at 0xfd8 - 0x20 = 0xfb8: paddr=1
            put_le32(omap_blk, 0xfb8, 0);
            put_le32(omap_blk, 0xfbc, kBlockSize);
            put_le64(omap_blk, 0xfc0, 1);
            seal(omap_blk);
            put(3, omap_blk);
        }

        const std::string multi_source =
            dir + "apfs_mut_multi_vol.img";
        const std::string multi_output =
            dir + "apfs_mut_multi_vol_out.img";
        if (!write_all(multi_source, multi)) {
            std::fprintf(
                stderr, "multi-vol write failed\n");
            return 1;
        }

        vphone::ApfsReaderReport rpt;
        std::string rerr;
        if (!vphone::apfs_read_container(
                multi_source, rpt, rerr)) {
            std::fprintf(
                stderr, "multi-vol reader failed: %s\n",
                rerr.c_str());
            return 1;
        }
        // Verify genuine nonzero owner.
        if (rpt.volumes.size() != 2) {
            std::fprintf(
                stderr,
                "multi-vol: expected 2 volumes, got %zu\n",
                rpt.volumes.size());
            return 1;
        }
        if (rpt.volumes[0].apsb_oid != 43 ||
            rpt.volumes[0].apsb_block != 1) {
            std::fprintf(
                stderr,
                "multi-vol: non-owner not at index 0\n");
            return 1;
        }
        if (rpt.volumes[1].apsb_oid != 42 ||
            rpt.volumes[1].apsb_block != 13) {
            std::fprintf(
                stderr,
                "multi-vol: owner not at index 1\n");
            return 1;
        }
        if (rpt.plist_file.status != "READ_OK" ||
            rpt.plist_file.owner_volume_index != 1) {
            std::fprintf(
                stderr,
                "multi-vol: owner_volume_index=%llu "
                "(expected 1)\n",
                static_cast<unsigned long long>(
                    rpt.plist_file.owner_volume_index));
            return 1;
        }

        // Replace the payload with DIFFERENT bytes (same size).
        const std::string multi_sha =
            sha256_hex(rpt.plist_file.bytes);
        std::vector<std::uint8_t> replacement =
            rpt.plist_file.bytes;
        for (std::size_t i = 0; i < replacement.size();
             ++i) {
            replacement[i] =
                static_cast<std::uint8_t>(
                    replacement[i] ^ 0x5A);
        }

        // Save non-owner block for untouched verification.
        const std::vector<std::uint8_t> non_owner_before =
            get(1);

        DeleteFileA(multi_output.c_str());
        vphone::ApfsMutationResult r;
        std::string err;
        if (!vphone::apfs_replace_plist_payload_safe(
                multi_source, multi_output, multi_sha,
                kFileCnid, replacement, r, err) ||
            !r.success || !r.reread_verified) {
            std::fprintf(
                stderr,
                "multi-vol replacement failed: %s\n",
                err.c_str());
            return 1;
        }

        // Verify reread bytes match exactly.
        {
            vphone::ApfsReaderReport out;
            std::string oerr;
            if (!vphone::apfs_read_container(
                    multi_output, out, oerr)) {
                std::fprintf(
                    stderr,
                    "multi-vol reread failed: %s\n",
                    oerr.c_str());
                return 1;
            }
            if (out.plist_file.status != "READ_OK" ||
                out.plist_file.owner_volume_index != 1 ||
                out.plist_file.bytes.size() !=
                    replacement.size() ||
                std::memcmp(
                    out.plist_file.bytes.data(),
                    replacement.data(),
                    replacement.size()) != 0) {
                std::fprintf(
                    stderr,
                    "multi-vol reread mismatch\n");
                return 1;
            }
            // Owner provenance on reread.
            if (out.volumes[1].apsb_block != 13 ||
                out.volumes[1].apsb_oid != 42) {
                std::fprintf(
                    stderr,
                    "multi-vol reread owner mismatch\n");
                return 1;
            }
        }

        // Non-owner block 1 must remain byte-identical.
        {
            std::vector<std::uint8_t> after;
            if (!read_all(multi_output, after) ||
                after.size() != multi.size()) {
                std::fprintf(
                    stderr,
                    "multi-vol output read failed\n");
                return 1;
            }
            const std::size_t no_off =
                static_cast<std::size_t>(1) * kBlockSize;
            for (std::size_t i = 0; i < kBlockSize; ++i) {
                if (after[no_off + i] !=
                    non_owner_before[i]) {
                    std::fprintf(
                        stderr,
                        "multi-vol NON-OWNER MODIFIED\n");
                    return 1;
                }
            }
        }

        // Source must remain unchanged.
        {
            std::vector<std::uint8_t> after;
            if (!read_all(multi_source, after) ||
                after != multi) {
                std::fprintf(
                    stderr,
                    "multi-vol SOURCE MODIFIED\n");
                return 1;
            }
        }

        // Negative: wrong source hash → fail closed before write.
        DeleteFileA(multi_output.c_str());
        vphone::ApfsMutationResult r2;
        std::string err2;
        if (vphone::apfs_replace_plist_payload_safe(
                multi_source, multi_output,
                "deadbeef", kFileCnid, replacement,
                r2, err2) ||
            err2 != "REFUSED: source hash mismatch") {
            std::fprintf(
                stderr,
                "multi-vol negative: got '%s'\n",
                err2.c_str());
            return 1;
        }

        DeleteFileA(multi_source.c_str());
        DeleteFileA(multi_output.c_str());
    }

    // Provenance-tamper negative (reviewer-required): use the
    // post-copy hook to tamper the owner APSB xid in the OUTPUT
    // after CopyFile but before the pre-write provenance reread.
    // The function must FAIL CLOSED with the exact provenance
    // mismatch error and leave the target leaf + source untouched.
    {
        std::vector<std::uint8_t> multi =
            build_two_era_image();
        {
            auto put = [&](
                std::uint64_t block,
                const std::vector<std::uint8_t>& blk) {
                std::memcpy(
                    multi.data() +
                        static_cast<std::size_t>(block) *
                            kBlockSize,
                    blk.data(), kBlockSize);
            };
            std::vector<std::uint8_t> apsb(kBlockSize, 0);
            put_le64(apsb, 8, 43);
            put_le64(apsb, 16, kApsbXid);
            put_le32(apsb, 24, 0x80000009u);
            put_le32(apsb, 32, 0x42535041u);
            put_le64(apsb, 0x80, 4);
            put_le64(apsb, 0x88, 999);
            put_le64(apsb, 0x90, 3);
            seal(apsb);
            put(1, apsb);
            std::vector<std::uint8_t> omap_blk(kBlockSize, 0);
            std::memcpy(omap_blk.data(), multi.data() + 3 * kBlockSize, kBlockSize);
            put_le32(omap_blk, 0x24, 2);
            omap_blk[0x3c] = 0x10; omap_blk[0x3d] = 0x00;
            omap_blk[0x3e] = 0x20; omap_blk[0x3f] = 0x00;
            put_le64(omap_blk, 0x58, 43);
            put_le64(omap_blk, 0x60, kApsbXid);
            put_le32(omap_blk, 0xfb8, 0);
            put_le32(omap_blk, 0xfbc, kBlockSize);
            put_le64(omap_blk, 0xfc0, 1);
            seal(omap_blk);
            put(3, omap_blk);
        }

        const std::string tp_src = dir + "apfs_mut_tp_src.img";
        const std::string tp_out = dir + "apfs_mut_tp_out.img";
        if (!write_all(tp_src, multi)) return 1;

        std::string tp_sha;
        std::vector<std::uint8_t> tp_payload;
        // Runtime provenance capture from the SOURCE read.
        std::uint64_t src_owner_idx = 0;
        std::uint64_t src_apsb_block = 0;
        std::uint64_t src_apsb_oid = 0;
        std::uint64_t src_xid = 0;
        std::uint64_t src_root_oid = 0;
        std::uint64_t src_root_block = 0;
        std::uint64_t src_leaf = 0;
        std::uint64_t src_cnid = 0;
        {
            vphone::ApfsReaderReport rpt;
            std::string rerr;
            if (!vphone::apfs_read_container(tp_src, rpt, rerr)) {
                std::fprintf(stderr, "tp reader: %s\n", rerr.c_str());
                return 1;
            }
            if (rpt.plist_file.status != "READ_OK") {
                std::fprintf(stderr, "tp: plist not READ_OK\n");
                return 1;
            }
            tp_sha = sha256_hex(rpt.plist_file.bytes);
            tp_payload = rpt.plist_file.bytes;
            for (auto& b : tp_payload) b ^= 0x5A;

            // Capture the ACTUAL owner volume provenance at runtime.
            if (rpt.plist_file.owner_volume_index >= rpt.volumes.size()) {
                std::fprintf(stderr, "tp: owner index out of range\n");
                return 1;
            }
            const auto& src_owner = rpt.volumes[rpt.plist_file.owner_volume_index];
            src_owner_idx = rpt.plist_file.owner_volume_index;
            src_apsb_block = src_owner.apsb_block;
            src_apsb_oid = src_owner.apsb_oid;
            src_xid = src_owner.xid;
            src_root_oid = src_owner.root_tree_oid;
            src_root_block = src_owner.root_tree_block;
            src_leaf = rpt.plist_file.xattr_leaf_paddr;
            src_cnid = rpt.plist_file.drec_cnid;

            // Runtime-verify the fixture's expectations.
            if (src_leaf != 8) {
                std::fprintf(stderr, "tp: src_leaf=%llu expected 8\n",
                    (unsigned long long)src_leaf);
                return 1;
            }
            if (src_cnid != kFileCnid) {
                std::fprintf(stderr, "tp: src_cnid=%llu expected %llu\n",
                    (unsigned long long)src_cnid,
                    (unsigned long long)kFileCnid);
                return 1;
            }
            // Runtime-verify the fixture's original root block.
            if (src_root_block != 6) {
                std::fprintf(stderr, "tp: original root=%llu expected 6\n",
                    (unsigned long long)src_root_block);
                return 1;
            }
        }

        // Save target leaf (block 8) before.
        std::vector<std::uint8_t> leaf_before(kBlockSize, 0);
        std::memcpy(leaf_before.data(),
            multi.data() + static_cast<std::size_t>(src_leaf) * kBlockSize,
            kBlockSize);

        // Tamper hook: duplicate root block 6 -> 19, redirect OMAP
        // mapping, reseal. Post-flush state is validated.
        auto tamper = [](const std::string& path) {
            // 1. Duplicate root block 6 -> 19.
            std::vector<std::uint8_t> root_blk(kBlockSize, 0);
            {
                std::ifstream tf(path, std::ios::binary);
                if (!tf.good()) { std::fprintf(stderr, "tamper: open failed\n"); std::exit(1); }
                tf.seekg(6 * kBlockSize);
                tf.read(reinterpret_cast<char*>(root_blk.data()), kBlockSize);
                if (!tf.good()) { std::fprintf(stderr, "tamper: read root failed\n"); std::exit(1); }
                tf.close();
            }
            {
                std::ofstream to(path, std::ios::binary | std::ios::in | std::ios::out);
                if (!to.good()) { std::fprintf(stderr, "tamper: open write failed\n"); std::exit(1); }
                to.seekp(19 * kBlockSize);
                to.write(reinterpret_cast<const char*>(root_blk.data()), kBlockSize);
                if (!to.good()) { std::fprintf(stderr, "tamper: write dup failed\n"); std::exit(1); }
                to.flush();
                if (!to.good()) { std::fprintf(stderr, "tamper: flush dup failed\n"); std::exit(1); }
                to.close();
            }

            // 2. Redirect OMAP mapping paddr 6 -> 19 at 0xfd0.
            std::vector<std::uint8_t> omap_blk(kBlockSize, 0);
            {
                std::ifstream tf(path, std::ios::binary);
                if (!tf.good()) { std::fprintf(stderr, "tamper: omap open failed\n"); std::exit(1); }
                tf.seekg(5 * kBlockSize);
                tf.read(reinterpret_cast<char*>(omap_blk.data()), kBlockSize);
                if (!tf.good()) { std::fprintf(stderr, "tamper: omap read failed\n"); std::exit(1); }
                tf.close();
            }
            put_le64(omap_blk, 0xfd0, 19);
            seal(omap_blk);
            {
                std::ofstream to(path, std::ios::binary | std::ios::in | std::ios::out);
                if (!to.good()) { std::fprintf(stderr, "tamper: omap write open failed\n"); std::exit(1); }
                to.seekp(5 * kBlockSize);
                to.write(reinterpret_cast<const char*>(omap_blk.data()), kBlockSize);
                if (!to.good()) { std::fprintf(stderr, "tamper: omap write failed\n"); std::exit(1); }
                to.flush();
                if (!to.good()) { std::fprintf(stderr, "tamper: omap flush failed\n"); std::exit(1); }
                to.close();
            }
        };

        const std::uint64_t tampered_root_block = 19;

        DeleteFileA(tp_out.c_str());
        vphone::ApfsMutationResult r;
        std::string err;
        const bool ok = vphone::apfs_replace_plist_payload_safe_with_hook(
            tp_src, tp_out, tp_sha, kFileCnid, tp_payload,
            tamper, r, err);
        if (ok || err != "REFUSED: pre-write reread provenance mismatch") {
            std::fprintf(stderr, "[tamper] expected exact provenance mismatch, got ok=%d err='%s'\n",
                ok ? 1 : 0, err.c_str());
            return 1;
        }
        if (r.success) {
            std::fprintf(stderr, "[tamper] result reports success\n");
            return 1;
        }

        // Prove the tampered output remains READ_OK with same
        // owner provenance except root_tree_block 6 -> 19.
        {
            vphone::ApfsReaderReport out_rpt;
            std::string oerr;
            if (!vphone::apfs_read_container(tp_out, out_rpt, oerr)) {
                std::fprintf(stderr, "[tamper] output not readable: %s\n", oerr.c_str());
                return 1;
            }
            if (out_rpt.plist_file.status != "READ_OK") {
                std::fprintf(stderr, "[tamper] plist not READ_OK\n");
                return 1;
            }
            // Validate via owner_volume_index, not hardcoded [1].
            if (out_rpt.plist_file.owner_volume_index >= out_rpt.volumes.size()) {
                std::fprintf(stderr, "[tamper] output owner index out of range\n");
                return 1;
            }
            const auto& out_owner =
                out_rpt.volumes[out_rpt.plist_file.owner_volume_index];
            if (out_rpt.plist_file.drec_cnid != src_cnid) {
                std::fprintf(stderr, "[tamper] CNID changed\n");
                return 1;
            }
            const std::string out_sha =
                sha256_hex(out_rpt.plist_file.bytes);
            if (out_sha != tp_sha) {
                std::fprintf(stderr, "[tamper] payload hash changed\n");
                return 1;
            }
            // Prove the requested replacement never reached disk.
            const std::string replacement_sha =
                sha256_hex(tp_payload);
            if (out_sha == replacement_sha) {
                std::fprintf(stderr, "[tamper] replacement payload reached disk!\n");
                return 1;
            }
            if (out_owner.apsb_block != src_apsb_block) {
                std::fprintf(stderr, "[tamper] APSB block changed\n");
                return 1;
            }
            if (out_owner.apsb_oid != src_apsb_oid) {
                std::fprintf(stderr, "[tamper] APSB oid changed\n");
                return 1;
            }
            if (out_owner.xid != src_xid) {
                std::fprintf(stderr, "[tamper] xid changed\n");
                return 1;
            }
            if (out_owner.root_tree_oid != src_root_oid) {
                std::fprintf(stderr, "[tamper] root_tree_oid changed\n");
                return 1;
            }
            if (out_owner.root_tree_block != tampered_root_block) {
                std::fprintf(stderr, "[tamper] root_tree_block=%llu expected %llu\n",
                    (unsigned long long)out_owner.root_tree_block,
                    (unsigned long long)tampered_root_block);
                return 1;
            }
            if (src_root_block != 6) {
                std::fprintf(stderr, "[tamper] source root was not 6\n");
                return 1;
            }
            if (out_rpt.plist_file.xattr_leaf_paddr != src_leaf) {
                std::fprintf(stderr, "[tamper] XATTR leaf changed\n");
                return 1;
            }
            if (out_rpt.plist_file.owner_volume_index != src_owner_idx) {
                std::fprintf(stderr, "[tamper] owner index changed\n");
                return 1;
            }
        }

        // Target leaf (block 8) must be byte-identical.
        bool target_unchanged = false;
        {
            std::vector<std::uint8_t> leaf_after(kBlockSize, 0);
            std::ifstream tf(tp_out, std::ios::binary);
            if (!tf.good()) { std::fprintf(stderr, "[tamper] leaf open failed\n"); return 1; }
            tf.seekg(static_cast<std::streamoff>(src_leaf * kBlockSize));
            tf.read(reinterpret_cast<char*>(leaf_after.data()), kBlockSize);
            tf.close();
            target_unchanged = (leaf_after == leaf_before);
            if (!target_unchanged) {
                std::fprintf(stderr, "[tamper] target leaf modified\n");
                return 1;
            }
        }

        // Source must remain unchanged.
        bool source_unchanged = false;
        {
            std::vector<std::uint8_t> after;
            source_unchanged = read_all(tp_src, after) && after == multi;
            if (!source_unchanged) {
                std::fprintf(stderr, "[tamper] source modified\n");
                return 1;
            }
        }

        // Emit evidence line with runtime values.
        std::printf(
            "PROVENANCE_TAMPER_PASS owner=%llu apsb=%llu root=%llu->%llu "
            "leaf=%llu cnid=%llu err=\"REFUSED: pre-write reread provenance mismatch\" "
            "source_unchanged=%d target_unchanged=%d\n",
            (unsigned long long)src_owner_idx,
            (unsigned long long)src_apsb_block,
            (unsigned long long)src_root_block,
            (unsigned long long)tampered_root_block,
            (unsigned long long)src_leaf,
            (unsigned long long)src_cnid,
            source_unchanged ? 1 : 0,
            target_unchanged ? 1 : 0);

        DeleteFileA(tp_src.c_str());
        DeleteFileA(tp_out.c_str());
    }

    // Size-changing replacement: grow, shrink, insufficient space.
    {
        const std::string rs_src = dir + "apfs_mut_resize_src.img";
        const std::string rs_out = dir + "apfs_mut_resize_out.img";
        if (!write_all(rs_src, base)) {
            std::fprintf(stderr, "resize src write failed\n");
            return 1;
        }
        std::string rs_sha;
        {
            vphone::ApfsReaderReport rpt;
            std::string rerr;
            if (!vphone::apfs_read_container(rs_src, rpt, rerr)) {
                std::fprintf(stderr, "resize reader: %s\n", rerr.c_str());
                return 1;
            }
            rs_sha = sha256_hex(rpt.plist_file.bytes);
        }

        // A. Grow by 1: 11 -> 12.
        {
            DeleteFileA(rs_out.c_str());
            std::vector<std::uint8_t> grow12 = {'b','p','l','i','s','t','0','0','X','Q','Z','W'};
            vphone::ApfsMutationResult r;
            std::string err;
            if (!vphone::apfs_resize_plist_payload_safe(
                    rs_src, rs_out, rs_sha, kFileCnid, grow12, r, err) ||
                !r.success || !r.reread_verified) {
                std::fprintf(stderr, "[resize grow+1] failed: %s\n", err.c_str());
                return 1;
            }
            vphone::ApfsReaderReport out;
            std::string oerr;
            if (!vphone::apfs_read_container(rs_out, out, oerr) ||
                out.plist_file.status != "READ_OK" ||
                out.plist_file.bytes.size() != 12 ||
                out.plist_file.drec_cnid != kFileCnid ||
                std::memcmp(out.plist_file.bytes.data(), grow12.data(), 12) != 0 ||
                out.plist_file.decmpfs_logical_size != 12) {
                std::fprintf(stderr, "[resize grow+1] reread mismatch\n");
                return 1;
            }
            std::printf("RESIZE_GROW1_PASS old=11 new=12 sha=%s\n", r.reread_plist_sha256.c_str());
        }

        // B. Shrink: 11 -> 5.
        {
            DeleteFileA(rs_out.c_str());
            std::vector<std::uint8_t> shrink5 = {'b','p','l','i','s'};
            vphone::ApfsMutationResult r;
            std::string err;
            if (!vphone::apfs_resize_plist_payload_safe(
                    rs_src, rs_out, rs_sha, kFileCnid, shrink5, r, err) ||
                !r.success || !r.reread_verified) {
                std::fprintf(stderr, "[resize shrink] failed: %s\n", err.c_str());
                return 1;
            }
            vphone::ApfsReaderReport out;
            std::string oerr;
            if (!vphone::apfs_read_container(rs_out, out, oerr) ||
                out.plist_file.status != "READ_OK" ||
                out.plist_file.bytes.size() != 5 ||
                std::memcmp(out.plist_file.bytes.data(), shrink5.data(), 5) != 0) {
                std::fprintf(stderr, "[resize shrink] reread mismatch\n");
                return 1;
            }
            std::printf("RESIZE_SHRINK_PASS old=11 new=5 sha=%s\n", r.reread_plist_sha256.c_str());
        }

        // C. Insufficient space: absurdly large payload.
        {
            DeleteFileA(rs_out.c_str());
            std::vector<std::uint8_t> huge(8000, 'H');
            vphone::ApfsMutationResult r;
            std::string err;
            if (vphone::apfs_resize_plist_payload_safe(
                    rs_src, rs_out, rs_sha, kFileCnid, huge, r, err)) {
                std::fprintf(stderr, "[resize huge] expected refusal\n");
                return 1;
            }
            if (err.find("does not fit") == std::string::npos) {
                std::fprintf(stderr, "[resize huge] wrong error: %s\n", err.c_str());
                return 1;
            }
            std::printf("RESIZE_INSUFFICIENT_PASS err=\"%s\"\n", err.c_str());
        }

        // E. XATTR length overflow boundary tests.
        {
            DeleteFileA(rs_out.c_str());
            // Max legal embedded payload = 65535 - 17 = 65518.
            // This will fail at the leaf-capacity gate (4096
            // block), which is correct behavior. But payloads
            // > 65518 must fail at the LENGTH gate first.
            vphone::ApfsMutationResult r;
            std::string err;
            // 65515 bytes: first illegal (max legal = 65514).
            DeleteFileA(rs_out.c_str());
            std::vector<std::uint8_t> b65515(65515, 'F');
            if (vphone::apfs_resize_plist_payload_safe(
                    rs_src, rs_out, rs_sha, kFileCnid,
                    b65515, r, err)) {
                std::fprintf(
                    stderr,
                    "[boundary 65515] expected refusal\n");
                return 1;
            }
            if (err != "REFUSED: replacement payload exceeds "
                       "embedded XATTR value length limit") {
                std::fprintf(
                    stderr,
                    "[boundary 65515] wrong error: %s\n",
                    err.c_str());
                return 1;
            }
            // 65518 bytes: exceeds 65514 (old wrong bound was
            // 65518 which forgot the 4-byte XATTR wrapper).
            DeleteFileA(rs_out.c_str());
            std::vector<std::uint8_t> b65518(65518, 'E');
            if (vphone::apfs_resize_plist_payload_safe(
                    rs_src, rs_out, rs_sha, kFileCnid,
                    b65518, r, err)) {
                std::fprintf(
                    stderr,
                    "[boundary 65518] expected refusal\n");
                return 1;
            }
            if (err != "REFUSED: replacement payload exceeds "
                       "embedded XATTR value length limit") {
                std::fprintf(
                    stderr,
                    "[boundary 65518] wrong error: %s\n",
                    err.c_str());
                return 1;
            }
            // 65519 bytes: also exceeds.
            std::vector<std::uint8_t> over(65519, 'O');
            if (vphone::apfs_resize_plist_payload_safe(
                    rs_src, rs_out, rs_sha, kFileCnid,
                    over, r, err)) {
                std::fprintf(
                    stderr,
                    "[overflow 65519] expected refusal\n");
                return 1;
            }
            if (err != "REFUSED: replacement payload exceeds "
                       "embedded XATTR value length limit") {
                std::fprintf(
                    stderr,
                    "[overflow 65519] wrong error: %s\n",
                    err.c_str());
                return 1;
            }
            // 65535: also exceeds.
            DeleteFileA(rs_out.c_str());
            std::vector<std::uint8_t> way(65535, 'W');
            if (vphone::apfs_resize_plist_payload_safe(
                    rs_src, rs_out, rs_sha, kFileCnid,
                    way, r, err)) {
                std::fprintf(
                    stderr,
                    "[overflow 65535] expected refusal\n");
                    return 1;
            }
            if (err != "REFUSED: replacement payload exceeds "
                       "embedded XATTR value length limit") {
                std::fprintf(
                    stderr,
                    "[overflow 65535] wrong error: %s\n",
                    err.c_str());
                return 1;
            }
            // 100000: very large.
            DeleteFileA(rs_out.c_str());
            std::vector<std::uint8_t> vlarge(100000, 'V');
            if (vphone::apfs_resize_plist_payload_safe(
                    rs_src, rs_out, rs_sha, kFileCnid,
                    vlarge, r, err)) {
                std::fprintf(
                    stderr,
                    "[overflow 100000] expected refusal\n");
                return 1;
            }
            std::printf(
                "RESIZE_XATTR_LENGTH_OVERFLOW_PASS "
                "err=\"%s\"\n",
                err.c_str());
            // Source must be unchanged.
            {
                std::vector<std::uint8_t> after;
                if (!read_all(rs_src, after) ||
                    after != base) {
                    std::fprintf(
                        stderr,
                        "[overflow] source modified\n");
                    return 1;
                }
            }
        }

        // D. Source immutability.
        {
            std::vector<std::uint8_t> after;
            if (!read_all(rs_src, after) || after != base) {
                std::fprintf(stderr, "[resize] source modified\n");
                return 1;
            }
        }
        DeleteFileA(rs_src.c_str());
        DeleteFileA(rs_out.c_str());
    }



    // ================================================================
    // COMPREHENSIVE FIXTURE SWEEP for Phase 5F closure.
    // Uses apfs_parse_leaf_geometry + apfs_reflow_leaf_value directly
    // to exercise exact boundary cases, fragmented leaves, root
    // leaves, neighbor preservation, and malformed geometry.
    // ================================================================
    {
        // Helper: build a minimal variable-KV leaf block with
        // configurable records.
        auto build_kv_leaf = [&](
            const std::vector<std::vector<std::uint8_t>>& keys,
            const std::vector<std::vector<std::uint8_t>>& vals,
            bool is_root,
            std::uint16_t flags_override = 0
        ) -> std::vector<std::uint8_t> {
            std::vector<std::uint8_t> blk(kBlockSize, 0);
            put_le64(blk, 8, 300); // oid
            put_le64(blk, 16, 3);  // xid
            put_le32(blk, 24, 0x40000003u);
            put_le32(blk, 28, 0x0000000Eu);
            std::uint16_t flags = is_root ? 0x03 : 0x02; // root+leaf or leaf
            if (flags_override) flags = flags_override;
            blk[0x20] = flags & 0xff;
            blk[0x21] = flags >> 8;
            blk[0x22] = 0; // level 0
            const std::uint32_t n = static_cast<std::uint32_t>(keys.size());
            put_le32(blk, 0x24, n);
            // tlen = n * 8 (variable-KV)
            const std::uint16_t tlen = static_cast<std::uint16_t>(n * 8);
            put_le32(blk, 0x28, static_cast<std::uint32_t>(tlen) << 16);
            // Key base = 0x38 + tlen
            const std::uint16_t key_base = 0x38 + tlen;
            // Value base = root ? 4096 - 0x28 : 4096
            const std::uint16_t vbase = is_root ? kBlockSize - 0x28 : kBlockSize;

            std::uint16_t cur_key_off = 0;
            std::uint32_t cumulative_val = 0;
            for (std::uint32_t i = 0; i < n; ++i) {
                // v_off = distance from value_base to START of this
                // value = sum of val_lens 0..i inclusive.
                cumulative_val += static_cast<std::uint32_t>(vals[i].size());
                const std::uint16_t v_off =
                    static_cast<std::uint16_t>(cumulative_val);
                // TOC entry
                const std::uint32_t toc = 0x38 + i * 8;
                put_le16(blk, toc, cur_key_off);
                put_le16(blk, toc + 2, static_cast<std::uint16_t>(keys[i].size()));
                put_le16(blk, toc + 4, v_off);
                put_le16(blk, toc + 6, static_cast<std::uint16_t>(vals[i].size()));
                // Key at key_base + cur_key_off
                std::memcpy(blk.data() + key_base + cur_key_off, keys[i].data(), keys[i].size());
                // Value starts at vbase - v_off
                const std::uint16_t vp = static_cast<std::uint16_t>(vbase - v_off);
                std::memcpy(blk.data() + vp, vals[i].data(), vals[i].size());
                cur_key_off += static_cast<std::uint16_t>(keys[i].size());
            }

            // Footer for root
            if (is_root) {
                put_le32(blk, kBlockSize - 0x28 + 4, kBlockSize); // node_size
            }

            seal(blk);
            return blk;
        };

        // --- EXACT CAPACITY TEST ---
        // Build a leaf where values + 1 extra byte exactly fill
        // the available region (value_base - key_region_end).
        {
            // 2 records: small key + value pair, plus target
            std::vector<std::uint8_t> k1 = {1,2,3,4,5,6,7,8}; // 8B key
            std::vector<std::uint8_t> v1(20, 0xAA); // 20B value
            std::vector<std::uint8_t> k2 = {9,10,11,12,13,14,15,16}; // 8B key
            // We'll compute the exact target value size at runtime
            // to fill remaining space exactly.
            std::vector<std::uint8_t> k_target = {17,18,19,20,21,22,23,24};

            // First pass: build with placeholder to get geometry
            std::vector<std::uint8_t> v2_placeholder(1, 0xBB);
            auto leaf1 = build_kv_leaf({k1, k2}, {v1, v2_placeholder}, false);
            vphone::ApfsLeafGeometry geo1;
            std::string geo_err;
            if (!vphone::apfs_parse_leaf_geometry(leaf1, 0, geo1, geo_err)) {
                std::fprintf(stderr, "[exact] parse failed: %s\n", geo_err.c_str());
                return 1;
            }
            // Debug: print geometry
            std::fprintf(stderr, "[exact] key_region_end=%llu value_base=%llu free=%llu\n",
                (unsigned long long)geo1.key_region_end,
                (unsigned long long)geo1.value_base,
                (unsigned long long)geo1.free_bytes);
            // available = value_base - key_region_end
            const std::uint64_t avail = geo1.value_base - geo1.key_region_end;
            // existing = v1 + v2
            const std::uint64_t existing = v1.size() + v2_placeholder.size();
            // target size = avail - v1 (so v1 + target = avail exactly)
            const std::uint64_t target_size = avail - v1.size();
            std::vector<std::uint8_t> v2_exact(target_size, 0xCC);

            // Rebuild with exact size
            auto leaf_exact = build_kv_leaf({k1, k2}, {v1, v2_exact}, false);
            vphone::ApfsLeafGeometry geo_exact;
            if (!vphone::apfs_parse_leaf_geometry(leaf_exact, 0, geo_exact, geo_err)) {
                std::fprintf(stderr, "[exact] reparse failed: %s\n", geo_err.c_str());
                return 1;
            }
            // Verify exact fit: key_region_end + total_values == value_base
            const std::uint64_t total_vals = v1.size() + v2_exact.size();
            if (geo_exact.key_region_end + total_vals != geo_exact.value_base) {
                std::fprintf(stderr, "[exact] not exact fit\n");
                return 1;
            }

            // Reflow with SAME size (should succeed — exact fit)
            std::vector<std::uint8_t> new_leaf;
            vphone::ApfsLeafGeometry out_geo;
            std::string rerr;
            if (!vphone::apfs_reflow_leaf_value(
                    leaf_exact, 1, v2_exact, new_leaf, out_geo, rerr)) {
                std::fprintf(stderr, "[exact] reflow failed: %s\n", rerr.c_str());
                return 1;
            }
            // Verify: Fletcher passes on the new leaf
            // (rebuild checksum manually)
            std::vector<std::uint8_t> check = new_leaf;
            put_le64(check, 0, 0);
            seal(check);
            if (new_leaf != check) {
                std::fprintf(stderr, "[exact] checksum mismatch\n");
                return 1;
            }
            std::printf("REFLOW_EXACT_CAPACITY_PASS avail=%llu\n",
                (unsigned long long)avail);

            // Capacity + 1: add one more byte, should refuse
            std::vector<std::uint8_t> v2_plus(target_size + 1, 0xDD);
            std::vector<std::uint8_t> new_leaf2;
            vphone::ApfsLeafGeometry out_geo2;
            std::string rerr2;
            if (vphone::apfs_reflow_leaf_value(
                    leaf_exact, 1, v2_plus, new_leaf2, out_geo2, rerr2)) {
                std::fprintf(stderr, "[exact+1] should refuse\n");
                return 1;
            }
            if (rerr2.find("does not fit") == std::string::npos) {
                std::fprintf(stderr, "[exact+1] wrong error: %s\n", rerr2.c_str());
                return 1;
            }
            std::printf("REFLOW_CAPACITY_PLUS_ONE_REFUSED_PASS err=\"%s\"\n",
                rerr2.c_str());
        }

        // --- ROOT LEAF TESTS ---
        {
            // Build a root leaf (ROOT+LEAF flags, with footer)
            std::vector<std::uint8_t> k1 = {1,2,3,4,5,6,7,8};
            std::vector<std::uint8_t> v1(50, 0xAA);
            std::vector<std::uint8_t> k2 = {9,10,11,12,13,14,15,16};
            std::vector<std::uint8_t> v2(100, 0xBB);
            auto root_leaf = build_kv_leaf({k1, k2}, {v1, v2}, true);

            // Verify root footer is present
            vphone::ApfsLeafGeometry geo;
            std::string gerr;
            if (!vphone::apfs_parse_leaf_geometry(root_leaf, 0, geo, gerr)) {
                std::fprintf(stderr, "[root] parse failed: %s\n", gerr.c_str());
                return 1;
            }
            if (!geo.has_root_footer) {
                std::fprintf(stderr, "[root] footer not detected\n");
                return 1;
            }

            // Grow target (record 1) by 10 bytes
            std::vector<std::uint8_t> v2_grown(110, 0xBB);
            std::vector<std::uint8_t> grown_leaf;
            vphone::ApfsLeafGeometry grown_geo;
            std::string grerr;
            if (!vphone::apfs_reflow_leaf_value(
                    root_leaf, 1, v2_grown, grown_leaf, grown_geo, grerr)) {
                std::fprintf(stderr, "[root grow] failed: %s\n", grerr.c_str());
                return 1;
            }
            // Footer bytes preserved (last 0x28 bytes unchanged)
            if (std::memcmp(
                    root_leaf.data() + kBlockSize - 0x28,
                    grown_leaf.data() + kBlockSize - 0x28,
                    0x28) != 0) {
                std::fprintf(stderr, "[root grow] footer changed\n");
                return 1;
            }
            std::printf("ROOT_LEAF_GROW_PASS\n");
            std::printf("ROOT_FOOTER_PRESERVED_PASS\n");

            // Shrink target by 50 bytes
            std::vector<std::uint8_t> v2_shrunk(50, 0xBB);
            std::vector<std::uint8_t> shrunk_leaf;
            vphone::ApfsLeafGeometry shrunk_geo;
            std::string srerr;
            if (!vphone::apfs_reflow_leaf_value(
                    root_leaf, 1, v2_shrunk, shrunk_leaf, shrunk_geo, srerr)) {
                std::fprintf(stderr, "[root shrink] failed: %s\n", srerr.c_str());
                return 1;
            }
            if (std::memcmp(
                    root_leaf.data() + kBlockSize - 0x28,
                    shrunk_leaf.data() + kBlockSize - 0x28,
                    0x28) != 0) {
                std::fprintf(stderr, "[root shrink] footer changed\n");
                return 1;
            }
            std::printf("ROOT_LEAF_SHRINK_PASS\n");

            // Insufficient: absurdly large
            std::vector<std::uint8_t> v2_huge(5000, 0xFF);
            std::vector<std::uint8_t> huge_leaf;
            vphone::ApfsLeafGeometry huge_geo;
            std::string hrerr;
            if (vphone::apfs_reflow_leaf_value(
                    root_leaf, 1, v2_huge, huge_leaf, huge_geo, hrerr)) {
                std::fprintf(stderr, "[root insufficient] should refuse\n");
                return 1;
            }
            std::printf("ROOT_LEAF_INSUFFICIENT_PASS err=\"%s\"\n",
                hrerr.c_str());
        }

        // --- NEIGHBOR PRESERVATION ---
        {
            std::vector<std::uint8_t> k1 = {1,2,3,4,5,6,7,8};
            std::vector<std::uint8_t> v1(30, 0x11);
            std::vector<std::uint8_t> k2 = {9,10,11,12,13,14,15,16};
            std::vector<std::uint8_t> v2(40, 0x22);
            std::vector<std::uint8_t> k3 = {17,18,19,20,21,22,23,24};
            std::vector<std::uint8_t> v3(50, 0x33);
            auto leaf = build_kv_leaf({k1, k2, k3}, {v1, v2, v3}, false);

            // Grow record 1 (middle)
            std::vector<std::uint8_t> v2_new(60, 0x22);
            std::vector<std::uint8_t> new_leaf;
            vphone::ApfsLeafGeometry new_geo;
            std::string nerr;
            if (!vphone::apfs_reflow_leaf_value(
                    leaf, 1, v2_new, new_leaf, new_geo, nerr)) {
                std::fprintf(stderr, "[neighbor] reflow failed: %s\n", nerr.c_str());
                return 1;
            }

            // Parse new leaf and verify non-target records have
            // identical key and value bytes.
            vphone::ApfsLeafGeometry check_geo;
            std::string cerr_;
            if (!vphone::apfs_parse_leaf_geometry(new_leaf, 0, check_geo, cerr_)) {
                std::fprintf(stderr, "[neighbor] reparse failed: %s\n", cerr_.c_str());
                return 1;
            }
            // Record 0: key and value preserved
            if (std::memcmp(new_leaf.data() + check_geo.records[0].abs_key_start,
                    leaf.data() + /* old key 0 */ 0, 0) != 0) {
                // noop — we compare by extracting
            }
            // Extract and compare
            auto extract_val = [&](
                const std::vector<std::uint8_t>& blk,
                const vphone::ApfsLeafGeometry& g,
                std::uint32_t idx
            ) -> std::vector<std::uint8_t> {
                const auto& r = g.records[idx];
                return std::vector<std::uint8_t>(
                    blk.begin() + r.abs_val_start,
                    blk.begin() + r.abs_val_end);
            };
            auto extract_key = [&](
                const std::vector<std::uint8_t>& blk,
                const vphone::ApfsLeafGeometry& g,
                std::uint32_t idx
            ) -> std::vector<std::uint8_t> {
                const auto& r = g.records[idx];
                return std::vector<std::uint8_t>(
                    blk.begin() + r.abs_key_start,
                    blk.begin() + r.abs_key_end);
            };

            vphone::ApfsLeafGeometry old_geo;
            std::string ogerr;
            if (!vphone::apfs_parse_leaf_geometry(leaf, 0, old_geo, ogerr)) {
                std::fprintf(stderr, "[neighbor] old parse failed\n");
                return 1;
            }
            if (extract_key(new_leaf, check_geo, 0) != extract_key(leaf, old_geo, 0) ||
                extract_key(new_leaf, check_geo, 2) != extract_key(leaf, old_geo, 2)) {
                std::fprintf(stderr, "[neighbor] keys changed\n");
                return 1;
            }
            if (extract_val(new_leaf, check_geo, 0) != extract_val(leaf, old_geo, 0) ||
                extract_val(new_leaf, check_geo, 2) != extract_val(leaf, old_geo, 2)) {
                std::fprintf(stderr, "[neighbor] values changed\n");
                return 1;
            }
            std::printf("REFLOW_NEIGHBOR_VALUES_PRESERVED_PASS\n");
            std::printf("REFLOW_RECORD_ORDER_PASS\n");
        }

        // --- GEOMETRY NEGATIVE TESTS ---
        {
            // Helper to create a leaf with a specific TOC mutation
            auto make_bad_leaf = [&](
                const std::vector<std::uint8_t>& good_leaf,
                std::uint32_t record_idx,
                std::uint16_t new_val_off,
                std::uint16_t new_val_len,
                std::uint16_t new_key_off = 0,
                bool use_key_off = false
            ) -> std::vector<std::uint8_t> {
                auto bad = good_leaf;
                const std::uint32_t toc = 0x38 + record_idx * 8;
                if (use_key_off) {
                    put_le16(bad, toc, new_key_off);
                }
                put_le16(bad, toc + 4, new_val_off);
                put_le16(bad, toc + 6, new_val_len);
                seal(bad);
                return bad;
            };

            // Build a valid base leaf
            std::vector<std::uint8_t> k1 = {1,2,3,4,5,6,7,8};
            std::vector<std::uint8_t> v1(30, 0x11);
            std::vector<std::uint8_t> k2 = {9,10,11,12,13,14,15,16};
            std::vector<std::uint8_t> v2(40, 0x22);
            auto base_leaf = build_kv_leaf({k1, k2}, {v1, v2}, false);

            // 1. Overlapping values: make record 1 overlap record 0
            {
                auto bad = make_bad_leaf(base_leaf, 1, 60, 40); // overlaps record 0
                vphone::ApfsLeafGeometry g;
                std::string e;
                if (vphone::apfs_parse_leaf_geometry(bad, 0, g, e)) {
                    std::fprintf(stderr, "[geo overlap] accepted\n");
                    return 1;
                }
                if (e != "overlapping value spans") {
                    std::fprintf(stderr, "[geo overlap] wrong error: %s\n", e.c_str());
                    return 1;
                }
                std::printf("GEOMETRY_OVERLAPPING_VALUES_REFUSED_PASS\n");
            }

            // 2. Value offset underflow: val_off > value_base
            {
                auto bad = make_bad_leaf(base_leaf, 0, 5000, 10);
                vphone::ApfsLeafGeometry g;
                std::string e;
                if (vphone::apfs_parse_leaf_geometry(bad, 0, g, e)) {
                    std::fprintf(stderr, "[geo underflow] accepted\n");
                    return 1;
                }
                if (e != "value offset exceeds value_base") {
                    std::fprintf(stderr, "[geo underflow] wrong error: %s\n", e.c_str());
                    return 1;
                }
                std::printf("GEOMETRY_VALUE_OFFSET_UNDERFLOW_REFUSED_PASS\n");
            }

            // 3. Key offset OOB: key_off beyond legal region
            {
                auto bad = make_bad_leaf(base_leaf, 0, 0, 30, 6000, true);
                vphone::ApfsLeafGeometry g;
                std::string e;
                if (vphone::apfs_parse_leaf_geometry(bad, 0, g, e)) {
                    std::fprintf(stderr, "[geo key OOB] accepted\n");
                    return 1;
                }
                if (e != "key offset beyond legal key region") {
                    std::fprintf(stderr, "[geo key OOB] wrong error: %s\n", e.c_str());
                    return 1;
                }
                std::printf("GEOMETRY_KEY_OFFSET_OOB_REFUSED_PASS\n");
            }

            // 4. Invalid offset (value span crosses value_base)
            {
                // Make val_off small enough that val_end > value_base
                auto bad = make_bad_leaf(base_leaf, 0, 0, 5000);
                vphone::ApfsLeafGeometry g;
                std::string e;
                if (vphone::apfs_parse_leaf_geometry(bad, 0, g, e)) {
                    std::fprintf(stderr, "[geo invalid] accepted\n");
                    return 1;
                }
                if (e != "value span crosses value_base") {
                    std::fprintf(stderr, "[geo invalid] wrong error: %s\n", e.c_str());
                    return 1;
                }
                std::printf("GEOMETRY_INVALID_OFFSET_REFUSED_PASS\n");
            }

            // 5. Key/value regions overlap (global check)
            {
                // Make key region extend into value region by
                // setting a key offset that goes past key_base into values
                auto bad = base_leaf;
                // Get geometry first to know where values start
                vphone::ApfsLeafGeometry g0;
                std::string e0;
                vphone::apfs_parse_leaf_geometry(base_leaf, 0, g0, e0);
                // Set key 1's length to extend into value region
                const std::uint32_t toc = 0x38 + 0 * 8; // record 0
                const std::uint16_t big_key_len = static_cast<std::uint16_t>(
                    g0.value_base - g0.key_base - g0.records[0].key_off);
                put_le16(bad, toc + 2, big_key_len);
                seal(bad);
                vphone::ApfsLeafGeometry g;
                std::string e;
                if (vphone::apfs_parse_leaf_geometry(bad, 0, g, e)) {
                    std::fprintf(stderr, "[geo kv overlap] accepted\n");
                    return 1;
                }
                std::printf("GEOMETRY_KEY_VALUE_COLLISION_REFUSED_PASS err=\"%s\"\n",
                    e.c_str());
            }
        }
    }


    // ================================================================
    // FINAL 6 FIXTURES for Phase 5F closure.
    // ================================================================
    {
        // Helper to build a leaf with a TOC mutation.
        auto mutate_toc = [&](
            std::vector<std::uint8_t> leaf,
            std::uint32_t rec,
            int field, // 0=key_off, 2=key_len, 4=val_off, 6=val_len
            std::uint16_t value
        ) -> std::vector<std::uint8_t> {
            const std::uint32_t toc = 0x38 + rec * 8;
            put_le16(leaf, toc + field, value);
            seal(leaf);
            return leaf;
        };

        // Build a base valid leaf for geometry tests.
        auto build_simple_leaf = [&]() {
            std::vector<std::uint8_t> blk(kBlockSize, 0);
            put_le64(blk, 8, 300);
            put_le64(blk, 16, 3);
            put_le32(blk, 24, 0x40000003u);
            put_le32(blk, 28, 0x0000000Eu);
            blk[0x20] = 0x02; // LEAF
            blk[0x22] = 0; // level 0
            put_le32(blk, 0x24, 2);
            put_le32(blk, 0x28, 0x00100000u);
            // TOC entry 0: key {0, 8}, value {30, 30}
            put_le16(blk, 0x38, 0);
            put_le16(blk, 0x3a, 8);
            put_le16(blk, 0x3c, 30);
            put_le16(blk, 0x3e, 30);
            // TOC entry 1: key {8, 8}, value {70, 40}
            put_le16(blk, 0x40, 8);
            put_le16(blk, 0x42, 8);
            put_le16(blk, 0x44, 70);
            put_le16(blk, 0x46, 40);
            // Key base = 0x38 + 16 = 0x48
            // Key 0 at 0x48..0x50, Key 1 at 0x50..0x58
            for (int i = 0; i < 8; ++i) blk[0x48 + i] = static_cast<std::uint8_t>(i + 1);
            for (int i = 0; i < 8; ++i) blk[0x50 + i] = static_cast<std::uint8_t>(i + 9);
            // Value 0 at 4096-30=4066..4096
            std::fill(blk.begin() + 4066, blk.begin() + 4096, 0x11);
            // Value 1 at 4096-70=4026..4066
            std::fill(blk.begin() + 4026, blk.begin() + 4066, 0x22);
            seal(blk);
            return blk;
        };

        // --- FRAGMENTED LEAF TESTS (constrained capacity) ---
        {
            // Build a constrained leaf where legacy contiguous free
            // is only 6 bytes, but a 30-byte internal fragmentation
            // gap exists. Grow delta (20) > legacy free (6).
            std::vector<std::uint8_t> blk(kBlockSize, 0);
            put_le64(blk, 8, 300);
            put_le64(blk, 16, 3);
            put_le32(blk, 24, 0x40000003u);
            put_le32(blk, 28, 0x0000000Eu);
            blk[0x20] = 0x02; // LEAF
            blk[0x22] = 0;
            put_le32(blk, 0x24, 2);
            // tlen = 16 (2 entries * 8 bytes)
            put_le32(blk, 0x28, 0x00100000u);

            // We want:
            // key_region_end ≈ 3990
            // actual_values_start ≈ 3996 (value B starts here)
            // gap = 30 bytes (value B ends at 4026, value A starts at 4056)
            // value_base = 4096
            //
            // Key region: key_base=0x48, keys fill [0x48, key_end)
            // We need key_end ≈ 3990. Key 0 has key_len = 3990-72 = 3918.
            // But key 1 needs to be after key 0. Place key 1 at 3918.
            // Key 1 key_len = 8 (ends at 3990).
            //
            // Values: value A (record 0) at [4056,4096) = 40 bytes
            // value B (record 1) at [3996,4026) = 30 bytes
            // gap = [4026, 4056) = 30 bytes
            //
            // TOC: record 0 = target (value A)
            // record 1 = neighbor (value B)

            // TOC entry 0: key {0, 3910}, value {40, 40}
            put_le16(blk, 0x38, 0);         // key_off
            put_le16(blk, 0x3a, 3910);      // key_len
            put_le16(blk, 0x3c, 40);        // val_off
            put_le16(blk, 0x3e, 40);        // val_len
            // TOC entry 1: key {3910, 8}, value {100, 30}
            put_le16(blk, 0x40, 3910);      // key_off
            put_le16(blk, 0x42, 8);         // key_len
            put_le16(blk, 0x44, 100);       // val_off
            put_le16(blk, 0x46, 30);        // val_len

            // Key 0 at key_base(0x48) + 0 = [72, 3982)
            std::fill(blk.begin() + 72, blk.begin() + 3982, 0x41);
            // Key 1 at key_base + 3910 = [3982, 3990)
            std::fill(blk.begin() + 3982, blk.begin() + 3990, 0x42);
            // Value A (record 0) at 4096-40=4056..4096
            std::fill(blk.begin() + 4056, blk.begin() + 4096, 0x11);
            // Value B (record 1) at 4096-100=3996..4026
            std::fill(blk.begin() + 3996, blk.begin() + 4026, 0x22);
            // Gap at [4026, 4056) — leave as zeros
            seal(blk);

            // Parse and verify constrained geometry
            vphone::ApfsLeafGeometry fg;
            std::string ferr;
            if (!vphone::apfs_parse_leaf_geometry(blk, 0, fg, ferr)) {
                std::fprintf(stderr, "[frag2] parse failed: %s\n", ferr.c_str());
                return 1;
            }

            // Assertions: legacy_free < grow_delta
            const std::uint64_t legacy_free =
                fg.actual_values_start - fg.key_region_end;
            const std::uint64_t old_target_size = 40;
            const std::uint64_t new_target_size = 60; // grow by 20
            const std::uint64_t grow_delta =
                new_target_size - old_target_size;
            if (!(grow_delta > legacy_free)) {
                std::fprintf(stderr,
                    "[frag2] grow_delta(%llu) <= legacy_free(%llu)\n"
                    "  fixture does not prove fragmentation reclaim\n",
                    (unsigned long long)grow_delta,
                    (unsigned long long)legacy_free);
                return 1;
            }
            // Assert new_total <= available
            const std::uint64_t new_total =
                new_target_size + 30; // + neighbor 30 bytes
            const std::uint64_t available =
                fg.value_base - fg.key_region_end;
            if (new_total > available) {
                std::fprintf(stderr,
                    "[frag2] new_total(%llu) > available(%llu)\n",
                    (unsigned long long)new_total,
                    (unsigned long long)available);
                return 1;
            }

            // Perform reflow: grow target from 40 to 60
            std::vector<std::uint8_t> v_grown(60, 0x33);
            std::vector<std::uint8_t> grown_leaf;
            vphone::ApfsLeafGeometry grown_geo;
            std::string grerr;
            if (!vphone::apfs_reflow_leaf_value(
                    blk, 0, v_grown, grown_leaf, grown_geo, grerr)) {
                std::fprintf(stderr,
                    "[frag2] reflow failed: %s\n", grerr.c_str());
                return 1;
            }

            // Verify neighbor value preserved
            {
                vphone::ApfsLeafGeometry cg;
                std::string ce;
                if (!vphone::apfs_parse_leaf_geometry(grown_leaf, 0, cg, ce)) {
                    std::fprintf(stderr, "[frag2] reparse failed: %s\n", ce.c_str());
                    return 1;
                }
                std::vector<std::uint8_t> v1_check(
                    grown_leaf.begin() + cg.records[1].abs_val_start,
                    grown_leaf.begin() + cg.records[1].abs_val_end);
                std::vector<std::uint8_t> v1_expected(30, 0x22);
                if (v1_check != v1_expected) {
                    std::fprintf(stderr, "[frag2] neighbor corrupted\n");
                    return 1;
                }
            }

            std::printf("REFLOW_FRAGMENTED_CAPACITY_PASS "
                "legacy_free=%llu grow_delta=%llu fragmented_gap=30 "
                "new_total=%llu available=%llu\n",
                (unsigned long long)legacy_free,
                (unsigned long long)grow_delta,
                (unsigned long long)new_total,
                (unsigned long long)available);

            // --- FRAGMENTED SHRINK CLEAN ---
            std::vector<std::uint8_t> v_small(10, 0x44);
            std::vector<std::uint8_t> shrunk;
            vphone::ApfsLeafGeometry shrunk_geo;
            std::string srerr;
            if (!vphone::apfs_reflow_leaf_value(
                    blk, 0, v_small, shrunk, shrunk_geo, srerr)) {
                std::fprintf(stderr, "[frag2 shrink] failed: %s\n", srerr.c_str());
                return 1;
            }
            // Verify released bytes are zero
            {
                vphone::ApfsLeafGeometry sg;
                std::string se;
                if (!vphone::apfs_parse_leaf_geometry(shrunk, 0, sg, se)) {
                    std::fprintf(stderr, "[frag2 shrink] reparse failed\n");
                    return 1;
                }
                std::vector<bool> in_use(kBlockSize, false);
                for (const auto& r : sg.records) {
                    for (std::uint64_t j = r.abs_val_start;
                         j < r.abs_val_end; ++j) {
                        in_use[static_cast<std::size_t>(j)] = true;
                    }
                }
                for (std::uint64_t j = fg.actual_values_start;
                     j < sg.value_base; ++j) {
                    if (!in_use[static_cast<std::size_t>(j)] &&
                        shrunk[static_cast<std::size_t>(j)] != 0) {
                        std::fprintf(stderr,
                            "[frag2 shrink] stale byte at %llu\n",
                            (unsigned long long)j);
                        return 1;
                    }
                }
            }
            std::printf("REFLOW_FRAGMENTED_SHRINK_CLEAN_PASS\n");
        }
        // --- CROSS-RECORD KEY/VALUE COLLISION (clean) ---
        {
            // 3 records with:
            // - every own key/value pair non-overlapping
            // - all keys mutually disjoint
            // - all values mutually disjoint
            // - ONLY record 0's key overlaps record 2's value
            std::vector<std::uint8_t> blk(kBlockSize, 0);
            put_le64(blk, 8, 300);
            put_le64(blk, 16, 3);
            put_le32(blk, 24, 0x40000003u);
            put_le32(blk, 28, 0x0000000Eu);
            blk[0x20] = 0x02; // LEAF
            blk[0x22] = 0;
            put_le32(blk, 0x24, 3);
            put_le32(blk, 0x28, 0x00180000u); // tlen=24 (3*8)

            // key_base = 0x38 + 24 = 0x50 (80)
            // value_base = 4096
            //
            // Record 0: key [4030,4038) → key_off = 4030-80 = 3950, len=8
            //            value [4080,4096) → val_off = 16, len = 16
            // Record 1: key [80,88) → key_off = 0, len = 8
            //            value [4060,4070) → val_off = 36, len = 10
            // Record 2: key [88,96) → key_off = 8, len = 8
            //            value [4026,4046) → val_off = 70, len = 20
            //
            // Own-record checks:
            //   rec 0: key [4030,4038) vs val [4080,4096) → NO overlap
            //   rec 1: key [80,88) vs val [4060,4070) → NO overlap
            //   rec 2: key [88,96) vs val [4026,4046) → NO overlap
            // Cross-record:
            //   rec 0 key [4030,4038) vs rec 2 val [4026,4046) → OVERLAP!
            // Keys disjoint: [80,88), [88,96), [4030,4038) → disjoint
            // Values disjoint: [4026,4046), [4060,4070), [4080,4096) → disjoint

            // TOC entry 0
            put_le16(blk, 0x38, 3950); // key_off
            put_le16(blk, 0x3a, 8);    // key_len
            put_le16(blk, 0x3c, 16);   // val_off
            put_le16(blk, 0x3e, 16);   // val_len
            // TOC entry 1
            put_le16(blk, 0x40, 0);    // key_off
            put_le16(blk, 0x42, 8);    // key_len
            put_le16(blk, 0x44, 36);   // val_off
            put_le16(blk, 0x46, 10);   // val_len
            // TOC entry 2
            put_le16(blk, 0x48, 8);    // key_off
            put_le16(blk, 0x4a, 8);    // key_len
            put_le16(blk, 0x4c, 70);   // val_off
            put_le16(blk, 0x4e, 20);   // val_len

            // Write key bytes
            std::fill(blk.begin() + 80, blk.begin() + 88, 0x01);   // key 1
            std::fill(blk.begin() + 88, blk.begin() + 96, 0x02);   // key 2
            std::fill(blk.begin() + 4030, blk.begin() + 4038, 0x03); // key 0
            // Write value bytes
            std::fill(blk.begin() + 4080, blk.begin() + 4096, 0xAA); // val 0
            std::fill(blk.begin() + 4060, blk.begin() + 4070, 0xBB); // val 1
            std::fill(blk.begin() + 4026, blk.begin() + 4046, 0xCC); // val 2
            seal(blk);

            // Verify fixture properties before calling parser
            {
                // Own-record: no overlap
                // rec 0: key [4030,4038), val [4080,4096)
                if (4038 > 4080) { std::fprintf(stderr, "[cross] rec0 own overlap\n"); return 1; }
                // rec 1: key [80,88), val [4060,4070)
                if (88 > 4060) { std::fprintf(stderr, "[cross] rec1 own overlap\n"); return 1; }
                // rec 2: key [88,96), val [4026,4046)
                if (96 > 4026) { std::fprintf(stderr, "[cross] rec2 own overlap\n"); return 1; }
                // Cross-record: rec 0 key [4030,4038) overlaps rec 2 val [4026,4046)
                if (!(4030 < 4046 && 4026 < 4038)) {
                    std::fprintf(stderr, "[cross] no cross overlap\n");
                    return 1;
                }
            }

            vphone::ApfsLeafGeometry g;
            std::string e;
            if (vphone::apfs_parse_leaf_geometry(blk, 0, g, e)) {
                std::fprintf(stderr, "[cross] accepted\n");
                return 1;
            }
            if (e != "key/value regions overlap") {
                std::fprintf(stderr, "[cross] wrong error: %s\n", e.c_str());
                return 1;
            }
            std::printf("GEOMETRY_CROSS_RECORD_KEY_VALUE_COLLISION_REFUSED_PASS\n");
        }

        }

        // --- ROOT FOOTER COLLISION ---
        {
            // Build a root leaf with footer
            std::vector<std::uint8_t> blk(kBlockSize, 0);
            put_le64(blk, 8, 300);
            put_le64(blk, 16, 3);
            put_le32(blk, 24, 0x40000003u);
            put_le32(blk, 28, 0x0000000Eu);
            blk[0x20] = 0x03; // ROOT+LEAF
            blk[0x22] = 0;
            put_le32(blk, 0x24, 1);
            put_le32(blk, 0x28, 0x00080000u); // tlen=8
            put_le16(blk, 0x38, 0); // key_off
            put_le16(blk, 0x3a, 8); // key_len
            put_le16(blk, 0x3c, 0); // val_off
            put_le16(blk, 0x3e, 100); // val_len
            for (int i = 0; i < 8; ++i) blk[0x40 + i] = static_cast<std::uint8_t>(i + 1);
            // Root footer at 4096-40=4056, value_base=4056
            // Value at 4056-0-100 = 3956..4056 — valid
            // But now make val_len=200 to cross value_base into footer
            put_le16(blk, 0x3e, 200); // val_len=200 crosses value_base
            put_le32(blk, 4056 + 4, kBlockSize); // footer node_size
            seal(blk);

            vphone::ApfsLeafGeometry g;
            std::string e;
            if (vphone::apfs_parse_leaf_geometry(blk, 0, g, e)) {
                std::fprintf(stderr, "[footer collision] accepted\n");
                return 1;
            }
            // Should fail: value span crosses value_base
            if (e != "value span crosses value_base") {
                std::fprintf(stderr, "[footer collision] wrong error: %s\n", e.c_str());
                return 1;
            }
            std::printf("GEOMETRY_FOOTER_COLLISION_REFUSED_PASS\n");
        }

        // --- POST-WRITE CERT FAILURE TEST ---
        {
            const std::string pw_src =
                dir + "apfs_mut_pw_src.img";
            const std::string pw_out =
                dir + "apfs_mut_pw_out.img";
            if (!write_all(pw_src, base)) {
                std::fprintf(stderr, "pw src write failed\n");
                return 1;
            }

            std::string pw_sha;
            {
                vphone::ApfsReaderReport rpt;
                std::string rerr;
                if (!vphone::apfs_read_container(pw_src, rpt, rerr)) {
                    std::fprintf(stderr, "pw reader: %s\n", rerr.c_str());
                    return 1;
                }
                pw_sha = sha256_hex(rpt.plist_file.bytes);
            }

            // Hook: corrupt the output after the write.
            auto corrupt = [](const std::string& path) {
                std::vector<std::uint8_t> blk(kBlockSize, 0);
                std::ifstream tf(path, std::ios::binary);
                if (!tf.good()) { std::fprintf(stderr, "pw hook: open failed\n"); std::exit(1); }
                tf.seekg(0); // corrupt block 0 (NXSB)
                tf.read(reinterpret_cast<char*>(blk.data()), kBlockSize);
                if (!tf.good()) { std::fprintf(stderr, "pw hook: read failed\n"); std::exit(1); }
                tf.close();
                // Corrupt the NXSB checksum
                put_le64(blk, 0, 0xDEADBEEF);
                std::ofstream to(path, std::ios::binary | std::ios::in | std::ios::out);
                if (!to.good()) { std::fprintf(stderr, "pw hook: write open failed\n"); std::exit(1); }
                to.seekp(0);
                to.write(reinterpret_cast<const char*>(blk.data()), kBlockSize);
                if (!to.good()) { std::fprintf(stderr, "pw hook: write failed\n"); std::exit(1); }
                to.flush();
                if (!to.good()) { std::fprintf(stderr, "pw hook: flush failed\n"); std::exit(1); }
                to.close();
            };

            DeleteFileA(pw_out.c_str());
            std::vector<std::uint8_t> payload(12, 'Z');
            vphone::ApfsMutationResult r;
            std::string err;
            const bool ok =
                vphone::apfs_resize_plist_payload_safe_with_post_write_hook(
                    pw_src, pw_out, pw_sha, kFileCnid,
                    payload, corrupt, r, err);
            if (ok) {
                std::fprintf(stderr, "[pw] expected failure\n");
                return 1;
            }

            // Verify output file was DELETED
            const DWORD attr = GetFileAttributesA(pw_out.c_str());
            if (attr != INVALID_FILE_ATTRIBUTES) {
                std::fprintf(stderr, "[pw] output still exists\n");
                return 1;
            }

            // Verify source unchanged
            {
                std::vector<std::uint8_t> after;
                if (!read_all(pw_src, after) || after != base) {
                    std::fprintf(stderr, "[pw] source modified\n");
                    return 1;
                }
            }
            std::printf("POSTWRITE_CERT_FAILURE_OUTPUT_REMOVED_PASS\n");
            std::printf("POSTWRITE_CERT_FAILURE_SOURCE_UNCHANGED_PASS\n");

            DeleteFileA(pw_src.c_str());
            if (GetFileAttributesA(pw_out.c_str()) == INVALID_FILE_ATTRIBUTES) {
                // already deleted by the API
            } else {
                DeleteFileA(pw_out.c_str());
            }
        }


    DeleteFileA(source.c_str());
    DeleteFileA(output.c_str());
    DeleteFileA(variant.c_str());
    DeleteFileA(variant_out.c_str());

    std::printf("APFS_MUTATOR_TEST_PASS\n");
    return 0;
}
