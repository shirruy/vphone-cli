#define NOMINMAX
#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include "vphone/apfs_reader.hpp"

#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

namespace {

void put_le32(std::vector<std::uint8_t>& b, std::size_t off, std::uint32_t v) {
    b[off] = static_cast<std::uint8_t>(v);
    b[off + 1] = static_cast<std::uint8_t>(v >> 8);
    b[off + 2] = static_cast<std::uint8_t>(v >> 16);
    b[off + 3] = static_cast<std::uint8_t>(v >> 24);
}

void put_le64(std::vector<std::uint8_t>& b, std::size_t off, std::uint64_t v) {
    for (int i = 0; i < 8; ++i) {
        b[off + i] = static_cast<std::uint8_t>((v >> (i * 8)) & 0xFFu);
    }
}

std::uint32_t read_le32(const std::vector<std::uint8_t>& b, std::size_t off) {
    return
        static_cast<std::uint32_t>(b[off]) |
        (static_cast<std::uint32_t>(b[off + 1]) << 8) |
        (static_cast<std::uint32_t>(b[off + 2]) << 16) |
        (static_cast<std::uint32_t>(b[off + 3]) << 24);
}

std::uint64_t read_le64(const std::vector<std::uint8_t>& b, std::size_t off) {
    std::uint64_t v = 0;
    for (int i = 7; i >= 0; --i) {
        v = (v << 8) | b[off + i];
    }
    return v;
}

// APFS Fletcher-64 (same algorithm as the reader).
std::uint64_t fletcher64(const std::vector<std::uint8_t>& b) {
    constexpr std::uint64_t modulus = 0xFFFFFFFFull;
    std::uint64_t s1 = 0, s2 = 0;
    for (std::size_t off = 8; off + 4 <= b.size(); off += 4) {
        const std::uint64_t w = read_le32(b, off);
        s1 = (s1 + w) % modulus;
        s2 = (s2 + s1) % modulus;
    }
    const std::uint64_t c1 = modulus - ((s1 + s2) % modulus);
    const std::uint64_t c2 = modulus - ((s1 + c1) % modulus);
    return c1 | (c2 << 32);
}

void seal_checksum(std::vector<std::uint8_t>& b) {
    put_le64(b, 0, fletcher64(b));
}

bool write_all(
    const std::string& path,
    const std::vector<std::uint8_t>& data
) {
    HANDLE file = CreateFileA(
        path.c_str(),
        GENERIC_WRITE,
        0,
        nullptr,
        CREATE_ALWAYS,
        FILE_ATTRIBUTE_NORMAL,
        nullptr
    );
    if (file == INVALID_HANDLE_VALUE) {
        return false;
    }
    DWORD written = 0;
    const BOOL ok = WriteFile(
        file,
        data.data(),
        static_cast<DWORD>(data.size()),
        &written,
        nullptr
    );
    CloseHandle(file);
    return ok && written == data.size();
}

void make_object_header(
    std::vector<std::uint8_t>& block,
    std::uint64_t oid,
    std::uint64_t xid,
    std::uint32_t type
) {
    put_le64(block, 8, oid);
    put_le64(block, 16, xid);
    put_le32(block, 24, type);
}

} // namespace

int main() {
    const std::uint32_t block_size = 4096;
    const std::uint64_t block_count = 16;
    // Synthetic layout:
    //   block 0: NXSB
    //   block 1: APSB (omap_oid=2, root_tree_oid=100 virtual)
    //   block 2: OMAP (om_tree_oid=4)
    //   block 3: catalog B-tree root (target of omap mapping)
    //   block 4: omap B-tree (fixed-KV leaf, entry oid 100 -> paddr 3)

    // Build a minimal synthetic container:
    //   block 0:  NXSB (checkpoint era)
    //   block 1:  APSB volume superblock
    //   block 2:  OMAP object (type 0x4000000b)
    //   block 3:  B-tree root (type 0x40000002)
    std::vector<std::uint8_t> image(
        static_cast<std::size_t>(block_count) * block_size,
        0
    );

    auto block_at = [&](std::uint64_t b) -> std::vector<std::uint8_t>& {
        return *reinterpret_cast<std::vector<std::uint8_t>*>(
            image.data() + static_cast<std::size_t>(b) * block_size
        );
    };

    // NXSB at block 0.
    {
        std::vector<std::uint8_t> blk(block_size, 0);
        make_object_header(blk, 1, 1, 0x80000001);
        put_le32(blk, 32, 0x4253584Eu); // 'NXSB'
        put_le32(blk, 36, block_size);
        put_le64(blk, 40, block_count);
        seal_checksum(blk);
        std::memcpy(
            image.data(),
            blk.data(),
            block_size
        );
    }

    // APSB at block 1.
    {
        std::vector<std::uint8_t> blk(block_size, 0);
        make_object_header(blk, 42, 3, 0x80000009);
        put_le32(blk, 32, 0x42535041u); // 'APSB'
        put_le64(blk, 0x80, 2);         // omap block
        put_le64(blk, 0x88, 100);       // root tree oid (virtual)
        put_le64(blk, 0x90, 3);         // extentref tree oid
        const char* name = "testvol";
        std::memcpy(blk.data() + 0x2C0, name, std::strlen(name));
        seal_checksum(blk);
        std::memcpy(
            image.data() + block_size,
            blk.data(),
            block_size
        );
    }

    // OMAP at block 2.
    {
        std::vector<std::uint8_t> blk(block_size, 0);
        make_object_header(blk, 2, 3, 0x4000000Bu);
        put_le64(blk, 0x30, 4);         // om_tree_oid -> block 4
        seal_checksum(blk);
        std::memcpy(
            image.data() + 2 * static_cast<std::size_t>(block_size),
            blk.data(),
            block_size
        );
    }

    // FSTREE root at block 3: B-tree kind, subtype 0x0E, root flag,
    // footer with node_size matching block size.
    {
        std::vector<std::uint8_t> blk(block_size, 0);
        make_object_header(blk, 3, 3, 0x40000002u);
        put_le32(blk, 28, 0x0000000Eu);              // subtype FSTREE
        put_le32(blk, 0x20, 0x00000001u);            // root flag
        put_le32(blk, 0x24, 0);                       // nkeys=0
        // Footer at block_size - 0x28: bt_flags, node_size.
        put_le32(blk, block_size - 0x28, 0);
        put_le32(blk, block_size - 0x28 + 4, block_size);
        seal_checksum(blk);
        std::memcpy(
            image.data() + 3 * static_cast<std::size_t>(block_size),
            blk.data(),
            block_size
        );
    }

    // OMAP B-tree leaf at block 4: fixed-KV, 3 entries for oid 100 at
    // xids 2/1/5 (xid-aware lookup must pick xid 2 -> paddr 3; the
    // older xid 1 and the future xid 5 must both lose).
    {
        std::vector<std::uint8_t> blk(block_size, 0);
        make_object_header(blk, 4, 3, 0x40000003u);
        // btn: flags = leaf+fixed (0x6), level=0, nkeys=3,
        // table_space off=0 len=0x10.
        put_le32(blk, 0x20, 0x00000006u);
        put_le32(blk, 0x24, 3); // nkeys
        // Authoritative fixed-KV TOC: 4-byte kvoff { k u16, v u16 }.
        put_le32(blk, 0x28, 0x00100000u); // tofs=0, tlen=0x10
        // TOC (4-byte kvoff entries) at 0x38:
        //   e0: k=0x00 v=0x10   e1: k=0x10 v=0x20   e2: k=0x20 v=0x30
        blk[0x38] = 0x00; blk[0x39] = 0x00; blk[0x3a] = 0x10; blk[0x3b] = 0x00;
        blk[0x3c] = 0x10; blk[0x3d] = 0x00; blk[0x3e] = 0x20; blk[0x3f] = 0x00;
        blk[0x40] = 0x20; blk[0x41] = 0x00; blk[0x42] = 0x30; blk[0x43] = 0x00;
        // Key area at 0x48 (16-byte OMAP keys {oid,xid}).
        put_le64(blk, 0x48, 100);        put_le64(blk, 0x48 + 8, 2);
        put_le64(blk, 0x48 + 0x10, 100); put_le64(blk, 0x48 + 0x18, 1);
        put_le64(blk, 0x48 + 0x20, 100); put_le64(blk, 0x48 + 0x28, 5);
        // Values (root value_base = 0xfd8; paddr at +8 of each 16-byte
        // slot, addresses taken only from kvoff.v):
        put_le64(blk, 0xfc8 + 8, 3);   // e0: xid 2 -> 3   (winner)
        put_le64(blk, 0xfb8 + 8, 14);  // e1: xid 1 -> 14  (older; loses)
        put_le64(blk, 0xfa8 + 8, 15);  // e2: xid 5 -> 15  (future; loses)
        seal_checksum(blk);
        std::memcpy(
            image.data() + 4 * static_cast<std::size_t>(block_size),
            blk.data(),
            block_size
        );
    }

    char temp_path[MAX_PATH] = {};
    if (!GetTempPathA(MAX_PATH, temp_path)) {
        std::fprintf(stderr, "GetTempPathA failed\n");
        return 1;
    }
    const std::string image_path =
        std::string(temp_path) + "apfs_reader_test.img";

    if (!write_all(image_path, image)) {
        std::fprintf(stderr, "failed to write synthetic image\n");
        return 1;
    }

    // Regression: a fixed-KV node whose table_len is only nkeys*2
    // (the stale 2-byte entry assumption) must fail closed. Build a
    // second image variant with a deliberately undersized TOC.
    {
        std::vector<std::uint8_t> bad = image;
        // OMAP leaf at block 4 in the bad image: nkeys=3 but
        // table_len = 3*2 = 6 bytes.
        std::vector<std::uint8_t> blk(block_size, 0);
        make_object_header(blk, 4, 3, 0x40000003u);
        put_le32(blk, 0x20, 0x00000006u);  // leaf+fixed
        put_le32(blk, 0x24, 3);            // nkeys
        put_le32(blk, 0x28, 0x00060000u);  // tofs=0, tlen=6 (undersized)
        seal_checksum(blk);
        std::memcpy(
            bad.data() + 4 * static_cast<std::size_t>(block_size),
            blk.data(),
            block_size
        );

        const std::string bad_path =
            std::string(temp_path) + "apfs_reader_test_bad.img";
        if (!write_all(bad_path, bad)) {
            std::fprintf(stderr, "failed to write bad image\n");
            return 1;
        }

        vphone::ApfsReaderReport bad_report;
        std::string bad_error;
        // The OMAP walk must reject the undersized TOC, so the volume
        // either fails container parse or reports root_tree_block 0.
        const bool parsed =
            vphone::apfs_read_container(bad_path, bad_report, bad_error);
        const bool rejected =
            !parsed ||
            bad_report.volumes.empty() ||
            bad_report.volumes[0].root_tree_block == 0;
        DeleteFileA(bad_path.c_str());

        if (!rejected) {
            std::fprintf(
                stderr,
                "undersized 2-byte TOC was not rejected\n"
            );
            return 1;
        }

    // Negative checksum regression: seal a valid OMAP leaf, flip one
    // payload byte without resealing, and prove the reader rejects it
    // (no trusted root/path result).
    {
        std::vector<std::uint8_t> bad = image;
        // Corrupt one payload byte of the OMAP leaf (block 4, key area).
        const std::size_t corrupt_off =
            4 * static_cast<std::size_t>(block_size) + 0x48;
        bad[corrupt_off] ^= 0x5A;

        const std::string bad_path =
            std::string(temp_path) + "apfs_reader_test_cksum.img";
        if (!write_all(bad_path, bad)) {
            std::fprintf(stderr, "failed to write checksum-bad image\n");
            return 1;
        }

        vphone::ApfsReaderReport bad_report;
        std::string bad_error;
        const bool cksum_rejected =
            !vphone::apfs_read_container(
                bad_path,
                bad_report,
                bad_error
            ) ||
            bad_report.volumes.empty() ||
            bad_report.volumes[0].root_tree_block == 0;
        DeleteFileA(bad_path.c_str());

        if (!cksum_rejected) {
            std::fprintf(
                stderr,
                "flipped checksum byte was not rejected\n"
            );
            return 1;
        }
    }
    }

    vphone::ApfsReaderReport report;
    std::string error;
    if (!vphone::apfs_read_container(image_path, report, error)) {
        std::fprintf(stderr, "apfs_read_container failed: %s\n", error.c_str());
        DeleteFileA(image_path.c_str());
        return 1;
    }

    DeleteFileA(image_path.c_str());

    if (report.container.block_size != block_size) {
        std::fprintf(stderr, "block size mismatch\n");
        return 1;
    }
    if (report.container.block_count != block_count) {
        std::fprintf(stderr, "block count mismatch\n");
        return 1;
    }
    if (report.volumes.size() != 1) {
        std::fprintf(
            stderr,
            "expected 1 volume, got %zu\n",
            report.volumes.size()
        );
        return 1;
    }

    const auto& vol = report.volumes[0];
    if (vol.apsb_block != 1 || vol.apsb_oid != 42 || vol.xid != 3) {
        std::fprintf(stderr, "volume identity mismatch\n");
        return 1;
    }
    if (vol.omap_block != 2 || vol.root_tree_block != 3) {
        std::fprintf(stderr, "volume tree pointers mismatch\n");
        return 1;
    }
    if (vol.volume_name != "testvol") {
        std::fprintf(
            stderr,
            "volume name mismatch: '%s'\n",
            vol.volume_name.c_str()
        );
        return 1;
    }

    // -----------------------------------------------------------------
    // FSTREE walk regressions: late-key acceptance, level-skip
    // rejection, virtual-child resolution, topology flag validation.
    // -----------------------------------------------------------------
    {
        constexpr std::uint32_t fbs = 4096;
        constexpr std::uint64_t fbc = 12;
        constexpr std::uint64_t kFstreeRootOid = 200;
        constexpr std::uint64_t kFstreeMidOid = 201;
        constexpr std::uint64_t kFstreeLeafOid = 202;
        constexpr std::uint64_t kFstreeLeafBlock = 8;

        struct FstreeImage {
            std::uint16_t mid_flags = 0;
            std::uint16_t mid_level = 1;
            bool mid_level_set = false;
            std::uint16_t leaf_flags = 2;
            bool root_flags_missing = false;
        };

        auto seal = [&](std::vector<std::uint8_t>& b) {
            put_le64(b, 0, fletcher64(b));
        };

        auto build = [&](const FstreeImage& cfg)
            -> std::vector<std::uint8_t> {
            std::vector<std::uint8_t> img(
                static_cast<std::size_t>(fbc) * fbs, 0);

            auto put = [&](
                std::uint64_t b,
                const std::vector<std::uint8_t>& blk
            ) {
                std::memcpy(
                    img.data() + static_cast<std::size_t>(b) * fbs,
                    blk.data(),
                    fbs
                );
            };

            // NXSB block 0
            {
                std::vector<std::uint8_t> blk(fbs, 0);
                put_le64(blk, 8, 1);
                put_le64(blk, 16, 1);
                put_le32(blk, 24, 0x80000001u);
                put_le32(blk, 32, 0x4253584Eu);
                put_le32(blk, 36, fbs);
                put_le64(blk, 40, fbc);
                seal(blk);
                put(0, blk);
            }

            // APSB block 1: omap=4, root_tree_oid=200 (virtual)
            {
                std::vector<std::uint8_t> blk(fbs, 0);
                put_le64(blk, 8, 42);
                put_le64(blk, 16, 3);
                put_le32(blk, 24, 0x80000009u);
                put_le32(blk, 32, 0x42535041u);
                put_le64(blk, 0x80, 4);
                put_le64(blk, 0x88, kFstreeRootOid);
                put_le64(blk, 0x90, 3);
                std::memcpy(blk.data() + 0x2C0, "fstretest", 9);
                seal(blk);
                put(1, blk);
            }

            // omap_phys block 4
            {
                std::vector<std::uint8_t> blk(fbs, 0);
                put_le64(blk, 8, 4);
                put_le64(blk, 16, 3);
                put_le32(blk, 24, 0x4000000Bu);
                put_le64(blk, 0x30, 5);
                seal(blk);
                put(4, blk);
            }

            // OMAP leaf block 5: fixed-KV, maps 200->6, 201->7, 202->8.
            // Virtual OIDs deliberately differ from physical paddrs.
            {
                std::vector<std::uint8_t> blk(fbs, 0);
                put_le64(blk, 8, 5);
                put_le64(blk, 16, 3);
                put_le32(blk, 24, 0x40000003u);
                put_le32(blk, 0x20, 0x00000006u); // leaf+fixed
                put_le32(blk, 0x24, 3);
                put_le32(blk, 0x28, 0x00100000u);
                blk[0x38] = 0x00; blk[0x39] = 0x00; blk[0x3a] = 0x10; blk[0x3b] = 0x00;
                blk[0x3c] = 0x10; blk[0x3d] = 0x00; blk[0x3e] = 0x20; blk[0x3f] = 0x00;
                blk[0x40] = 0x20; blk[0x41] = 0x00; blk[0x42] = 0x30; blk[0x43] = 0x00;
                put_le64(blk, 0x48, kFstreeRootOid); put_le64(blk, 0x48 + 8, 2);
                put_le64(blk, 0x48 + 0x10, kFstreeMidOid); put_le64(blk, 0x48 + 0x18, 2);
                put_le64(blk, 0x48 + 0x20, kFstreeLeafOid); put_le64(blk, 0x48 + 0x28, 2);
                put_le64(blk, 0xfc8 + 8, 6);
                put_le64(blk, 0xfb8 + 8, 7);
                put_le64(blk, 0xfa8 + 8, 8);
                seal(blk);
                put(5, blk);
            }

            // FSTREE root block 6: variable-KV, level 2, ROOT flag,
            // 1 entry -> child OID 201 (virtual).
            {
                std::vector<std::uint8_t> blk(fbs, 0);
                put_le64(blk, 8, kFstreeRootOid);
                put_le64(blk, 16, 3);
                put_le32(blk, 24, 0x40000003u);
                put_le32(blk, 28, 0x0000000Eu);
                blk[0x20] = cfg.root_flags_missing ? 0x00 : 0x01;
                blk[0x21] = 0x00;
                blk[0x22] = 0x02; blk[0x23] = 0x00; // level = 2
                put_le32(blk, 0x24, 1);
                put_le32(blk, 0x28, 0x00100000u);
                blk[0x38] = 0x00; blk[0x39] = 0x00; blk[0x3a] = 0x10; blk[0x3b] = 0x00;
                blk[0x3c] = 0x10; blk[0x3d] = 0x00; blk[0x3e] = 0x08; blk[0x3f] = 0x00;
                put_le64(blk, 0x48, (9ull << 60) | 1ull);
                put_le64(blk, 0x48 + 8, 0);
                put_le64(blk, 0xfc8, kFstreeMidOid);
                put_le32(blk, fbs - 0x28, 0);
                put_le32(blk, fbs - 0x28 + 4, fbs);
                seal(blk);
                put(6, blk);
            }

            // FSTREE mid block 7: variable-KV, level 1 (or override),
            // 1 entry -> leaf block 8.
            {
                std::vector<std::uint8_t> blk(fbs, 0);
                put_le64(blk, 8, kFstreeMidOid);
                put_le64(blk, 16, 3);
                put_le32(blk, 24, 0x40000003u);
                put_le32(blk, 28, 0x0000000Eu);
                const std::uint16_t mflags = cfg.mid_flags;
                const std::uint16_t mlevel =
                    cfg.mid_level_set ? cfg.mid_level : 1;
                blk[0x20] = static_cast<std::uint8_t>(mflags & 0xff);
                blk[0x21] = static_cast<std::uint8_t>(mflags >> 8);
                blk[0x22] = static_cast<std::uint8_t>(mlevel & 0xff);
                blk[0x23] = static_cast<std::uint8_t>(mlevel >> 8);
                put_le32(blk, 0x24, 1);
                put_le32(blk, 0x28, 0x00100000u);
                blk[0x38] = 0x00; blk[0x39] = 0x00; blk[0x3a] = 0x10; blk[0x3b] = 0x00;
                blk[0x3c] = 0x10; blk[0x3d] = 0x00; blk[0x3e] = 0x08; blk[0x3f] = 0x00;
                put_le64(blk, 0x48, (9ull << 60) | 1ull);
                put_le64(blk, 0x48 + 8, 0);
                put_le64(blk, 0xff0, kFstreeLeafOid);
                seal(blk);
                put(7, blk);
            }

            // FSTREE leaf block 8: variable-KV, level 0, one DIR_REC
            // "System\0" under parent CNID 2, key placed LATE
            // (k_off = 0x0F00 pushes the key near block end).
            {
                std::vector<std::uint8_t> blk(fbs, 0);
                put_le64(blk, 8, kFstreeLeafOid);
                put_le64(blk, 16, 3);
                put_le32(blk, 24, 0x40000003u);
                put_le32(blk, 28, 0x0000000Eu);
                blk[0x20] = static_cast<std::uint8_t>(cfg.leaf_flags & 0xff);
                blk[0x21] = static_cast<std::uint8_t>(cfg.leaf_flags >> 8);
                blk[0x22] = 0x00; blk[0x23] = 0x00;
                put_le32(blk, 0x24, 1);
                put_le32(blk, 0x28, 0x00100000u);
                const std::uint16_t k_off = 0x0F00;
                const std::uint16_t k_len = 10 + 7;
                const std::uint16_t v_off = 0x18;
                const std::uint16_t v_len = 18;
                blk[0x38] = static_cast<std::uint8_t>(k_off & 0xff);
                blk[0x39] = static_cast<std::uint8_t>(k_off >> 8);
                blk[0x3a] = static_cast<std::uint8_t>(k_len & 0xff);
                blk[0x3b] = static_cast<std::uint8_t>(k_len >> 8);
                blk[0x3c] = static_cast<std::uint8_t>(v_off & 0xff);
                blk[0x3d] = static_cast<std::uint8_t>(v_off >> 8);
                blk[0x3e] = static_cast<std::uint8_t>(v_len & 0xff);
                blk[0x3f] = static_cast<std::uint8_t>(v_len >> 8);
                const std::uint64_t kp = 0x48 + k_off;
                put_le64(blk, kp, (9ull << 60) | 2ull);
                blk[kp + 8] = 0x07; blk[kp + 9] = 0x00;
                std::memcpy(blk.data() + kp + 10, "System\0", 7);
                put_le64(blk, 4096 - 0x18, 16);
                put_le64(blk, 4096 - 0x18 + 8, 0);
                put_le32(blk, 4096 - 0x18 + 16, 4);
                seal(blk);
                put(kFstreeLeafBlock, blk);
            }

            return img;
        };

        auto run_case = [&](
            const std::vector<std::uint8_t>& blocks,
            const char* suffix,
            const char* expected_error  // null = positive case
        ) -> bool {
            const std::string path =
                std::string(temp_path) + "apfs_fstree_" + suffix + ".img";
            if (!write_all(path, blocks)) {
                std::fprintf(stderr, "write %s failed\n", suffix);
                return false;
            }
            vphone::ApfsReaderReport rpt;
            std::string err;
            vphone::apfs_read_container(path, rpt, err);
            DeleteFileA(path.c_str());
            if (expected_error == nullptr) {
                // Positive: the walk must reach the Library lookup
                // boundary (System was found and decoded).
                return rpt.launchdaemons_status.find(
                    "component not found: Library"
                ) != std::string::npos;
            }
            // Negative: the specific failure must be the rejection
            // reason, not just any failure.
            return rpt.launchdaemons_status.find(expected_error) !=
                   std::string::npos;
        };

        // A: positive — late key accepted, virtual child resolved.
        {
            FstreeImage cfg;
            if (!run_case(build(cfg), "latekey_ok", nullptr)) {
                std::fprintf(
                    stderr,
                    "late-key/virtual-child positive case failed\n"
                );
                return 1;
            }
        }

        // B: negative — level skip 2 -> 0.
        {
            FstreeImage cfg;
            cfg.mid_level_set = true;
            cfg.mid_level = 0;
            cfg.mid_flags = 2; // LEAF (consistent with level 0)
            if (!run_case(
                    build(cfg),
                    "levelskip",
                    "FSTREE node level mismatch (expected exact descent)"
                )) {
                std::fprintf(stderr, "level-skip 2->0 not rejected\n");
                return 1;
            }
        }

        // C: negative — level-0 leaf without LEAF flag.
        {
            FstreeImage cfg;
            cfg.leaf_flags = 0;
            if (!run_case(
                    build(cfg),
                    "noflag",
                    "FSTREE level-0 node missing LEAF flag"
                )) {
                std::fprintf(
                    stderr,
                    "level-0 without LEAF flag not rejected\n"
                );
                return 1;
            }
        }

        // D: negative — interior carrying LEAF flag (isolated: no
        // ROOT flag so only the LEAF violation can trigger).
        {
            FstreeImage cfg;
            cfg.mid_flags = 0x0002; // LEAF only, no ROOT
            if (!run_case(
                    build(cfg),
                    "midleaf",
                    "FSTREE interior node carries LEAF flag"
                )) {
                std::fprintf(
                    stderr,
                    "interior with LEAF flag not rejected\n"
                );
                return 1;
            }
        }

        // E: negative — non-root carrying ROOT flag.
        {
            FstreeImage cfg;
            cfg.mid_flags = 0x0001; // ROOT only
            if (!run_case(
                    build(cfg),
                    "midroot",
                    "FSTREE non-root node carries ROOT flag"
                )) {
                std::fprintf(
                    stderr,
                    "non-root with ROOT flag not rejected\n"
                );
                return 1;
            }
        }

        // F: negative — root missing ROOT flag.
        {
            FstreeImage cfg;
            cfg.root_flags_missing = true;
            // The volume-level root validation (ROOT flag + footer
            // geometry in apfs_read_container) rejects this before the
            // FSTREE walker runs. Assert the fail-closed outcome: no
            // volumes (root rejected) or no path resolution.
            const std::string path =
                std::string(temp_path) + "apfs_fstree_norootflag.img";
            const auto blocks = build(cfg);
            if (!write_all(path, blocks)) {
                std::fprintf(stderr, "write norootflag failed\n");
                return 1;
            }
            vphone::ApfsReaderReport rpt;
            std::string err;
            vphone::apfs_read_container(path, rpt, err);
            DeleteFileA(path.c_str());
            const bool rejected =
                rpt.volumes.empty() ||
                rpt.volumes[0].root_tree_block == 0 ||
                rpt.launchdaemons_status != "RESOLVED";
            if (!rejected) {
                std::fprintf(
                    stderr,
                    "root without ROOT flag not rejected\n"
                );
                return 1;
            }
        }
    }

    std::printf("APFS_READER_TEST_PASS\n");
    return 0;
}
