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

    // -----------------------------------------------------------------
    // Read-path regression matrix: inode/xfield, XATTR/decmpfs,
    // FILE_EXTENT malformations with exact error assertions.
    // -----------------------------------------------------------------
    {
        constexpr std::uint32_t rbs = 4096;
        constexpr std::uint64_t rbc = 16;
        constexpr std::uint64_t kRootOid = 300;
        constexpr std::uint64_t kMidOid = 301;
        constexpr std::uint64_t kLeafOid = 302;
        constexpr std::uint64_t kFileCnid = 50;

        // Mutation selector.
        enum class Mut {
            None,                    // positive baseline
            InodeShortBase,          // value_len < 0x5c
            InodeBaseOnly,           // value_len == 0x5c (valid)
            InodePartialXfHeader,    // value_len 0x5d
            InodeXfMetaOverflow,     // metadata array exceeds value
            InodeXfValOverflow,      // padded value exceeds value
            InodeBadUsedData,        // consumed != xf_used_data
            InodeShortDstream,       // DSTREAM x_size < 40
            InodeTrailingBytes,      // collection-size mismatch
            XattrBadSignature,       // signature != 0x636D7066
            XattrBadMarker,          // xdata[16] != 0xCC
            XattrSizeMismatch,       // logical_size != xdata_len - 17
            XattrBadXdataLen,        // xdata_len != value_len - 4
            XattrDataStreamOnly,     // flags = 0x1 only
            XattrAmbiguous,          // flags = 0x3
            ExtentBadKeyLen,         // key_extra_len != 8
            ExtentLeadingGap,        // first extent at logical > 0
            ExtentMiddleGap,         // gap between extents
            ExtentHoleAccepted,      // phys==0 hole (positive)
            ExtentPhysOverrun,       // blocks_needed > remaining
            ExtentLogicalOverflow    // logical + length overflows u64
        };

        struct ReadPathImage {
            Mut mut = Mut::None;
        };

        auto put_le16_safe = [](
            std::vector<std::uint8_t>& b,
            std::size_t off,
            std::uint16_t v
        ) {
            b[off] = static_cast<std::uint8_t>(v & 0xff);
            b[off + 1] = static_cast<std::uint8_t>(v >> 8);
        };

        auto build_read_path_image = [&](
            const ReadPathImage& cfg
        ) -> std::vector<std::uint8_t> {
            std::vector<std::uint8_t> img(
                static_cast<std::size_t>(rbc) * rbs, 0
            );

            auto put = [&](
                std::uint64_t b,
                const std::vector<std::uint8_t>& blk
            ) {
                std::memcpy(
                    img.data() + static_cast<std::size_t>(b) * rbs,
                    blk.data(),
                    rbs
                );
            };

            auto rseal = [&](std::vector<std::uint8_t>& b) {
                put_le64(b, 0, fletcher64(b));
            };

            // Build a variable-KV FSTREE leaf with configurable records.
            // We pack multiple records into a single leaf block.
            auto build_leaf = [&](
            ) -> std::vector<std::uint8_t> {
                std::vector<std::uint8_t> blk(rbs, 0);
                put_le64(blk, 8, kLeafOid);
                put_le64(blk, 16, 3);
                put_le32(blk, 24, 0x40000003u);
                put_le32(blk, 28, 0x0000000Eu);
                blk[0x20] = 0x02; // LEAF
                blk[0x22] = 0x00; // level 0

                // We'll build records: 3 DIR_REC (path components),
                // 1 DIR_REC (plist), 1 INODE, 1+ FILE_EXTENT.

                // TOC starts at 0x38; key_base after all TOC entries.
                // We'll use up to 4 entries.
                // Each TOC entry is 8 bytes (variable-KV).
                std::uint16_t nkeys = 0;
                std::uint16_t tofs = 0;
                std::uint16_t tlen = 8 * 8; // max 8 entries

                // Key area starts at 0x38 + tlen = 0x58.
                // Value area: block_size (non-root).
                const std::uint64_t kb = 0x38 + tlen;
                const std::uint64_t vb = rbs;

                // Build key/value data at specific offsets from kb/vb.
                std::uint16_t cur_key_off = 0;
                std::uint64_t cur_val_end = vb;

                auto add_rec = [&](
                    std::uint64_t hdr,
                    const std::vector<std::uint8_t>& key_extra,
                    std::uint16_t val_len,
                    const std::vector<std::uint8_t>& val_data,
                    std::uint16_t forced_key_extra_len = 0
                ) -> void {
                    if (nkeys >= 8) return;
                    const std::uint16_t k_len =
                        8 + static_cast<std::uint16_t>(key_extra.size());
                    // Write TOC entry.
                    const std::uint64_t toc =
                        0x38 + tofs +
                        static_cast<std::uint64_t>(nkeys) * 8;
                    blk[toc] = static_cast<std::uint8_t>(
                        cur_key_off & 0xff);
                    blk[toc + 1] = static_cast<std::uint8_t>(
                        cur_key_off >> 8);
                    blk[toc + 2] = static_cast<std::uint8_t>(
                        k_len & 0xff);
                    blk[toc + 3] = static_cast<std::uint8_t>(
                        k_len >> 8);
                    // Value offset from vb downward.
                    const std::uint16_t v_off =
                        static_cast<std::uint16_t>(
                            vb - (cur_val_end - val_len));
                    blk[toc + 4] = static_cast<std::uint8_t>(
                        v_off & 0xff);
                    blk[toc + 5] = static_cast<std::uint8_t>(
                        v_off >> 8);
                    blk[toc + 6] = static_cast<std::uint8_t>(
                        val_len & 0xff);
                    blk[toc + 7] = static_cast<std::uint8_t>(
                        val_len >> 8);

                    // Write key at kb + cur_key_off.
                    const std::uint64_t kp = kb + cur_key_off;
                    put_le64(blk, kp, hdr);
                    if (!key_extra.empty()) {
                        std::memcpy(
                            blk.data() + kp + 8,
                            key_extra.data(),
                            key_extra.size()
                        );
                    }

                    // Write value at vb - v_off.
                    const std::uint64_t vp = vb - v_off;
                    if (!val_data.empty()) {
                        std::memcpy(
                            blk.data() + vp,
                            val_data.data(),
                            std::min<std::size_t>(
                                val_data.size(), val_len)
                        );
                    }

                    cur_key_off += k_len;
                    cur_val_end -= val_len;
                    nkeys++;

                    (void)forced_key_extra_len;
                };

                // Record 1: DIR_REC "test.plist" under parent 2.
                // First add the path components System→Library→LaunchDaemons.
                {
                    // CNID 3 = System, CNID 4 = Library, CNID 5 = LaunchDaemons
                    const char* names[] = {"System", "Library", "LaunchDaemons"};
                    const std::uint64_t parents[] = {2, 3, 4};
                    const std::uint64_t children[] = {3, 4, 5};

                    for (int pi = 0; pi < 3; ++pi) {
                        const std::string pn = names[pi];
                        const std::uint16_t stored =
                            static_cast<std::uint16_t>(pn.size()) + 1;
                        std::vector<std::uint8_t> ke(2 + stored);
                        ke[0] = static_cast<std::uint8_t>(stored & 0xff);
                        ke[1] = static_cast<std::uint8_t>(stored >> 8);
                        std::memcpy(ke.data() + 2, pn.c_str(), pn.size());
                        ke[2 + pn.size()] = 0;

                        std::vector<std::uint8_t> val(18, 0);
                        put_le64(val, 0, children[pi]);
                        put_le32(val, 16, 4); // DT_DIR

                        add_rec(
                            (9ull << 60) | parents[pi],
                            ke, 18, val
                        );
                    }
                }

                // Now the plist under LaunchDaemons (CNID 5).
                {
                    const std::string name = "test.plist";
                    const std::uint16_t name_stored =
                        static_cast<std::uint16_t>(name.size()) + 1;
                    std::vector<std::uint8_t> ke(2 + name_stored);
                    ke[0] = static_cast<std::uint8_t>(
                        name_stored & 0xff);
                    ke[1] = static_cast<std::uint8_t>(
                        name_stored >> 8);
                    std::memcpy(
                        ke.data() + 2, name.c_str(), name.size());
                    ke[2 + name.size()] = 0;

                    // drec_val: file_id u64 + date_added u64 + flags u16
                    std::vector<std::uint8_t> val(18, 0);
                    put_le64(val, 0, kFileCnid);
                    put_le32(val, 16, 0x8); // DT_REG

                    add_rec(
                        (9ull << 60) | 5ull, ke, 18, val
                    );
                }

                // Record 2: INODE for kFileCnid.
                {
                    const bool is_xattr_test =
                        cfg.mut == Mut::XattrBadSignature ||
                        cfg.mut == Mut::XattrBadMarker ||
                        cfg.mut == Mut::XattrSizeMismatch ||
                        cfg.mut == Mut::XattrBadXdataLen ||
                        cfg.mut == Mut::XattrDataStreamOnly ||
                        cfg.mut == Mut::XattrAmbiguous;

                    std::vector<std::uint8_t> inode_val;

                    if (cfg.mut == Mut::InodeShortBase) {
                        // Truncated base: < 0x5c.
                        inode_val.assign(0x40, 0);
                        put_le64(inode_val, 0, 5);   // parent = LaunchDaemons
                        put_le64(inode_val, 8, kFileCnid); // private
                    } else if (cfg.mut == Mut::InodeBaseOnly) {
                        // Exactly 0x5c, no xfields.
                        inode_val.assign(0x5c, 0);
                        put_le64(inode_val, 0, 5);
                        put_le64(inode_val, 8, kFileCnid);
                        put_le32(inode_val, 0x44, 0); // bsd_flags
                        put_le32(inode_val, 0x50, 0x81a4); // mode=reg
                    } else if (cfg.mut == Mut::InodePartialXfHeader) {
                        // 0x5d: partial xf_blob.
                        inode_val.assign(0x5d, 0);
                        put_le64(inode_val, 0, 5);
                        put_le64(inode_val, 8, kFileCnid);
                        put_le32(inode_val, 0x50, 0x81a4);
                    } else if (
                        cfg.mut == Mut::InodeXfMetaOverflow) {
                        // Claim 100 metadata entries but value too small.
                        inode_val.assign(0x70, 0);
                        put_le64(inode_val, 0, 5);
                        put_le64(inode_val, 8, kFileCnid);
                        put_le32(inode_val, 0x50, 0x81a4);
                        // xf_blob at 0x5c: num_exts=100 (overflow).
                        put_le16_safe(
                            inode_val, 0x5c, 100);
                        put_le16_safe(
                            inode_val, 0x5e, 0);
                    } else if (
                        cfg.mut == Mut::InodeXfValOverflow) {
                        // Metadata claims large padded value.
                        inode_val.assign(0x80, 0);
                        put_le64(inode_val, 0, 5);
                        put_le64(inode_val, 8, kFileCnid);
                        put_le32(inode_val, 0x50, 0x81a4);
                        // xf_blob: 1 ext, type=DSTREAM(8), size=0x100.
                        put_le16_safe(inode_val, 0x5c, 1);
                        put_le16_safe(inode_val, 0x5e, 0x100);
                        inode_val[0x60] = 8; // type
                        inode_val[0x62] = 0x00; // size lo
                        inode_val[0x63] = 0x01; // size hi (0x100)
                    } else if (cfg.mut == Mut::InodeBadUsedData) {
                        // 1 DSTREAM ext (40 bytes padded to 40), but
                        // xf_used_data = 48 (wrong).
                        inode_val.assign(
                            0x5c + 4 + 4 + 40, 0);
                        put_le64(inode_val, 0, 5);
                        put_le64(inode_val, 8, kFileCnid);
                        put_le32(inode_val, 0x50, 0x81a4);
                        put_le16_safe(inode_val, 0x5c, 1);
                        put_le16_safe(inode_val, 0x5e, 48); // wrong
                        inode_val[0x60] = 8;
                        inode_val[0x62] = 40;
                        put_le64(inode_val, 0x64, 100); // dstream size
                    } else if (cfg.mut == Mut::InodeShortDstream) {
                        // DSTREAM ext claims size=20 (too short).
                        inode_val.assign(
                            0x5c + 4 + 4 + 24, 0);
                        put_le64(inode_val, 0, 5);
                        put_le64(inode_val, 8, kFileCnid);
                        put_le32(inode_val, 0x50, 0x81a4);
                        put_le16_safe(inode_val, 0x5c, 1);
                        put_le16_safe(inode_val, 0x5e, 24);
                        inode_val[0x60] = 8;
                        inode_val[0x62] = 20; // short
                        put_le64(inode_val, 0x64, 100);
                    } else if (cfg.mut == Mut::InodeTrailingBytes) {
                        // Correct DSTREAM but extra trailing bytes.
                        inode_val.assign(
                            0x5c + 4 + 4 + 40 + 8, 0);
                        put_le64(inode_val, 0, 5);
                        put_le64(inode_val, 8, kFileCnid);
                        put_le32(inode_val, 0x50, 0x81a4);
                        put_le16_safe(inode_val, 0x5c, 1);
                        put_le16_safe(inode_val, 0x5e, 40);
                        inode_val[0x60] = 8;
                        inode_val[0x62] = 40;
                        put_le64(inode_val, 0x64, 100);
                    } else {
                        // Valid inode with DSTREAM (or compressed for XATTR tests).
                        inode_val.assign(
                            0x5c + 4 + 4 + 40, 0);
                        put_le64(inode_val, 0, 5); // parent
                        put_le64(inode_val, 8, kFileCnid);
                        // Set compressed flag for XATTR tests.
                        put_le32(inode_val, 0x44,
                            is_xattr_test ? 0x20 : 0);
                        put_le32(inode_val, 0x50, 0x81a4); // reg
                        // xf_blob: 1 ext, DSTREAM, 40 bytes.
                        put_le16_safe(inode_val, 0x5c, 1);
                        put_le16_safe(inode_val, 0x5e, 40);
                        inode_val[0x60] = 8; // DSTREAM type
                        inode_val[0x62] = 40; // x_size = 40
                        put_le64(inode_val, 0x64, 100); // size=100
                    }

                    std::vector<std::uint8_t> ke; // empty
                    add_rec(
                        (3ull << 60) | kFileCnid,
                        ke,
                        static_cast<std::uint16_t>(
                            inode_val.size()),
                        inode_val
                    );
                }

                // XATTR record (only for XATTR test cases).
                if (cfg.mut == Mut::XattrBadSignature ||
                    cfg.mut == Mut::XattrBadMarker ||
                    cfg.mut == Mut::XattrSizeMismatch ||
                    cfg.mut == Mut::XattrBadXdataLen ||
                    cfg.mut == Mut::XattrDataStreamOnly ||
                    cfg.mut == Mut::XattrAmbiguous) {

                    // XATTR key: name_len=18, "com.apple.decmpfs\0"
                    std::vector<std::uint8_t> ke(2 + 18);
                    ke[0] = 18; ke[1] = 0;
                    std::memcpy(ke.data() + 2,
                        "com.apple.decmpfs", 17);
                    ke[2 + 17] = 0;

                    // Build decmpfs xdata (19 bytes: 16 hdr + 1 marker + 2 payload).
                    std::vector<std::uint8_t> xdata(19, 0);
                    put_le32(xdata, 0, 0x636D7066u); // "cmpf"
                    put_le32(xdata, 4, 9); // algo 9
                    put_le64(xdata, 8, 2); // logical_size = 2
                    xdata[16] = 0xCC; // marker
                    xdata[17] = 'A'; xdata[18] = 'B'; // payload

                    // Apply mutation.
                    if (cfg.mut == Mut::XattrBadSignature) {
                        put_le32(xdata, 0, 0xDEADBEEFu);
                    } else if (cfg.mut == Mut::XattrBadMarker) {
                        xdata[16] = 0x00;
                    } else if (cfg.mut == Mut::XattrSizeMismatch) {
                        put_le64(xdata, 8, 99); // wrong size
                    }

                    // XATTR value: flags u16 + xdata_len u16 + xdata[]
                    std::uint16_t xflags = 0x0002; // DATA_EMBEDDED
                    if (cfg.mut == Mut::XattrDataStreamOnly) {
                        xflags = 0x0001;
                    } else if (cfg.mut == Mut::XattrAmbiguous) {
                        xflags = 0x0003;
                    }

                    std::uint16_t xdata_len_field =
                        static_cast<std::uint16_t>(xdata.size());
                    if (cfg.mut == Mut::XattrBadXdataLen) {
                        xdata_len_field = 99; // mismatch
                    }

                    std::vector<std::uint8_t> xval(
                        4 + xdata.size(), 0);
                    xval[0] = static_cast<std::uint8_t>(
                        xflags & 0xff);
                    xval[1] = static_cast<std::uint8_t>(
                        xflags >> 8);
                    xval[2] = static_cast<std::uint8_t>(
                        xdata_len_field & 0xff);
                    xval[3] = static_cast<std::uint8_t>(
                        xdata_len_field >> 8);
                    std::memcpy(
                        xval.data() + 4,
                        xdata.data(), xdata.size());

                    add_rec(
                        (4ull << 60) | kFileCnid,
                        ke,
                        static_cast<std::uint16_t>(xval.size()),
                        xval
                    );
                }

                // Record 3+: FILE_EXTENT for private_id.
                if (cfg.mut != Mut::XattrBadSignature &&
                    cfg.mut != Mut::XattrBadMarker &&
                    cfg.mut != Mut::XattrSizeMismatch &&
                    cfg.mut != Mut::XattrBadXdataLen &&
                    cfg.mut != Mut::XattrDataStreamOnly &&
                    cfg.mut != Mut::XattrAmbiguous) {

                    auto add_extent = [&](
                        std::uint64_t logical,
                        std::uint64_t length,
                        std::uint64_t phys,
                        std::uint16_t forced_key_extra_len = 8,
                        std::uint16_t forced_val_len = 24
                    ) {
                        std::vector<std::uint8_t> ke(
                            forced_key_extra_len);
                        if (forced_key_extra_len >= 8) {
                            put_le64(ke, 0, logical);
                        } else {
                            for (std::uint16_t i = 0;
                                 i < forced_key_extra_len; ++i) {
                                ke[i] =
                                    static_cast<std::uint8_t>(
                                        logical >> (i * 8));
                            }
                        }

                        std::vector<std::uint8_t> val(24, 0);
                        put_le64(val, 0, length); // len_and_flags
                        put_le64(val, 8, phys);

                        add_rec(
                            (8ull << 60) | kFileCnid,
                            ke,
                            forced_val_len,
                            val,
                            forced_key_extra_len
                        );
                    };

                    if (cfg.mut == Mut::ExtentBadKeyLen) {
                        add_extent(0, 100, 12, 6, 24); // bad key len
                    } else if (cfg.mut == Mut::ExtentLeadingGap) {
                        add_extent(50, 50, 12); // gap at [0,50)
                    } else if (cfg.mut == Mut::ExtentMiddleGap) {
                        add_extent(0, 40, 12);
                        add_extent(60, 40, 14); // gap at [40,60)
                    } else if (cfg.mut == Mut::ExtentHoleAccepted) {
                        add_extent(0, 40, 10);
                        add_extent(40, 20, 0); // hole
                        add_extent(60, 40, 11);
                    } else if (cfg.mut == Mut::ExtentPhysOverrun) {
                        // phys at last block, length needs 2 blocks.
                        add_extent(0, 8192, rbc - 1); // needs 2 blocks
                    } else if (cfg.mut == Mut::ExtentLogicalOverflow) {
                        // Two overlapping extents (logical overlap).
                        add_extent(0, 100, 12);
                        add_extent(50, 100, 14); // overlaps [50,100)
                    } else {
                        // Valid: one extent covering [0,100).
                        add_extent(0, 100, 12);
                    }
                }

                put_le32(blk, 0x24, nkeys);
                put_le32(blk, 0x28,
                    (static_cast<std::uint32_t>(tlen) << 16) | tofs);
                rseal(blk);
                return blk;
            };

            // NXSB block 0.
            {
                std::vector<std::uint8_t> blk(rbs, 0);
                put_le64(blk, 8, 1); put_le64(blk, 16, 1);
                put_le32(blk, 24, 0x80000001u);
                put_le32(blk, 32, 0x4253584Eu);
                put_le32(blk, 36, rbs);
                put_le64(blk, 40, rbc);
                rseal(blk);
                put(0, blk);
            }

            // APSB block 1.
            {
                std::vector<std::uint8_t> blk(rbs, 0);
                put_le64(blk, 8, 42); put_le64(blk, 16, 3);
                put_le32(blk, 24, 0x80000009u);
                put_le32(blk, 32, 0x42535041u);
                put_le64(blk, 0x80, 4);
                put_le64(blk, 0x88, kRootOid);
                put_le64(blk, 0x90, 3);
                std::memcpy(blk.data() + 0x2C0, "rdtest", 6);
                rseal(blk);
                put(1, blk);
            }

            // omap_phys block 4.
            {
                std::vector<std::uint8_t> blk(rbs, 0);
                put_le64(blk, 8, 4); put_le64(blk, 16, 3);
                put_le32(blk, 24, 0x4000000Bu);
                put_le64(blk, 0x30, 5);
                rseal(blk);
                put(4, blk);
            }

            // OMAP leaf block 5: 300→6, 301→7, 302→8.
            {
                std::vector<std::uint8_t> blk(rbs, 0);
                put_le64(blk, 8, 5); put_le64(blk, 16, 3);
                put_le32(blk, 24, 0x40000003u);
                put_le32(blk, 0x20, 0x00000006u);
                put_le32(blk, 0x24, 3);
                put_le32(blk, 0x28, 0x00100000u);
                blk[0x38] = 0x00; blk[0x39] = 0x00;
                blk[0x3a] = 0x10; blk[0x3b] = 0x00;
                blk[0x3c] = 0x10; blk[0x3d] = 0x00;
                blk[0x3e] = 0x20; blk[0x3f] = 0x00;
                blk[0x40] = 0x20; blk[0x41] = 0x00;
                blk[0x42] = 0x30; blk[0x43] = 0x00;
                put_le64(blk, 0x48, kRootOid);
                put_le64(blk, 0x48 + 8, 2);
                put_le64(blk, 0x48 + 0x10, kMidOid);
                put_le64(blk, 0x48 + 0x18, 2);
                put_le64(blk, 0x48 + 0x20, kLeafOid);
                put_le64(blk, 0x48 + 0x28, 2);
                put_le64(blk, 0xfc8 + 8, 6);
                put_le64(blk, 0xfb8 + 8, 7);
                put_le64(blk, 0xfa8 + 8, 8);
                rseal(blk);
                put(5, blk);
            }

            // FSTREE root block 6: level 1, 1 child.
            {
                std::vector<std::uint8_t> blk(rbs, 0);
                put_le64(blk, 8, kRootOid);
                put_le64(blk, 16, 3);
                put_le32(blk, 24, 0x40000003u);
                put_le32(blk, 28, 0x0000000Eu);
                blk[0x20] = 0x01; // ROOT
                blk[0x22] = 0x01; // level 1
                put_le32(blk, 0x24, 1);
                put_le32(blk, 0x28, 0x00100000u);
                blk[0x38] = 0x00; blk[0x39] = 0x00;
                blk[0x3a] = 0x10; blk[0x3b] = 0x00;
                blk[0x3c] = 0x10; blk[0x3d] = 0x00;
                blk[0x3e] = 0x08; blk[0x3f] = 0x00;
                put_le64(blk, 0x48, (9ull << 60) | 1ull);
                put_le64(blk, 0xfc8, kMidOid);
                put_le32(blk, rbs - 0x28, 0);
                put_le32(blk, rbs - 0x28 + 4, rbs);
                rseal(blk);
                put(6, blk);
            }

            // FSTREE mid block 7: level 0 (leaf), direct to leaf 8.
            // Wait — we need root(level 1) → leaf(level 0).
            // So mid IS the leaf containing all records.
            // Block 7 = mid = leaf with all records.
            {
                auto leaf_blk = build_leaf();
                // Override OID/level for mid position.
                put_le64(leaf_blk, 8, kMidOid);
                leaf_blk[0x22] = 0x00; // level 0 (leaf)
                leaf_blk[0x20] = 0x02; // LEAF
                rseal(leaf_blk);
                put(7, leaf_blk);
            }

            return img;
        };

        // Helper: run image, return plist_file error/status.
        auto run_read_path = [&](
            const std::vector<std::uint8_t>& blocks,
            const char* tag
        ) -> std::pair<std::string, std::string> {
            const std::string path =
                std::string(temp_path) + "apfs_rp_" + tag + ".img";
            if (!write_all(path, blocks)) {
                return {"WRITE_FAIL", ""};
            }
            vphone::ApfsReaderReport rpt;
            std::string err;
            vphone::apfs_read_container(path, rpt, err);
            DeleteFileA(path.c_str());
            return {
                rpt.plist_file.status,
                rpt.plist_file.error
            };
        };

        auto assert_error = [&](
            const std::pair<std::string, std::string>& result,
            const char* expected_substring,
            const char* tag
        ) -> bool {
            if (result.first != "FAIL" && result.first != "UNSUPPORTED") {
                std::fprintf(
                    stderr,
                    "[%s] expected FAIL, got '%s' (err='%s')\n",
                    tag, result.first.c_str(),
                    result.second.c_str()
                );
                return false;
            }
            if (result.second.find(expected_substring) ==
                std::string::npos) {
                std::fprintf(
                    stderr,
                    "[%s] error '%s' missing '%s'\n",
                    tag, result.second.c_str(),
                    expected_substring
                );
                return false;
            }
            return true;
        };

        // Run the matrix.
        struct TestCase {
            Mut mut;
            const char* tag;
            const char* expected_error; // null = positive
            bool expect_ok;
        };

        const TestCase cases[] = {
            // Positive baseline.
            {Mut::None, "valid",
             nullptr, true},
            // INODE/xfield.
            {Mut::InodeShortBase, "short_base",
             "INODE value shorter than base structure", false},
            {Mut::InodeBaseOnly, "base_only",
             "all", false}, // valid base but no dstream; generic reject
            {Mut::InodePartialXfHeader, "partial_xf",
             "xfield partial xf_blob header", false},
            {Mut::InodeXfMetaOverflow, "meta_overflow",
             "xfield metadata bounds exceeded", false},
            {Mut::InodeXfValOverflow, "val_overflow",
             "xfield value bounds exceeded", false},
            {Mut::InodeBadUsedData, "bad_used_data",
             "xfield xf_used_data mismatch", false},
            {Mut::InodeShortDstream, "short_dstream",
             "DSTREAM xfield value too short", false},
            {Mut::InodeTrailingBytes, "trailing_bytes",
             "xfield collection-size mismatch", false},
            // XATTR/decmpfs (these need compressed inode path).
            {Mut::XattrBadSignature, "bad_sig",
             "XATTR bad cmpf signature", false},
            {Mut::XattrBadMarker, "bad_marker",
             "XATTR bad 0xCC marker", false},
            {Mut::XattrSizeMismatch, "size_mismatch",
             "XATTR logical-size mismatch", false},
            {Mut::XattrBadXdataLen, "bad_xdata_len",
             "XATTR xdata_len mismatch", false},
            {Mut::XattrDataStreamOnly, "datastream_only",
             "XATTR DATA_STREAM not supported", false},
            {Mut::XattrAmbiguous, "ambiguous",
             "XATTR DATA_STREAM not supported", false},
            // FILE_EXTENT.
            {Mut::ExtentBadKeyLen, "ext_bad_key",
             "FILE_EXTENT malformed size", false},
            {Mut::ExtentLeadingGap, "ext_lead_gap",
             "extent coverage gap", false},
            {Mut::ExtentMiddleGap, "ext_mid_gap",
             "extent coverage gap", false},
            {Mut::ExtentHoleAccepted, "ext_hole",
             nullptr, true}, // positive
            {Mut::ExtentPhysOverrun, "ext_phys_overrun",
             "extent physical range exceeds container", false},
            {Mut::ExtentLogicalOverflow, "ext_logical_overflow",
             "overlapping extents", false},
        };

        for (const auto& tc : cases) {
            ReadPathImage cfg;
            cfg.mut = tc.mut;
            const auto blocks = build_read_path_image(cfg);
            const auto result = run_read_path(blocks, tc.tag);

            if (tc.expect_ok) {
                if (result.first != "READ_OK") {
                    std::fprintf(
                        stderr,
                        "[%s] expected READ_OK, got '%s' (err='%s')\n",
                        tc.tag, result.first.c_str(),
                        result.second.c_str()
                    );
                    return 1;
                }
            } else {
                if (!assert_error(
                        result, tc.expected_error, tc.tag)) {
                    return 1;
                }
            }
        }

        std::fprintf(
            stderr,
            "read-path regression matrix: %zu cases passed\n",
            sizeof(cases) / sizeof(cases[0])
        );
    }

    std::printf("APFS_READER_TEST_PASS\n");
    return 0;
}
