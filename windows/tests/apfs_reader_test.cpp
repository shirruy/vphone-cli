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
        put_le64(blk, 0x90, 3);         // root tree block
        const char* name = "testvol";
        std::memcpy(blk.data() + 0x2C0, name, std::strlen(name));
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
        std::memcpy(
            image.data() + 2 * static_cast<std::size_t>(block_size),
            blk.data(),
            block_size
        );
    }

    // B-tree root at block 3.
    {
        std::vector<std::uint8_t> blk(block_size, 0);
        make_object_header(blk, 3, 3, 0x40000002u);
        std::memcpy(
            image.data() + 3 * static_cast<std::size_t>(block_size),
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

    std::printf("APFS_READER_TEST_PASS\n");
    return 0;
}
