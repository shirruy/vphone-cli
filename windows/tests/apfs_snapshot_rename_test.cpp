#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include "vphone/apfs_snapshot_portable.hpp"

#include <array>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <string>
#include <vector>

#define CHECK(expr) \
    do { \
        if (!(expr)) { \
            std::fprintf(stderr, "CHECK FAILED at %s:%d: %s\n", __FILE__, __LINE__, #expr); \
            return 1; \
        } \
    } while (0)

static void write_le64(std::uint8_t* p, std::uint64_t value)
{
    for (int i = 0; i < 8; ++i) {
        p[i] = static_cast<std::uint8_t>((value >> (i * 8)) & 0xFFu);
    }
}

static bool write_fixture(
    const std::string& path,
    const std::vector<std::uint8_t>& data
)
{
    std::ofstream out(path, std::ios::binary | std::ios::trunc);
    if (!out) {
        return false;
    }
    out.write(
        reinterpret_cast<const char*>(data.data()),
        static_cast<std::streamsize>(data.size())
    );
    return out.good();
}

static bool read_fixture(
    const std::string& path,
    std::vector<std::uint8_t>& data
)
{
    std::ifstream in(path, std::ios::binary);
    if (!in) {
        return false;
    }
    in.seekg(0, std::ios::end);
    const auto size = in.tellg();
    if (size <= 0) {
        return false;
    }
    in.seekg(0, std::ios::beg);
    data.resize(static_cast<std::size_t>(size));
    in.read(reinterpret_cast<char*>(data.data()), size);
    return in.good();
}

int main(int argc, char** argv)
{
    CHECK(argc == 2);

    const std::string path =
        std::string(argv[1]) + "\\apfs-snapshot-rename-fixture.img";

    DeleteFileA(path.c_str());

    constexpr std::size_t block_size = vphone::kApfsSnapshotBlockSize;
    std::vector<std::uint8_t> image(block_size * 2, 0);

    const std::string hash =
        "0123456789abcdef0123456789abcdef"
        "0123456789abcdef0123456789abcdef";

    const std::string original =
        std::string(vphone::kApfsSnapshotOldPrefix) + hash;

    const std::size_t first = 256;
    const std::size_t second = 1024;
    const std::size_t invalid = block_size + 512;

    std::memcpy(image.data() + first, original.data(), original.size());
    std::memcpy(image.data() + second, original.data(), original.size());
    std::memcpy(image.data() + invalid, original.data(), original.size());

    const std::uint64_t valid_sum =
        vphone::apfs_snapshot_checksum(image.data(), block_size);
    write_le64(image.data(), valid_sum);

    // Leave block 2's stored checksum invalid on purpose.
    CHECK(vphone::apfs_snapshot_block_valid(image.data(), block_size));
    CHECK(!vphone::apfs_snapshot_block_valid(
        image.data() + block_size,
        block_size
    ));

    CHECK(write_fixture(path, image));

    vphone::ApfsSnapshotReport dry;
    std::string error;

    CHECK(vphone::apfs_snapshot_rename_file(
        path,
        vphone::kApfsSnapshotDefaultNewPrefix,
        true,
        dry,
        error
    ));
    CHECK(dry.record_count() == 2);
    CHECK(dry.blocks.size() == 1);
    CHECK(dry.snapshot_name == original);

    std::vector<std::uint8_t> after_dry;
    CHECK(read_fixture(path, after_dry));
    CHECK(after_dry == image);

    vphone::ApfsSnapshotReport applied;
    error.clear();

    CHECK(vphone::apfs_snapshot_rename_file(
        path,
        vphone::kApfsSnapshotDefaultNewPrefix,
        false,
        applied,
        error
    ));
    CHECK(applied.record_count() == 2);
    CHECK(applied.blocks.size() == 1);

    std::vector<std::uint8_t> after;
    CHECK(read_fixture(path, after));
    CHECK(after.size() == image.size());

    const std::string replacement =
        std::string(vphone::kApfsSnapshotDefaultNewPrefix) + hash;

    CHECK(std::memcmp(
        after.data() + first,
        replacement.data(),
        replacement.size()
    ) == 0);

    CHECK(std::memcmp(
        after.data() + second,
        replacement.data(),
        replacement.size()
    ) == 0);

    // Invalid metadata block must not be rewritten.
    CHECK(std::memcmp(
        after.data() + invalid,
        original.data(),
        original.size()
    ) == 0);

    CHECK(vphone::apfs_snapshot_block_valid(after.data(), block_size));
    CHECK(!vphone::apfs_snapshot_block_valid(
        after.data() + block_size,
        block_size
    ));

    // Prefix length is a hard safety invariant.
    vphone::ApfsSnapshotReport rejected;
    error.clear();
    CHECK(!vphone::apfs_snapshot_rename_file(
        path,
        "too-short",
        false,
        rejected,
        error
    ));
    CHECK(error.find("exactly") != std::string::npos);

    DeleteFileA(path.c_str());
    return 0;
}
