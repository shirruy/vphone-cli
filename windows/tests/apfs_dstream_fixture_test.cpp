// ResourceFork DATA_STREAM descriptor + XATTR storage-mode negative
// matrix. Exercises the SAME production helpers used by
// apfs_reader.cpp (decmpfs_parse_xattr_dstream and
// decmpfs_classify_xattr_flags), so the tested code is the exact
// production parser path for j_xattr_dstream descriptors.

#include "vphone/decmpfs_dstream.hpp"

#include <cstdint>
#include <cstdio>
#include <string>
#include <vector>

namespace {

void put_le64(
    std::vector<std::uint8_t>& b, std::size_t off,
    std::uint64_t v
) {
    for (int i = 0; i < 8; ++i) {
        b[off + i] = static_cast<std::uint8_t>(v >> (i * 8));
    }
}

// Build a structurally valid 48-byte descriptor.
std::vector<std::uint8_t> valid_descriptor() {
    std::vector<std::uint8_t> d(48, 0);
    put_le64(d, 0, 0x12345678); // xattr_obj_id
    put_le64(d, 8, 4096); // size
    put_le64(d, 16, 8192); // alloced_size
    put_le64(d, 24, 3); // default_crypto_id
    put_le64(d, 32, 4096); // total_bytes_written
    put_le64(d, 40, 0); // total_bytes_read
    return d;
}

} // namespace

int main() {
    int failures = 0;

    // 1. Exact DATA_STREAM flag (0x0001) accepted.
    if (vphone::decmpfs_classify_xattr_flags(0x0001) !=
        vphone::XattrStorageMode::DATA_STREAM) {
        std::fprintf(stderr, "[1] 0x0001 not DATA_STREAM\n");
        ++failures;
    } else {
        std::printf("DSTREAM_FLAGS_0X0001_DATA_STREAM_PASS\n");
    }

    // 2. Exact DATA_EMBEDDED flag (0x0002) accepted.
    if (vphone::decmpfs_classify_xattr_flags(0x0002) !=
        vphone::XattrStorageMode::DATA_EMBEDDED) {
        std::fprintf(stderr, "[2] 0x0002 not DATA_EMBEDDED\n");
        ++failures;
    } else {
        std::printf("DSTREAM_FLAGS_0X0002_DATA_EMBEDDED_PASS\n");
    }

    // 3. Zero flags refused.
    if (vphone::decmpfs_classify_xattr_flags(0x0000) !=
        vphone::XattrStorageMode::INVALID) {
        std::fprintf(stderr, "[3] 0x0000 accepted\n");
        ++failures;
    } else {
        std::printf("DSTREAM_FLAGS_0X0000_REFUSED_PASS\n");
    }

    // 4. Ambiguous combination 0x0003 refused.
    if (vphone::decmpfs_classify_xattr_flags(0x0003) !=
        vphone::XattrStorageMode::INVALID) {
        std::fprintf(stderr, "[4] 0x0003 accepted\n");
        ++failures;
    } else {
        std::printf("DSTREAM_FLAGS_0X0003_REFUSED_PASS\n");
    }

    // 5. Unknown flag bit 0x0004 refused.
    if (vphone::decmpfs_classify_xattr_flags(0x0004) !=
        vphone::XattrStorageMode::INVALID) {
        std::fprintf(stderr, "[5] 0x0004 accepted\n");
        ++failures;
    } else {
        std::printf("DSTREAM_FLAGS_0X0004_REFUSED_PASS\n");
    }

    // 6. Valid 48-byte descriptor parses with exact fields.
    {
        const auto d = valid_descriptor();
        const auto info =
            vphone::decmpfs_parse_xattr_dstream(d);
        if (!info.valid || info.xattr_obj_id != 0x12345678 ||
            info.size != 4096 || info.alloced_size != 8192 ||
            info.default_crypto_id != 3 ||
            info.total_bytes_written != 4096 ||
            info.total_bytes_read != 0) {
            std::fprintf(
                stderr, "[6] valid descriptor failed: %s\n",
                info.error.c_str());
            ++failures;
        } else {
            std::printf("DSTREAM_DESCRIPTOR_48_VALID_PASS\n");
        }
    }

    // 7. 8-byte descriptor refused.
    {
        std::vector<std::uint8_t> d(8, 0);
        if (vphone::decmpfs_parse_xattr_dstream(d).valid) {
            std::fprintf(stderr, "[7] 8-byte descriptor accepted\n");
            ++failures;
        } else {
            std::printf("DSTREAM_DESCRIPTOR_8_REFUSED_PASS\n");
        }
    }

    // 8. 16-byte descriptor refused.
    {
        std::vector<std::uint8_t> d(16, 0);
        if (vphone::decmpfs_parse_xattr_dstream(d).valid) {
            std::fprintf(stderr, "[8] 16-byte descriptor accepted\n");
            ++failures;
        } else {
            std::printf("DSTREAM_DESCRIPTOR_16_REFUSED_PASS\n");
        }
    }

    // 9. 47-byte descriptor refused.
    {
        std::vector<std::uint8_t> d(47, 0);
        if (vphone::decmpfs_parse_xattr_dstream(d).valid) {
            std::fprintf(stderr, "[9] 47-byte descriptor accepted\n");
            ++failures;
        } else {
            std::printf("DSTREAM_DESCRIPTOR_47_REFUSED_PASS\n");
        }
    }

    // 10. 49-byte descriptor refused.
    {
        std::vector<std::uint8_t> d(49, 0);
        if (vphone::decmpfs_parse_xattr_dstream(d).valid) {
            std::fprintf(stderr, "[10] 49-byte descriptor accepted\n");
            ++failures;
        } else {
            std::printf("DSTREAM_DESCRIPTOR_49_REFUSED_PASS\n");
        }
    }

    // 11. size > alloced_size refused.
    {
        auto d = valid_descriptor();
        put_le64(d, 8, 9000); // size
        put_le64(d, 16, 8192); // alloced_size
        if (vphone::decmpfs_parse_xattr_dstream(d).valid) {
            std::fprintf(
                stderr, "[11] size>alloced accepted\n");
            ++failures;
        } else {
            std::printf("DSTREAM_DESCRIPTOR_SIZE_GT_ALLOCED_REFUSED_PASS\n");
        }
    }

    // 12. size == alloced_size accepted (boundary).
    {
        auto d = valid_descriptor();
        put_le64(d, 8, 8192);
        put_le64(d, 16, 8192);
        if (!vphone::decmpfs_parse_xattr_dstream(d).valid) {
            std::fprintf(stderr, "[12] size==alloced refused\n");
            ++failures;
        } else {
            std::printf("DSTREAM_DESCRIPTOR_SIZE_EQ_ALLOCED_PASS\n");
        }
    }

    if (failures == 0) {
        // Descriptor/flags scope only. FILE_EXTENT coverage lives in
        // apfs_file_extent_fixture_test; the combined orchestration
        // gate lives in apfs_dstream_contract_test.
        std::printf(
            "RESOURCEFORK_DSTREAM_DESCRIPTOR_NEGATIVE_MATRIX_PASS\n");
        return 0;
    }
    std::fprintf(stderr, "FAILURES=%d\n", failures);
    return 1;
}
