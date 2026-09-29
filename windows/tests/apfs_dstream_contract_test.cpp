// Combined DATA_STREAM contract: exact XATTR flags -> strict 48-byte
// j_xattr_dstream descriptor -> shared FILE_EXTENT validation ->
// complete logical coverage. Every step calls the SAME production
// helpers used by apfs_reader.cpp (decmpfs_classify_xattr_flags,
// decmpfs_parse_xattr_dstream, validate_file_extents). This is the
// orchestration-level contract the broad marker name represents.

#include "vphone/decmpfs_dstream.hpp"
#include "vphone/file_extent.hpp"

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

} // namespace

int main() {
    int failures = 0;
    const auto fail = [&](const char* msg) {
        std::fprintf(stderr, "%s\n", msg);
        ++failures;
    };

    // Positive: the full DATA_STREAM contract.
    {
        // flags 0x0001 -> DATA_STREAM.
        const vphone::XattrStorageMode mode =
            vphone::decmpfs_classify_xattr_flags(0x0001);
        if (mode != vphone::XattrStorageMode::DATA_STREAM) {
            fail("[pos] flags classified incorrectly");
        } else {
            std::printf("DSTREAM_CONTRACT_FLAGS_PASS\n");
        }

        // 48-byte descriptor with size<=alloced.
        std::vector<std::uint8_t> d(48, 0);
        put_le64(d, 0, 0x12345); // xattr_obj_id
        put_le64(d, 8, 8192); // size
        put_le64(d, 16, 16384); // alloced_size
        const vphone::XattrDstreamInfo info =
            vphone::decmpfs_parse_xattr_dstream(d);
        if (!info.valid || info.size != 8192) {
            fail("[pos] descriptor rejected");
        } else {
            std::printf("DSTREAM_CONTRACT_DESCRIPTOR_PASS\n");
        }

        // Extents covering [0, 8192).
        vphone::FileExtentContext fctx{};
        fctx.dstream_size = info.size;
        fctx.block_size = 4096;
        fctx.block_count = 1000;
        fctx.allow_sparse = true;
        const vphone::FileExtentValidation val =
            vphone::validate_file_extents(
                {{0, 4096, 10}, {4096, 4096, 11}},
                fctx);
        if (!val.valid || !val.complete) {
            fail("[pos] extents rejected");
        } else {
            std::printf("DSTREAM_CONTRACT_EXTENTS_PASS\n");
        }
        if (failures == 0) {
            std::printf("DSTREAM_CONTRACT_COMPLETE_PASS\n");
        }
    }

    // Negative A: ambiguous flags break the contract at step 1.
    {
        const vphone::XattrStorageMode mode =
            vphone::decmpfs_classify_xattr_flags(0x0003);
        if (mode != vphone::XattrStorageMode::INVALID) {
            fail("[negA] ambiguous flags accepted");
        } else {
            std::printf("DSTREAM_CONTRACT_AMBIGUOUS_FLAGS_REFUSED_PASS\n");
        }
    }

    // Negative B: descriptor size>alloced breaks the contract.
    {
        std::vector<std::uint8_t> d(48, 0);
        put_le64(d, 0, 0x12345);
        put_le64(d, 8, 16384); // size
        put_le64(d, 16, 8192); // alloced_size
        if (vphone::decmpfs_parse_xattr_dstream(d).valid) {
            fail("[negB] size>alloced descriptor accepted");
        } else {
            std::printf("DSTREAM_CONTRACT_BAD_DESCRIPTOR_REFUSED_PASS\n");
        }
    }

    // Negative C: extent gap breaks the contract.
    {
        vphone::FileExtentContext fctx{};
        fctx.dstream_size = 8192;
        fctx.block_size = 4096;
        fctx.block_count = 1000;
        fctx.allow_sparse = true;
        if (vphone::validate_file_extents(
                {{0, 4000, 10}, {6000, 2192, 11}},
                fctx).valid) {
            fail("[negC] gapped extents accepted");
        } else {
            std::printf("DSTREAM_CONTRACT_GAP_REFUSED_PASS\n");
        }
    }

    // Negative D: incomplete coverage breaks the contract.
    {
        vphone::FileExtentContext fctx{};
        fctx.dstream_size = 8192;
        fctx.block_size = 4096;
        fctx.block_count = 1000;
        fctx.allow_sparse = true;
        if (vphone::validate_file_extents(
                {{0, 4000, 10}}, fctx).valid) {
            fail("[negD] incomplete extents accepted");
        } else {
            std::printf("DSTREAM_CONTRACT_INCOMPLETE_REFUSED_PASS\n");
        }
    }

    if (failures == 0) {
        std::printf("RESOURCEFORK_DATA_STREAM_NEGATIVE_MATRIX_PASS\n");
        return 0;
    }
    std::fprintf(stderr, "FAILURES=%d\n", failures);
    return 1;
}