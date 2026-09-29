// FILE_EXTENT geometry negative matrix exercising the SHARED
// production validator (vphone::validate_file_extents), which is the
// exact code used by apfs_reader.cpp for plist reconstruction and the
// ResourceFork DATA_STREAM path. Tests do not mirror the logic, and
// every negative asserts the exact rejection reason.

#include "vphone/file_extent.hpp"

#include <cstdint>
#include <cstdio>
#include <limits>
#include <string>
#include <vector>

using vphone::FileExtent;
using vphone::FileExtentContext;
using vphone::FileExtentValidation;

namespace {

FileExtentContext ctx(std::uint64_t dstream_size) {
    FileExtentContext c{};
    c.dstream_size = dstream_size;
    c.block_size = 4096;
    c.block_count = 1000;
    c.allow_sparse = true;
    return c;
}

} // namespace

int main() {
    int failures = 0;
    const auto run = [&](
        const char* name,
        const std::vector<FileExtent>& extents,
        const FileExtentContext& c,
        bool expect_valid,
        const std::string& expect_error
    ) {
        const FileExtentValidation v =
            vphone::validate_file_extents(extents, c);
        bool ok = (v.valid == expect_valid);
        if (ok && !expect_valid) {
            ok = v.error.find(expect_error) != std::string::npos;
        }
        if (!ok) {
            std::fprintf(
                stderr, "FAIL %s : valid=%d error=%s expected=%s\n",
                name, static_cast<int>(v.valid),
                v.error.c_str(), expect_error.c_str());
            ++failures;
        } else {
            std::printf("%s\n", name);
        }
    };

    // --- positives ---

    // 1. Valid one extent covering the whole stream.
    run("FILE_EXTENT_ONE_VALID_PASS",
        {{0, 8192, 10}}, ctx(8192), true, "");

    // 2. Valid multiple contiguous extents.
    run("FILE_EXTENT_MULTI_CONTIGUOUS_PASS",
        {{0, 4096, 10}, {4096, 4096, 11}},
        ctx(8192), true, "");

    // 3. Valid explicit sparse extent (hole) accepted.
    run("FILE_EXTENT_SPARSE_HOLE_PASS",
        {{0, 4096, 10}, {4096, 2048, 0}, {6144, 2048, 11}},
        ctx(8192), true, "");

    // 4. Final extent clipped at dstream_size accepted.
    run("FILE_EXTENT_FINAL_CLIPPED_PASS",
        {{0, 9000, 10}}, ctx(8192), true, "");

    // --- negatives (exact reason) ---

    run("FILE_EXTENT_MISSING_CHAIN_REFUSED_PASS",
        {}, ctx(8192), false, "no FILE_EXTENT records");

    run("FILE_EXTENT_ZERO_LENGTH_REFUSED_PASS",
        {{0, 0, 10}}, ctx(8192), false, "zero-length extent");

    run("FILE_EXTENT_LEADING_GAP_REFUSED_PASS",
        {{100, 8092, 10}}, ctx(8192), false,
        "coverage gap at logical offset 0");

    run("FILE_EXTENT_MIDDLE_GAP_REFUSED_PASS",
        {{0, 4000, 10}, {5000, 3192, 11}},
        ctx(8192), false, "coverage gap");

    run("FILE_EXTENT_OVERLAP_REFUSED_PASS",
        {{0, 5000, 10}, {4000, 4192, 11}},
        ctx(8192), false, "overlap or duplicate start");

    run("FILE_EXTENT_DUPLICATE_START_REFUSED_PASS",
        {{0, 4096, 10}, {0, 4096, 11}},
        ctx(8192), false, "overlap or duplicate start");

    run(
        "FILE_EXTENT_LOGICAL_OVERFLOW_REFUSED_PASS",
        {{std::numeric_limits<std::uint64_t>::max() - 100,
          200, 10}},
        ctx(8192), false, "logical + length overflows");

    run("FILE_EXTENT_PHYS_BLOCK_OOB_REFUSED_PASS",
        {{0, 4096, 1000}}, ctx(8192), false,
        "physical block out of bounds");

    run("FILE_EXTENT_PHYS_RANGE_OOB_REFUSED_PASS",
        {{0, 8192, 999}}, ctx(8192), false,
        "physical range out of bounds");

    run(
        "FILE_EXTENT_PHYS_MUL_OVERFLOW_REFUSED_PASS",
        {{0, 4096,
          std::numeric_limits<std::uint64_t>::max() / 4096 + 1}},
        ctx(8192), false, "phys * block_size overflows");

    run("FILE_EXTENT_COVERAGE_INCOMPLETE_REFUSED_PASS",
        {{0, 4000, 10}}, ctx(8192), false,
        "coverage incomplete");

    run("FILE_EXTENT_AFTER_DSTREAM_REFUSED_PASS",
        {{9000, 100, 10}}, ctx(8192), false,
        "entirely after dstream_size");

    if (failures == 0) {
        std::printf("RESOURCEFORK_FILE_EXTENT_NEGATIVE_MATRIX_PASS\n");
        return 0;
    }
    std::fprintf(stderr, "FAILURES=%d\n", failures);
    return 1;
}