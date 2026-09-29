// Shared FILE_EXTENT geometry validator used by apfs_reader.cpp
// (production reconstruction and ResourceFork DATA_STREAM paths) and
// by the FILE_EXTENT negative-matrix test. The tested code is the
// exact production validation logic; tests do not mirror it.

#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace vphone {

struct FileExtent {
    std::uint64_t logical = 0;
    std::uint64_t length = 0;
    std::uint64_t phys = 0; // 0 == explicit sparse/hole extent
};

struct FileExtentContext {
    std::uint64_t dstream_size = 0;
    std::uint64_t block_size = 0;
    std::uint64_t block_count = 0;
    // Physical block -> byte multiplication must not overflow.
    bool allow_sparse = true;
};

struct FileExtentValidation {
    bool valid = false;
    bool complete = false; // full [0, dstream_size) covered
    std::string error;
};

// Validate an unsorted FILE_EXTENT list against dstream geometry.
// Checks (in production order):
//   - non-empty chain
//   - zero-length extent refusal
//   - logical + length overflow
//   - physical block OOB, physical range OOB (overflow-safe blocks
//     arithmetic, no phys*block_size multiplication overflow)
//   - duplicate logical starts / extent overlap
//   - leading/middle logical gaps
//   - extents wholly after dstream_size refused
//   - final extent allowed to be clipped at dstream_size
//   - incomplete coverage refusal
FileExtentValidation validate_file_extents(
    const std::vector<FileExtent>& extents,
    const FileExtentContext& ctx
);

} // namespace vphone