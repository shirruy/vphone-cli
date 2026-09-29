// Shared ResourceFork DATA_STREAM helpers used by apfs_reader.cpp
// (production) and the DATA_STREAM negative-matrix test.
//
// j_xattr_dstream { xattr_obj_id u64; j_dstream_t dstream; } is
// exactly 48 bytes; j_dstream_t is 40 bytes: size, alloced_size,
// default_crypto_id, total_bytes_written, total_bytes_read (u64 LE).

#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace vphone {

struct XattrDstreamInfo {
    bool valid = false;
    std::uint64_t xattr_obj_id = 0;
    std::uint64_t size = 0;
    std::uint64_t alloced_size = 0;
    std::uint64_t default_crypto_id = 0;
    std::uint64_t total_bytes_written = 0;
    std::uint64_t total_bytes_read = 0;
    std::string error;
};

// Parse the 48-byte descriptor strictly. Returns false with error on
// wrong size or impossible geometry.
XattrDstreamInfo decmpfs_parse_xattr_dstream(
    const std::vector<std::uint8_t>& xdata
);

// Classify the XATTR storage flags for the ResourceFork path.
// Accept only exact XATTR_DATA_STREAM (0x0001) or
// XATTR_DATA_EMBEDDED (0x0002); everything else is refused.
enum class XattrStorageMode {
    INVALID,
    DATA_STREAM,
    DATA_EMBEDDED,
};

XattrStorageMode decmpfs_classify_xattr_flags(
    std::uint16_t flags
);

} // namespace vphone
