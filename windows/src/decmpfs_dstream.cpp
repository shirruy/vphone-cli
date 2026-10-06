// Production ResourceFork DATA_STREAM descriptor helpers.
//
// The ResourceFork path in apfs_reader.cpp and the DATA_STREAM
// negative-matrix fixture test both call these functions so the
// tested code is the exact production parser.

#include "vphone/decmpfs_dstream.hpp"

namespace vphone {

static std::uint64_t read_le64_ds(const std::uint8_t* p) {
    return static_cast<std::uint64_t>(p[0]) |
           (static_cast<std::uint64_t>(p[1]) << 8) |
           (static_cast<std::uint64_t>(p[2]) << 16) |
           (static_cast<std::uint64_t>(p[3]) << 24) |
           (static_cast<std::uint64_t>(p[4]) << 32) |
           (static_cast<std::uint64_t>(p[5]) << 40) |
           (static_cast<std::uint64_t>(p[6]) << 48) |
           (static_cast<std::uint64_t>(p[7]) << 56);
}

XattrDstreamInfo decmpfs_parse_xattr_dstream(
    const std::vector<std::uint8_t>& xdata
) {
    XattrDstreamInfo out;
    if (xdata.size() != 48) {
        out.error =
            "DATA_STREAM descriptor size " +
            std::to_string(xdata.size()) + " != 48";
        return out;
    }
    out.xattr_obj_id = read_le64_ds(xdata.data());
    out.size = read_le64_ds(xdata.data() + 8);
    out.alloced_size = read_le64_ds(xdata.data() + 16);
    out.default_crypto_id = read_le64_ds(xdata.data() + 24);
    out.total_bytes_written = read_le64_ds(xdata.data() + 32);
    out.total_bytes_read = read_le64_ds(xdata.data() + 40);
    if (out.size > out.alloced_size) {
        out.error = "dstream.size > alloced_size";
        return out;
    }
    out.valid = true;
    return out;
}

XattrStorageMode decmpfs_classify_xattr_flags(
    std::uint16_t flags
) {
    if (flags == 0x0001) {
        return XattrStorageMode::DATA_STREAM;
    }
    if (flags == 0x0002) {
        return XattrStorageMode::DATA_EMBEDDED;
    }
    return XattrStorageMode::INVALID;
}

} // namespace vphone