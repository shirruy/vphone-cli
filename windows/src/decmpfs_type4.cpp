#include "vphone/decmpfs_type4.hpp"

#include <zlib.h>

#include <cstring>

namespace vphone {

namespace {

std::uint32_t read_be32(const std::uint8_t* p) {
    return (static_cast<std::uint32_t>(p[0]) << 24) |
           (static_cast<std::uint32_t>(p[1]) << 16) |
           (static_cast<std::uint32_t>(p[2]) << 8) |
           static_cast<std::uint32_t>(p[3]);
}

std::uint32_t read_le32(const std::uint8_t* p) {
    return static_cast<std::uint32_t>(p[0]) |
           (static_cast<std::uint32_t>(p[1]) << 8) |
           (static_cast<std::uint32_t>(p[2]) << 16) |
           (static_cast<std::uint32_t>(p[3]) << 24);
}

} // namespace

bool decmpfs_type4_parse_header(
    const std::vector<std::uint8_t>& rsrc,
    DecmpfsType4Header& out
) {
    if (rsrc.size() < 16) {
        return false;
    }
    out.data_offset = read_be32(rsrc.data());
    out.mgmt_offset = read_be32(rsrc.data() + 4);
    out.data_size = read_be32(rsrc.data() + 8);
    out.mgmt_size = read_be32(rsrc.data() + 12);
    return true;
}

bool decmpfs_type4_parse_block_table(
    const std::vector<std::uint8_t>& rsrc,
    const DecmpfsType4Header& header,
    std::vector<DecmpfsType4Entry>& entries,
    std::string& error
) {
    entries.clear();

    // The block table sits at data_offset + 4 (after a 4-byte
    // resource-data length field in the reference layout).
    const std::uint64_t table_base =
        static_cast<std::uint64_t>(header.data_offset) + 4;
    if (table_base + 4 > rsrc.size()) {
        error = "block table base out of bounds";
        return false;
    }
    const std::uint32_t entry_count =
        read_le32(rsrc.data() + table_base);
    if (entry_count > 4096) {
        error = "implausible block count";
        return false;
    }
    const std::uint64_t table_bytes =
        static_cast<std::uint64_t>(entry_count) * 8;
    if (table_base + 4 + table_bytes > rsrc.size()) {
        error = "block table truncated";
        return false;
    }
    entries.resize(entry_count);
    for (std::uint32_t i = 0; i < entry_count; ++i) {
        const std::uint64_t e = table_base + 4 +
            static_cast<std::uint64_t>(i) * 8;
        entries[i].off = read_le32(rsrc.data() + e);
        entries[i].size = read_le32(rsrc.data() + e + 4);
    }
    return true;
}

bool decmpfs_type4_reconstruct(
    const std::vector<std::uint8_t>& rsrc,
    std::uint64_t logical_size,
    std::vector<std::uint8_t>& output,
    std::string& error
) {
    output.clear();

    DecmpfsType4Header header{};
    if (!decmpfs_type4_parse_header(rsrc, header)) {
        error = "resource-fork header too short";
        return false;
    }
    if (header.data_offset > rsrc.size()) {
        error = "data_offset exceeds resource fork";
        return false;
    }

    std::vector<DecmpfsType4Entry> entries;
    if (!decmpfs_type4_parse_block_table(
            rsrc, header, entries, error)) {
        return false;
    }

    // Reconcile entry count with logical size (64KiB units).
    const std::uint64_t expected_chunks =
        (logical_size + 0xFFFF) / 0x10000;
    if (entries.size() != expected_chunks) {
        error = "block count mismatch: declared=" +
            std::to_string(entries.size()) +
            " expected=" + std::to_string(expected_chunks);
        return false;
    }

    const std::uint64_t table_base =
        static_cast<std::uint64_t>(header.data_offset) + 4;
    const std::uint64_t table_end =
        table_base + 4 + entries.size() * 8;

    output.resize(
        (logical_size + 0xFFFF) & ~static_cast<std::uint64_t>(0xFFFF),
        0);

    for (std::uint64_t k = 0; k < entries.size(); ++k) {
        const auto& entry = entries[k];
        std::uint64_t expected_len =
            logical_size - (0x10000 * k);
        if (expected_len > 0x10000) {
            expected_len = 0x10000;
        }
        if (entry.size == 0) {
            error = "zero-length chunk";
            return false;
        }
        if (entry.size > 0x10001) {
            error = "chunk size exceeds 64KiB+marker";
            return false;
        }
        const std::uint64_t src_off =
            table_base + static_cast<std::uint64_t>(entry.off);
        if (src_off < table_end) {
            error = "chunk overlaps block table";
            return false;
        }
        if (src_off > rsrc.size() ||
            entry.size > rsrc.size() - src_off) {
            error = "chunk out of bounds";
            return false;
        }
        const std::uint8_t* src = rsrc.data() + src_off;
        std::uint8_t* dst = output.data() + 0x10000 * k;
        std::uint64_t decoded_bytes = 0;

        if (src[0] == 0x78) {
            // zlib stream.
            uLongf dest_len =
                static_cast<uLongf>(0x10000);
            const int rc = uncompress(
                dst, &dest_len, src,
                static_cast<uLong>(entry.size));
            if (rc != Z_OK) {
                error = "zlib inflate failed";
                return false;
            }
            decoded_bytes = dest_len;
        } else if ((src[0] & 0x0F) == 0x0F) {
            // Stored bytes after the 1-byte marker.
            std::memcpy(dst, src + 1, entry.size - 1);
            decoded_bytes = entry.size - 1;
        } else {
            error = "unknown chunk marker";
            return false;
        }

        if (decoded_bytes != expected_len) {
            error =
                "chunk decoded size mismatch: " +
                std::to_string(decoded_bytes) +
                " != " + std::to_string(expected_len);
            return false;
        }
    }

    output.resize(logical_size);
    return true;
}

} // namespace vphone
