// Decmpfs type-4 (zlib resource fork) REAL fixture matrix.
//
// Builds synthetic resource forks with the reference layout
// (apfs-fuse ApfsLib/Decmpfs.cpp) and exercises the SHARED
// decmpfs_type4_reconstruct() decoder used by apfs_reader.cpp.
//
// Layout:
//   RsrcForkHeader { data_offset, mgmt_offset, data_size,
//                    mgmt_size }      (BE u32 each)
//   data_offset points at: [resource-data length u32 LE]
//                          [block count u32 LE]
//                          [entries: off LE, size LE]*
//                          [compressed chunks...]

#include "vphone/decmpfs_type4.hpp"

#include <zlib.h>

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

namespace {

void put_be32(
    std::vector<std::uint8_t>& b, std::size_t off,
    std::uint32_t v
) {
    b[off] = static_cast<std::uint8_t>(v >> 24);
    b[off + 1] = static_cast<std::uint8_t>(v >> 16);
    b[off + 2] = static_cast<std::uint8_t>(v >> 8);
    b[off + 3] = static_cast<std::uint8_t>(v);
}

void put_le32(
    std::vector<std::uint8_t>& b, std::size_t off,
    std::uint32_t v
) {
    b[off] = static_cast<std::uint8_t>(v);
    b[off + 1] = static_cast<std::uint8_t>(v >> 8);
    b[off + 2] = static_cast<std::uint8_t>(v >> 16);
    b[off + 3] = static_cast<std::uint8_t>(v >> 24);
}

bool zlib_compress_chunk(
    const std::vector<std::uint8_t>& plain,
    std::vector<std::uint8_t>& out
) {
    uLongf dest_len = compressBound(
        static_cast<uLong>(plain.size()));
    out.resize(dest_len);
    const int rc = compress2(
        out.data(), &dest_len, plain.data(),
        static_cast<uLong>(plain.size()),
        Z_DEFAULT_COMPRESSION);
    if (rc != Z_OK) {
        return false;
    }
    out.resize(dest_len);
    return true;
}

// Build a valid type-4 resource fork from plaintext chunks.
bool build_type4_rsrc(
    const std::vector<std::vector<std::uint8_t>>& plain_chunks,
    std::vector<std::uint8_t>& out
) {
    const std::size_t n = plain_chunks.size();
    // Header: data_offset = 16 (right after header). The data area
    // holds [res_len u32][count u32][table][chunks].
    const std::size_t data_offset = 16;
    const std::size_t table_size = 4 + 4 + n * 8;

    out.assign(data_offset + table_size, 0);

    // Compress chunks, lay them after the table.
    std::vector<std::vector<std::uint8_t>> comps(n);
    // cmpf_rsrc_base = data_offset + 4; chunk offsets are relative
    // to that base, matching apfs-fuse Decmpfs.cpp.
    std::size_t cursor = out.size() - (data_offset + 4);
    for (std::size_t i = 0; i < n; ++i) {
        if (!zlib_compress_chunk(plain_chunks[i], comps[i])) {
            return false;
        }
    }
    for (std::size_t i = 0; i < n; ++i) {
        put_le32(
            out, data_offset + 4 + 4 + i * 8,
            static_cast<std::uint32_t>(cursor));
        put_le32(
            out, data_offset + 4 + 4 + i * 8 + 4,
            static_cast<std::uint32_t>(comps[i].size()));
        cursor += comps[i].size();
    }
    for (const auto& c : comps) {
        out.insert(out.end(), c.begin(), c.end());
    }

    const std::size_t res_len_pos = data_offset;
    // Resource-data length: everything after data_offset, including
    // the length field itself and the table and chunks.
    const std::uint32_t res_len =
        static_cast<std::uint32_t>(out.size() - data_offset);
    // res_len field at data_offset; count at data_offset+4.
    put_le32(out, res_len_pos, res_len);
    put_le32(
        out, data_offset + 4,
        static_cast<std::uint32_t>(n));

    put_be32(out, 0, static_cast<std::uint32_t>(data_offset));
    put_be32(out, 4, 0); // mgmt_offset
    put_be32(out, 8, res_len); // data_size = resource data length
    put_be32(out, 12, 0); // mgmt_size
    return true;
}

struct CaseResult {
    bool ok = false;
    std::string error;
};

} // namespace

int main() {
    int failures = 0;

    // Fixture helper: 1..3 chunks of patterned data.
    const auto make_chunks = [](std::size_t n, std::size_t per) {
        std::vector<std::vector<std::uint8_t>> chunks(n);
        for (std::size_t i = 0; i < n; ++i) {
            chunks[i].resize(per);
            for (std::size_t j = 0; j < per; ++j) {
                chunks[i][j] = static_cast<std::uint8_t>(
                    (i * 31 + j * 7 + 5) & 0xff);
            }
        }
        return chunks;
    };

    // 1. Valid one-chunk.
    {
        auto chunks = make_chunks(1, 4096);
        std::vector<std::uint8_t> rsrc, out;
        std::string error;
        if (!build_type4_rsrc(chunks, rsrc)) {
            ++failures;
        } else if (!vphone::decmpfs_type4_reconstruct(
                       rsrc, 4096, out, error) ||
                   out.size() != 4096 ||
                   out != chunks[0]) {
            std::fprintf(
                stderr, "[1] one-chunk failed: %s\n",
                error.c_str());
            ++failures;
        } else {
            std::printf("DECMPFS_TYPE4_ONE_CHUNK_PASS\n");
        }
    }

    // 2. Valid multi-chunk (2 x 64KiB + tail).
    {
        auto a = make_chunks(1, 0x10000)[0];
        auto b = make_chunks(1, 0x10000)[0];
        std::vector<std::uint8_t> c(1000, 0x42);
        std::vector<std::uint8_t> rsrc, out;
        std::string error;
        if (!build_type4_rsrc({a, b, c}, rsrc)) {
            ++failures;
        } else if (!vphone::decmpfs_type4_reconstruct(
                       rsrc, 0x10000 + 0x10000 + 1000,
                       out, error)) {
            std::fprintf(
                stderr, "[2] multi-chunk failed: %s\n",
                error.c_str());
            ++failures;
        } else {
            std::printf("DECMPFS_TYPE4_MULTI_CHUNK_PASS\n");
        }
    }

    // 3. Wrong block count.
    {
        auto chunks = make_chunks(1, 4096);
        std::vector<std::uint8_t> rsrc, out;
        std::string error;
        if (!build_type4_rsrc(chunks, rsrc)) {
            ++failures;
        } else {
            // corrupt the count to 2
            put_le32(rsrc, 20, 2);
            if (vphone::decmpfs_type4_reconstruct(
                    rsrc, 4096, out, error)) {
                std::fprintf(
                    stderr, "[3] wrong count accepted\n");
                ++failures;
            } else {
                std::printf(
                    "DECMPFS_TYPE4_WRONG_COUNT_REFUSED_PASS\n");
            }
        }
    }

    // 4. Out-of-bounds chunk offset.
    {
        auto chunks = make_chunks(1, 4096);
        std::vector<std::uint8_t> rsrc, out;
        std::string error;
        if (!build_type4_rsrc(chunks, rsrc)) {
            ++failures;
        } else {
            put_le32(rsrc, 28, 0xFFFFFFu);
            if (vphone::decmpfs_type4_reconstruct(
                    rsrc, 4096, out, error)) {
                std::fprintf(
                    stderr, "[4] OOB offset accepted\n");
                ++failures;
            } else {
                std::printf(
                    "DECMPFS_TYPE4_OOB_OFFSET_REFUSED_PASS\n");
            }
        }
    }

    // 5. Corrupt zlib chunk.
    {
        auto chunks = make_chunks(1, 4096);
        std::vector<std::uint8_t> rsrc, out;
        std::string error;
        if (!build_type4_rsrc(chunks, rsrc)) {
            ++failures;
        } else {
            rsrc[rsrc.size() - 2] ^= 0xFF;
            if (vphone::decmpfs_type4_reconstruct(
                    rsrc, 4096, out, error)) {
                std::fprintf(
                    stderr, "[5] corrupt chunk accepted\n");
                ++failures;
            } else {
                std::printf(
                    "DECMPFS_TYPE4_CORRUPT_CHUNK_REFUSED_PASS\n");
            }
        }
    }

    // 6. Final logical-size mismatch.
    {
        auto chunks = make_chunks(1, 4096);
        std::vector<std::uint8_t> rsrc, out;
        std::string error;
        if (!build_type4_rsrc(chunks, rsrc)) {
            ++failures;
        } else if (vphone::decmpfs_type4_reconstruct(
                       rsrc, 5000, out, error)) {
            std::fprintf(
                stderr, "[6] size mismatch accepted\n");
            ++failures;
        } else {
            std::printf(
                "DECMPFS_TYPE4_SIZE_MISMATCH_REFUSED_PASS\n");
        }
    }

    // 7. Truncated header.
    {
        std::vector<std::uint8_t> tiny(8, 0);
        std::vector<std::uint8_t> out;
        std::string error;
        if (vphone::decmpfs_type4_reconstruct(
                tiny, 100, out, error)) {
            std::fprintf(
                stderr, "[7] truncated header accepted\n");
            ++failures;
        } else {
            std::printf(
                "DECMPFS_TYPE4_TRUNCATED_HEADER_REFUSED_PASS\n");
        }
    }

    // 8. Zero-length chunk.
    {
        auto chunks = make_chunks(1, 4096);
        std::vector<std::uint8_t> rsrc, out;
        std::string error;
        if (!build_type4_rsrc(chunks, rsrc)) {
            ++failures;
        } else {
            put_le32(rsrc, 32, 0);
            if (vphone::decmpfs_type4_reconstruct(
                    rsrc, 4096, out, error)) {
                std::fprintf(
                    stderr, "[8] zero-length chunk accepted\n");
                ++failures;
            } else {
                std::printf(
                    "DECMPFS_TYPE4_ZERO_CHUNK_REFUSED_PASS\n");
            }
        }
    }

    // 9. Valid stored/raw chunk (marker 0xFF + verbatim bytes).
    {
        // Build a custom RF with one stored chunk: byte 0xFF followed
        // by 4096 data bytes (marker 0xFF has low nibble 0x0F).
        std::vector<std::uint8_t> plain(4096, 0x5A);
        std::vector<std::uint8_t> rsrc(16 + 16, 0);
        // stored chunk: 1 marker + 4096 bytes at table_end.
        const std::size_t table_end = 16 + 16;
        rsrc.resize(table_end + 1 + plain.size());
        rsrc[table_end] = 0xFF;
        std::memcpy(
            rsrc.data() + table_end + 1,
            plain.data(), plain.size());
        put_le32(rsrc, 16, 4097); // res_len
        put_le32(rsrc, 20, 1); // count
        // chunk off is relative to cmpf_rsrc_base (data_offset+4).
        // chunk starts at table_end (28); base = 16+4 = 20.
        put_le32(rsrc, 24, table_end - 20);
        put_le32(rsrc, 28, 1 + 4096); // chunk size
        put_be32(rsrc, 0, 16); // data_offset
        put_be32(
            rsrc, 8,
            static_cast<std::uint32_t>(
                table_end + 1 + plain.size() - 16));
        std::vector<std::uint8_t> out;
        std::string error;
        if (!vphone::decmpfs_type4_reconstruct(
                rsrc, plain.size(), out, error) ||
            out != plain) {
            std::fprintf(
                stderr, "[9] stored chunk failed: %s\n",
                error.c_str());
            ++failures;
        } else {
            std::printf("DECMPFS_TYPE4_STORED_CHUNK_PASS\n");
        }
    }

    // 10. Wrong-endian data_offset (BE bytes swapped) refused.
    {
        auto chunks = make_chunks(1, 4096);
        std::vector<std::uint8_t> rsrc, out;
        std::string error;
        if (!build_type4_rsrc(chunks, rsrc)) {
            ++failures;
        } else {
            // corrupt data_offset to a swapped value that is OOB
            put_be32(rsrc, 0, 0xFFFF0000u);
            if (vphone::decmpfs_type4_reconstruct(
                    rsrc, 4096, out, error)) {
                std::fprintf(
                    stderr, "[10] wrong-endian offset accepted\n");
                ++failures;
            } else {
                std::printf(
                    "DECMPFS_TYPE4_WRONG_ENDIAN_OFFSET_REFUSED_PASS\n");
            }
        }
    }

    // 11. Truncated block table refused.
    {
        auto chunks = make_chunks(3, 4096);
        std::vector<std::uint8_t> rsrc, out;
        std::string error;
        if (!build_type4_rsrc(chunks, rsrc)) {
            ++failures;
        } else {
            // shrink data_size so the table is cut off
            put_be32(rsrc, 8, 20);
            if (vphone::decmpfs_type4_reconstruct(
                    rsrc, 4096 * 3, out, error)) {
                std::fprintf(
                    stderr, "[11] truncated table accepted\n");
                ++failures;
            } else {
                std::printf(
                    "DECMPFS_TYPE4_TRUNCATED_TABLE_REFUSED_PASS\n");
            }
        }
    }

    // 12. Overlapping chunks refused.
    {
        auto a = make_chunks(1, 0x10000)[0];
        auto b = make_chunks(1, 1000)[0];
        std::vector<std::uint8_t> rsrc, out;
        std::string error;
        if (!build_type4_rsrc({a, b}, rsrc)) {
            ++failures;
        } else {
            // True chunk-to-chunk overlap: both chunks start after
            // the block table, but chunk 1 starts inside chunk 0's
            // range. Chunk 0 starts at entry off; force chunk 1 to
            // start one byte before chunk 0's end.
            // Read chunk0's offset+size from the table.
            const std::uint32_t c0_off =
                [&]() {
                    std::uint32_t v = 0;
                    v |= rsrc[16 + 4 + 4 + 0];
                    v |= static_cast<std::uint32_t>(
                        rsrc[16 + 4 + 4 + 1]) << 8;
                    v |= static_cast<std::uint32_t>(
                        rsrc[16 + 4 + 4 + 2]) << 16;
                    v |= static_cast<std::uint32_t>(
                        rsrc[16 + 4 + 4 + 3]) << 24;
                    return v;
                }();
            const std::uint32_t c0_size =
                [&]() {
                    std::uint32_t v = 0;
                    v |= rsrc[16 + 4 + 4 + 4];
                    v |= static_cast<std::uint32_t>(
                        rsrc[16 + 4 + 4 + 5]) << 8;
                    v |= static_cast<std::uint32_t>(
                        rsrc[16 + 4 + 4 + 6]) << 16;
                    v |= static_cast<std::uint32_t>(
                        rsrc[16 + 4 + 4 + 7]) << 24;
                    return v;
                }();
            // chunk1.start = chunk0.start + chunk0.size - 1
            const std::uint32_t c1_off =
                c0_off + c0_size - 1;
            put_le32(rsrc, 16 + 4 + 4 + 8, c1_off);
            if (vphone::decmpfs_type4_reconstruct(
                    rsrc, 0x10000 + 1000, out, error)) {
                std::fprintf(
                    stderr,
                    "[12] true chunk overlap accepted: %s\n",
                    error.c_str());
                ++failures;
            } else {
                std::printf(
                    "DECMPFS_TYPE4_TRUE_CHUNK_OVERLAP_REFUSED_PASS\n");
            }
        }
    }

    // 13. Management-region geometry: mgmt_offset=0 with nonzero
    //     mgmt_size must be refused.
    {
        auto chunks = make_chunks(1, 4096);
        std::vector<std::uint8_t> rsrc, out;
        std::string error;
        if (!build_type4_rsrc(chunks, rsrc)) {
            ++failures;
        } else {
            put_be32(rsrc, 12, 64); // mgmt_size with mgmt_offset=0
            if (vphone::decmpfs_type4_reconstruct(
                    rsrc, 4096, out, error)) {
                std::fprintf(
                    stderr, "[13] inconsistent mgmt accepted\n");
                ++failures;
            } else {
                std::printf(
                    "DECMPFS_TYPE4_MANAGEMENT_REGION_GEOMETRY_PASS\n");
            }
        }
    }

    if (failures == 0) {
        std::printf("DECMPFS_TYPE4_REAL_FIXTURE_MATRIX_PASS\n");
        return 0;
    }
    std::fprintf(stderr, "FAILURES=%d\n", failures);
    return 1;
}
