// Decmpfs type-4 (zlib resource fork) decoder, shared by
// apfs_reader.cpp and apfs_decmpfs_fixture_test.cpp so the test
// exercises the SAME code path as production.
//
// Reference layout (apfs-fuse ApfsLib/Decmpfs.cpp):
//   RsrcForkHeader {  // all big-endian u32
//     data_offset;    // offset of resource data in the RF stream
//     mgmt_offset;    // resource map offset
//     data_size;      // resource data length
//     mgmt_size;      // resource map length
//   };
//   At data_offset + 4: CmpfRsrc {  // all little-endian
//     entries;          // number of 64KiB compression units
//     entry[32] {       // per unit:
//       off;            // relative to cmpf_rsrc_base (LE u32)
//       size;           // compressed byte length (LE u32)
//     };
//   };
//   Each chunk: src[0]==0x78 -> zlib inflate; (src[0]&0x0F)==0x0F
//   -> stored bytes verbatim after the marker; otherwise fail.
//   Decoded size per unit: min(0x10000, logical_size - k*0x10000).

#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace vphone {

struct DecmpfsType4Entry {
    std::uint32_t off = 0;
    std::uint32_t size = 0;
};

struct DecmpfsType4Header {
    std::uint32_t data_offset = 0;
    std::uint32_t mgmt_offset = 0;
    std::uint32_t data_size = 0;
    std::uint32_t mgmt_size = 0;
};

// Parse the big-endian resource-fork header. Returns false when the
// stream is too short.
bool decmpfs_type4_parse_header(
    const std::vector<std::uint8_t>& rsrc,
    DecmpfsType4Header& out
);

// Parse the little-endian block table at data_offset + 4.
// Returns false on out-of-bounds table or invalid entry count.
bool decmpfs_type4_parse_block_table(
    const std::vector<std::uint8_t>& rsrc,
    const DecmpfsType4Header& header,
    std::vector<DecmpfsType4Entry>& entries,
    std::string& error
);

// Reconstruct the logical file bytes. Fail closed on:
//   - entry count != ceil(logical_size / 0x10000)
//   - chunk offset/size out of bounds or overlapping the table
//   - zero-length chunk
//   - invalid zlib stream or stored marker
//   - per-unit decoded size mismatch
//   - final decoded size mismatch with logical_size
bool decmpfs_type4_reconstruct(
    const std::vector<std::uint8_t>& rsrc,
    std::uint64_t logical_size,
    std::vector<std::uint8_t>& output,
    std::string& error
);

} // namespace vphone
