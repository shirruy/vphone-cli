#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace vphone {

struct ApfsContainerInfo {
    std::uint32_t block_size = 0;
    std::uint64_t block_count = 0;
    std::uint64_t omap_oid = 0;
};

struct ApfsVolumeInfo {
    std::uint64_t apsb_block = 0;
    std::uint64_t apsb_oid = 0;
    std::uint64_t xid = 0;
    std::uint64_t omap_block = 0;
    std::uint64_t root_tree_block = 0;
    std::string volume_name;
};

struct ApfsReaderReport {
    ApfsContainerInfo container;
    std::vector<ApfsVolumeInfo> volumes;
};

// Parse a raw APFS container image and resolve each volume superblock
// (APSB) through the container checkpoint area. Fails closed on invalid
// magic, impossible block geometry, or missing object headers.
bool apfs_read_container(
    const std::string& path,
    ApfsReaderReport& report,
    std::string& error
);

} // namespace vphone
