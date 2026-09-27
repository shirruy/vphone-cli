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

struct ApfsBtreeNodeInfo {
    std::uint16_t flags = 0;
    std::uint16_t level = 0;
    std::uint32_t nkeys = 0;
    // Decoded btree_info_t footer (root nodes only).
    bool has_footer = false;
    std::uint32_t bt_flags = 0;
    std::uint32_t node_size = 0;
    std::uint32_t key_size = 0;
    std::uint32_t val_size = 0;
};

struct ApfsOmapEntry {
    std::uint64_t oid = 0;
    std::uint64_t xid = 0;
    std::uint64_t paddr = 0;
    std::uint32_t size = 0;
    std::uint32_t flags = 0;
};

struct ApfsVolumeInfo {
    std::uint64_t apsb_block = 0;
    std::uint64_t apsb_oid = 0;
    std::uint64_t xid = 0;
    std::uint64_t omap_block = 0;
    std::uint64_t root_tree_oid = 0;
    std::uint64_t extentref_tree_oid = 0;
    std::uint64_t root_tree_block = 0;
    ApfsBtreeNodeInfo root_tree_info;
    std::string volume_name;
};

struct ApfsReaderReport {
    ApfsContainerInfo container;
    std::vector<ApfsVolumeInfo> volumes;
    // Structural path resolution result (empty when unresolved).
    std::string launchdaemons_status = "NOT_RESOLVED";
    std::uint64_t launchdaemons_cnid = 0;
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
