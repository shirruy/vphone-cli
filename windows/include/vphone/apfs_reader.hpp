#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace vphone {

struct ApfsContainerInfo {
    std::uint32_t block_size = 0;
    std::uint64_t block_count = 0;
    std::uint64_t omap_oid = 0;
    // Active container checkpoint era from the NXSB object header.
    std::uint64_t nxsb_xid = 0;
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

    // Selected plist file reconstruction result.
    struct PlistFileResult {
        std::string status = "NOT_ATTEMPTED";
        std::string name;
        std::uint64_t drec_cnid = 0;
        std::uint64_t inode_cnid = 0;
        std::uint64_t private_id = 0;
        std::uint64_t file_size = 0;
        std::uint64_t extent_count = 0;
        std::string sha256;
        std::string format;
        std::vector<std::uint8_t> bytes;
        std::string error;
        // Decmpfs XATTR inspection (filled when compressed).
        bool decmpfs_found = false;
        std::uint16_t xattr_flags = 0;
        std::uint32_t decmpfs_signature = 0;
        std::uint32_t decmpfs_algo = 0;
        std::uint64_t decmpfs_logical_size = 0;
        bool xattr_embedded = false;
        bool needs_resource_fork = false;
        std::uint64_t owner_volume_index = 0;
        // Physical provenance from structural descent (for mutation).
        std::uint64_t xattr_leaf_paddr = 0;
        std::uint64_t xattr_key_off = 0;
        std::uint64_t xattr_val_off = 0;
        std::uint64_t xattr_data_start_off = 0; // plist bytes start
    } plist_file;
};

// Structural mutation result.
struct ApfsMutationResult {
    bool success = false;
    std::string error;
    // Era/identity chain.
    std::uint64_t apsb_block = 0;
    std::uint64_t apsb_oid = 0;
    std::uint64_t volume_xid = 0;
    std::uint64_t root_tree_oid = 0;
    std::uint64_t resolved_root_block = 0;
    std::uint64_t target_cnid = 0;
    std::uint64_t target_leaf_block = 0;
    // Mutation details.
    std::uint64_t data_offset_in_block = 0;
    std::uint8_t old_byte = 0;
    std::uint8_t new_byte = 0;
    std::string old_plist_sha256;
    std::string new_plist_sha256;
    std::string old_block_checksum;
    std::string new_block_checksum;
    // Physical provenance from structural descent.
    std::uint64_t xattr_key_off_in_leaf = 0;
    std::uint64_t xattr_val_off_in_leaf = 0;
    // Certified reread verification.
    std::string reread_plist_sha256;
    bool reread_verified = false;
};

// Structural single-byte mutation: source → output, certified chain.
// Source image is NEVER opened for writing. Output must be a
// distinct copied image. The mutation resolves the target through
// APSB/xid → OMAP → FSTREE structural descent, derives the exact
// TOC/XATTR value pointer, and verifies post-write via certified
// reread of the output image.
bool apfs_mutate_plist_byte_safe(
    const std::string& source_image_path,
    const std::string& output_image_path,
    const std::string& expected_source_sha256,
    std::uint64_t target_cnid,
    std::uint64_t plist_byte_offset,
    std::uint8_t expected_old_byte,
    std::uint8_t new_byte,
    ApfsMutationResult& result,
    std::string& error
);

// Legacy in-place variant (refuses if source == output).
// Kept for backward compatibility but prefer the safe API.
// Refuses to write when any precondition differs.
bool apfs_mutate_plist_byte(
    const std::string& image_path,
    const std::string& expected_source_sha256,
    std::uint64_t target_cnid,
    std::uint64_t plist_byte_offset,
    std::uint8_t expected_old_byte,
    std::uint8_t new_byte,
    ApfsMutationResult& result,
    std::string& error
);

// Parse a raw APFS container image and resolve each volume superblock
// (APSB) through the container checkpoint area. Fails closed on invalid
// magic, impossible block geometry, or missing object headers.
bool apfs_read_container(
    const std::string& path,
    ApfsReaderReport& report,
    std::string& error
);

} // namespace vphone
