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
    // Rooted checkpoint authority provenance.
    std::uint64_t checkpoint_map_block = 0;
    std::uint64_t container_omap_phys_block = 0;
    std::uint64_t container_omap_tree_root_block = 0;
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

// Parsed B-tree leaf geometry for variable-KV records.
struct ApfsLeafGeometry {
    bool valid = false;
    std::uint64_t leaf_paddr = 0;
    std::uint32_t block_size = 0;
    std::uint16_t node_flags = 0;
    std::uint16_t node_level = 0;
    std::uint32_t nkeys = 0;
    std::uint16_t table_space_off = 0;
    std::uint16_t table_space_len = 0;
    // Variable-KV TOC entries are 8 bytes.
    std::uint16_t toc_entry_size = 8;
    std::uint64_t key_base = 0;
    std::uint64_t value_base = 0;
    bool has_root_footer = false;
    std::uint64_t footer_offset = 0;
    // Per-record parsed geometry (index parallel to TOC).
    struct RecordSpan {
        std::uint16_t key_off = 0;
        std::uint16_t key_len = 0;
        std::uint16_t val_off = 0;
        std::uint16_t val_len = 0;
        std::uint64_t abs_key_start = 0;
        std::uint64_t abs_key_end = 0;
        std::uint64_t abs_val_start = 0;
        std::uint64_t abs_val_end = 0;
    };
    std::vector<RecordSpan> records;
    // Derived free space (from geometry, not zero bytes).
    std::uint64_t packed_values_start = 0;
    std::uint64_t key_region_end = 0;
    std::uint64_t free_bytes = 0;
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

// Full plist payload replacement (same-size only for this gate):
// replaces the entire embedded decmpfs PLAIN_ATTR payload with new
// bytes of EXACTLY the same length, updates the decmpfs logical
// size field if needed, reseals the leaf Fletcher-64 checksum, and
// verifies via certified reread. Preserves all single-byte-gate
// invariants: rooted authority, source→output isolation, file
// identity safety, provenance, and fail-closed behavior.
bool apfs_replace_plist_payload_safe(
    const std::string& source_image_path,
    const std::string& output_image_path,
    const std::string& expected_source_sha256,
    std::uint64_t target_cnid,
    const std::vector<std::uint8_t>& new_payload,
    ApfsMutationResult& result,
    std::string& error
);

// Test seam variant: invokes the callback after the source→output
// copy but before the pre-write provenance reread, allowing tests
// to tamper with the copied output and prove the function fails
// closed on provenance mismatch. Production code must use the
// non-callback variant.
bool apfs_replace_plist_payload_safe_with_hook(
    const std::string& source_image_path,
    const std::string& output_image_path,
    const std::string& expected_source_sha256,
    std::uint64_t target_cnid,
    const std::vector<std::uint8_t>& new_payload,
    void (*post_copy_hook)(const std::string& output_path),
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

// Parse variable-KV B-tree leaf geometry from a raw block.
// Derives all offsets, spans, boundaries, and free space from the
// actual TOC/record layout — never from zero bytes. Fails closed
// on fixed-KV nodes, level != 0, or malformed geometry.
bool apfs_parse_leaf_geometry(
    const std::vector<std::uint8_t>& leaf_block,
    std::uint64_t leaf_paddr,
    ApfsLeafGeometry& out,
    std::string& error
);

// Leaf-local reflow: replace one variable-KV record's value with a
// different-sized value by repacking ALL values deterministically
// from value_base backward. Keys, TOC key fields, nkeys, and node
// identity are preserved. Returns the new leaf block.
// Fails closed on: insufficient space, overlap, unsupported layout.
bool apfs_reflow_leaf_value(
    const std::vector<std::uint8_t>& old_leaf,
    std::uint32_t target_toc_index,
    const std::vector<std::uint8_t>& new_value,
    std::vector<std::uint8_t>& new_leaf,
    ApfsLeafGeometry& geometry_out,
    std::string& error
);

// Size-changing embedded decmpfs plist replacement. Supports
// grow, shrink, and same-size through leaf-local reflow when the
// resized value fits within the target leaf's derived capacity.
// Fails closed on insufficient space, malformed geometry, or
// provenance mismatch. Preserves all single-byte-gate invariants.
bool apfs_resize_plist_payload_safe(
    const std::string& source_image_path,
    const std::string& output_image_path,
    const std::string& expected_source_sha256,
    std::uint64_t target_cnid,
    const std::vector<std::uint8_t>& new_payload,
    ApfsMutationResult& result,
    std::string& error
);

} // namespace vphone
