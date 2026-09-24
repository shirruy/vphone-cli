#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <utility>
#include <vector>

namespace vphone {

inline constexpr std::size_t kApfsSnapshotBlockSize = 4096;
inline constexpr const char* kApfsSnapshotOldPrefix = "com.apple.os.update-";
inline constexpr const char* kApfsSnapshotDefaultNewPrefix = "orig-fs.disabled.rn-";

struct ApfsSnapshotReport {
    std::string snapshot_name;
    std::vector<std::pair<std::uint64_t, std::vector<std::size_t>>> blocks;

    std::size_t record_count() const;
    bool empty() const;
};

std::uint64_t apfs_snapshot_checksum(const std::uint8_t* block, std::size_t size);
bool apfs_snapshot_block_valid(const std::uint8_t* block, std::size_t size);

bool apfs_snapshot_scan_buffer(
    const std::uint8_t* data,
    std::size_t size,
    std::uint64_t base_offset,
    ApfsSnapshotReport& report,
    std::string& error
);

bool apfs_snapshot_rename_file(
    const std::string& path,
    const std::string& new_prefix,
    bool dry_run,
    ApfsSnapshotReport& report,
    std::string& error
);

} // namespace vphone
