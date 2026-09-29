// Mach-O structural validator shared by apfs_reader.cpp (production
// fail-closed gate) and the fixture tests. Supports:
//   - thin Mach-O (little-endian, 32/64): magic, cputype,
//     cpusubtype, filetype, ncmds, sizeofcmds, flags, header size,
//     every load_command cmdsize >= 8 and within bounds.
//   - FAT (big-endian raw magic 0xcafebabe): 20-byte fat_arch
//     entries, u32 offset/size.
//   - FAT64 (big-endian raw magic 0xcafebabf): 32-byte fat_arch_64
//     entries, u64 offset/size.
// Swapped FAT variants are explicitly unsupported (refused).

#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace vphone {

struct MachOValidationResult {
    bool valid = false;
    // Thin-Mach-O identity fields (0 for FAT containers).
    bool is_thin = false;
    bool is_64 = false;
    std::uint32_t cputype = 0;
    std::uint32_t cpusubtype = 0;
    std::uint32_t filetype = 0;
    std::uint32_t ncmds = 0;
    std::uint32_t sizeofcmds = 0;
    std::uint32_t flags = 0;
    // FAT container stats.
    bool is_fat = false;
    bool is_fat64 = false;
    std::uint32_t nfat = 0;
    std::string error;
};

// Validate a reconstructed Mach-O/FAT container. Fail closed on any
// malformed structure; record identity fields for thin binaries.
MachOValidationResult macho_validate(
    const std::vector<std::uint8_t>& bytes
);

} // namespace vphone
