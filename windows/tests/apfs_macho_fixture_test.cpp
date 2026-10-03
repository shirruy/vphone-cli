// Mach-O structural validation fixture matrix using the SHARED
// production validator (vphone::macho_validate).
//
// Covers: valid thin 64, valid FAT32 with real thin slices, valid
// FAT64 with real thin slices, truncated FAT table, slice OOB,
// overlapping slices, zero-size slice, zero architectures, slice
// overlapping FAT metadata, swapped FAT, nested FAT, garbage slice,
// bad-magic slice, malformed-load-command slice, and a thin
// load-command-bounds violation.

#include "vphone/macho_validate.hpp"

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

namespace {

void put_le32(
    std::vector<std::uint8_t>& b, std::size_t off,
    std::uint32_t v
) {
    b[off] = static_cast<std::uint8_t>(v);
    b[off + 1] = static_cast<std::uint8_t>(v >> 8);
    b[off + 2] = static_cast<std::uint8_t>(v >> 16);
    b[off + 3] = static_cast<std::uint8_t>(v >> 24);
}

void put_be32(
    std::vector<std::uint8_t>& b, std::size_t off,
    std::uint32_t v
) {
    b[off] = static_cast<std::uint8_t>(v >> 24);
    b[off + 1] = static_cast<std::uint8_t>(v >> 16);
    b[off + 2] = static_cast<std::uint8_t>(v >> 8);
    b[off + 3] = static_cast<std::uint8_t>(v);
}

void put_be64(
    std::vector<std::uint8_t>& b, std::size_t off,
    std::uint64_t v
) {
    put_be32(b, off, static_cast<std::uint32_t>(v >> 32));
    put_be32(b, off + 4, static_cast<std::uint32_t>(v));
}

// Minimal valid thin arm64 Mach-O: 32-byte header + one LC_SEGMENT_64
// load command (72 bytes).
std::vector<std::uint8_t> make_thin64() {
    std::vector<std::uint8_t> b(32 + 72, 0);
    put_le32(b, 0, 0xfeedfacfu); // MH_MAGIC_64
    put_le32(b, 4, 0x0100000Cu); // CPU_TYPE_ARM64
    put_le32(b, 8, 0);           // cpusubtype
    put_le32(b, 12, 2);          // MH_EXECUTE
    put_le32(b, 16, 1);          // ncmds
    put_le32(b, 20, 72);         // sizeofcmds
    put_le32(b, 24, 0);          // flags
    // LC_SEGMENT_64 at offset 32.
    put_le32(b, 32, 0x19);       // LC_SEGMENT_64
    put_le32(b, 36, 72);         // cmdsize
    return b;
}

// Build a FAT container whose slices are laid out after the
// architecture table. Each entry's payload is a real thin Mach-O
// unless the caller asks for filler.
std::vector<std::uint8_t> make_fat_with_real_slices(
    bool fat64,
    std::uint32_t nfat,
    const std::vector<bool>& garbage_slices,
    bool nested_fat_slice
) {
    const std::size_t entry_size = fat64 ? 32 : 20;
    const std::size_t metadata_end = 8 + nfat * entry_size;
    std::vector<std::uint8_t> b(metadata_end, 0);
    b[0] = 0xCA; b[1] = 0xFE;
    b[2] = fat64 ? 0xBA : 0xBA;
    b[3] = fat64 ? 0xBF : 0xBE;
    put_be32(b, 4, nfat);
    for (std::uint32_t i = 0; i < nfat; ++i) {
        const std::size_t e = 8 + i * entry_size;
        std::vector<std::uint8_t> payload;
        if (nested_fat_slice && i == 0) {
            // A FAT32 header where a slice payload belongs.
            payload.assign(8 + 20, 0);
            payload[0] = 0xCA; payload[1] = 0xFE;
            payload[2] = 0xBA; payload[3] = 0xBE;
            put_be32(payload, 4, 0);
        } else if (i < garbage_slices.size() &&
                   garbage_slices[i]) {
            payload.assign(64, 0xEE); // zero-filled-like garbage
        } else {
            payload = make_thin64();
        }
        const std::uint64_t off = b.size();
        b.insert(b.end(), payload.begin(), payload.end());
        if (fat64) {
            put_be64(b, e + 8, off);
            put_be64(b, e + 16, payload.size());
        } else {
            put_be32(b, e + 8,
                static_cast<std::uint32_t>(off));
            put_be32(b, e + 12,
                static_cast<std::uint32_t>(payload.size()));
        }
    }
    return b;
}

} // namespace

int main() {
    int failures = 0;

    // 1. Valid thin arm64.
    {
        auto b = make_thin64();
        const auto r = vphone::macho_validate(b);
        if (!r.valid || !r.is_thin || !r.is_64 ||
            r.cputype != 0x0100000Cu ||
            r.filetype != 2 ||
            r.ncmds != 1 || r.sizeofcmds != 72) {
            std::fprintf(
                stderr, "[1] thin64 failed: %s\n",
                r.error.c_str());
            ++failures;
        } else {
            std::printf("MACHO_THIN64_STRUCTURE_PASS\n");
        }
    }

    // 2. Valid FAT32 with two real thin slices.
    {
        auto b = make_fat_with_real_slices(
            false, 2, {}, false);
        const auto r = vphone::macho_validate(b);
        if (!r.valid || !r.is_fat || r.is_fat64 ||
            r.nfat != 2 || r.slices_validated != 2) {
            std::fprintf(
                stderr, "[2] fat32 real slices failed: %s\n",
                r.error.c_str());
            ++failures;
        } else {
            std::printf("MACHO_FAT32_SLICE_STRUCTURE_PASS\n");
        }
    }

    // 3. Valid FAT64 with two real thin slices.
    {
        auto b = make_fat_with_real_slices(
            true, 2, {}, false);
        const auto r = vphone::macho_validate(b);
        if (!r.valid || !r.is_fat || !r.is_fat64 ||
            r.nfat != 2 || r.slices_validated != 2) {
            std::fprintf(
                stderr, "[3] fat64 real slices failed: %s\n",
                r.error.c_str());
            ++failures;
        } else {
            std::printf("MACHO_FAT64_SLICE_STRUCTURE_PASS\n");
        }
    }

    // 4. Garbage (non-Mach-O) slice refused.
    {
        auto b = make_fat_with_real_slices(
            false, 2, {false, true}, false);
        const auto r = vphone::macho_validate(b);
        if (r.valid) {
            std::fprintf(
                stderr, "[4] garbage slice accepted\n");
            ++failures;
        } else {
            std::printf("MACHO_FAT_INVALID_SLICE_REFUSAL_PASS\n");
        }
    }

    // 5. Slice with bad magic refused.
    {
        auto b = make_fat_with_real_slices(
            false, 1, {}, false);
        // First slice begins at metadata_end; corrupt its magic.
        const std::size_t meta_end =
            8 + static_cast<std::size_t>(1) * 20;
        b[meta_end] = 0xDE;
        b[meta_end + 1] = 0xAD;
        b[meta_end + 2] = 0xBE;
        b[meta_end + 3] = 0xEF;
        const auto r = vphone::macho_validate(b);
        if (r.valid) {
            std::fprintf(
                stderr, "[5] bad-magic slice accepted\n");
            ++failures;
        } else {
            std::printf("MACHO_FAT_BAD_MAGIC_SLICE_REFUSED_PASS\n");
        }
    }

    // 6. Slice with malformed load command refused.
    {
        auto b = make_fat_with_real_slices(
            false, 1, {}, false);
        const std::size_t meta_end =
            8 + static_cast<std::size_t>(1) * 20;
        // cmdsize of the first (only) load command exceeds bounds.
        put_le32(b, meta_end + 32 + 4, 500);
        const auto r = vphone::macho_validate(b);
        if (r.valid) {
            std::fprintf(
                stderr, "[6] malformed-loadcmd slice accepted\n");
            ++failures;
        } else {
            std::printf(
                "MACHO_FAT_MALFORMED_LOADCMD_SLICE_REFUSED_PASS\n");
        }
    }

    // 7. Nested FAT slice refused.
    {
        auto b = make_fat_with_real_slices(
            false, 1, {}, true);
        const auto r = vphone::macho_validate(b);
        if (r.valid) {
            std::fprintf(
                stderr, "[7] nested FAT slice accepted\n");
            ++failures;
        } else {
            std::printf("MACHO_FAT_NESTED_SLICE_REFUSED_PASS\n");
        }
    }

    // 8. Zero architectures refused.
    {
        std::vector<std::uint8_t> b(8, 0);
        b[0] = 0xCA; b[1] = 0xFE;
        b[2] = 0xBA; b[3] = 0xBE;
        put_be32(b, 4, 0);
        const auto r = vphone::macho_validate(b);
        if (r.valid) {
            std::fprintf(
                stderr, "[8] zero-arch FAT accepted\n");
            ++failures;
        } else {
            std::printf("MACHO_FAT_ZERO_ARCH_REFUSAL_PASS\n");
        }
    }

    // 9. Slice overlapping FAT metadata refused.
    {
        std::vector<std::uint8_t> b(8 + 20, 0);
        b[0] = 0xCA; b[1] = 0xFE;
        b[2] = 0xBA; b[3] = 0xBE;
        put_be32(b, 4, 1);
        put_be32(b, 8 + 8, 4); // offset inside the header
        put_be32(b, 8 + 12, 64);
        b.resize(128, 0);
        const auto r = vphone::macho_validate(b);
        if (r.valid) {
            std::fprintf(
                stderr, "[9] metadata-overlap slice accepted\n");
            ++failures;
        } else {
            std::printf("MACHO_FAT_METADATA_OVERLAP_REFUSAL_PASS\n");
        }
    }

    // 10. Truncated FAT table refused.
    {
        std::vector<std::uint8_t> b(8 + 20 * 2, 0);
        b[0] = 0xCA; b[1] = 0xFE;
        b[2] = 0xBA; b[3] = 0xBE;
        put_be32(b, 4, 4);
        const auto r = vphone::macho_validate(b);
        if (r.valid) {
            std::fprintf(
                stderr, "[10] truncated fat accepted\n");
            ++failures;
        } else {
            std::printf("MACHO_FAT_TRUNCATED_TABLE_REFUSED_PASS\n");
        }
    }

    // 11. Slice OOB refused.
    {
        auto b = make_fat_with_real_slices(
            false, 1, {}, false);
        // Rewrite the slice offset beyond the file end.
        put_be32(b, 8 + 8, 0xFFFF0000u);
        const auto r = vphone::macho_validate(b);
        if (r.valid) {
            std::fprintf(stderr, "[11] slice OOB accepted\n");
            ++failures;
        } else {
            std::printf("MACHO_FAT_SLICE_OOB_REFUSED_PASS\n");
        }
    }

    // 12. Overlapping slices refused.
    {
        std::vector<std::uint8_t> b(8 + 20 * 2, 0);
        b[0] = 0xCA; b[1] = 0xFE;
        b[2] = 0xBA; b[3] = 0xBE;
        put_be32(b, 4, 2);
        put_be32(b, 8 + 8, 100);
        put_be32(b, 8 + 12, 300);
        put_be32(b, 8 + 28, 200);
        put_be32(b, 8 + 32, 300);
        b.resize(700, 0);
        const auto r = vphone::macho_validate(b);
        if (r.valid) {
            std::fprintf(
                stderr, "[12] overlapping slices accepted\n");
            ++failures;
        } else {
            std::printf("MACHO_FAT_OVERLAP_REFUSED_PASS\n");
        }
    }

    // 13. Zero-size slice refused.
    {
        std::vector<std::uint8_t> b(8 + 20, 0);
        b[0] = 0xCA; b[1] = 0xFE;
        b[2] = 0xBA; b[3] = 0xBE;
        put_be32(b, 4, 1);
        put_be32(b, 8 + 8, 100);
        put_be32(b, 8 + 12, 0);
        b.resize(200, 0);
        const auto r = vphone::macho_validate(b);
        if (r.valid) {
            std::fprintf(
                stderr, "[13] zero-size slice accepted\n");
            ++failures;
        } else {
            std::printf("MACHO_FAT_ZERO_SLICE_REFUSED_PASS\n");
        }
    }

    // 14. Swapped FAT (CIGAM) refused.
    {
        std::vector<std::uint8_t> b(8 + 20, 0);
        b[0] = 0xBE; b[1] = 0xBA; b[2] = 0xFE; b[3] = 0xCA;
        const auto r = vphone::macho_validate(b);
        if (r.valid) {
            std::fprintf(
                stderr, "[14] swapped FAT accepted\n");
            ++failures;
        } else {
            std::printf("MACHO_FAT_SWAPPED_REFUSED_PASS\n");
        }
    }

    // 15. Load-command bounds violation (thin) refused.
    {
        auto b = make_thin64();
        put_le32(b, 36, 200); // cmdsize exceeds remaining
        const auto r = vphone::macho_validate(b);
        if (r.valid) {
            std::fprintf(
                stderr, "[15] load-command OOB accepted\n");
            ++failures;
        } else {
            std::printf(
                "MACHO_LOAD_COMMAND_BOUNDS_REFUSED_PASS\n");
        }
    }

    if (failures == 0) {
        std::printf("MACHO_STRUCTURAL_FIXTURE_MATRIX_PASS\n");
        std::printf("MACHO_FAT_REAL_SLICE_FIXTURE_MATRIX_PASS\n");
        return 0;
    }
    std::fprintf(stderr, "FAILURES=%d\n", failures);
    return 1;
}