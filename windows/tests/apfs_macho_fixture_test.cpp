// Mach-O structural validation fixture matrix using the SHARED
// production validator (vphone::macho_validate).
//
// Covers: valid thin 64, valid FAT32, valid FAT64, truncated FAT
// table, slice OOB, overlapping slices, zero-size slice, invalid
// nested slice, and a load-command-bounds violation.

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

std::vector<std::uint8_t> make_fat32(
    std::uint32_t nfat,
    const std::vector<std::pair<std::uint32_t, std::uint32_t>>&
        slices
) {
    std::vector<std::uint8_t> b(8 + 20 * nfat, 0);
    b[0] = 0xCA; b[1] = 0xFE; b[2] = 0xBA; b[3] = 0xBE;
    put_be32(b, 4, nfat);
    for (std::size_t i = 0;
         i < slices.size() && i < nfat; ++i) {
        const std::size_t e = 8 + i * 20;
        put_be32(b, e + 8, slices[i].first);
        put_be32(b, e + 12, slices[i].second);
    }
    return b;
}

std::vector<std::uint8_t> make_fat64(
    std::uint32_t nfat,
    const std::vector<std::pair<std::uint64_t, std::uint64_t>>&
        slices
) {
    std::vector<std::uint8_t> b(8 + 32 * nfat, 0);
    b[0] = 0xCA; b[1] = 0xFE; b[2] = 0xBA; b[3] = 0xBF;
    put_be32(b, 4, nfat);
    for (std::size_t i = 0;
         i < slices.size() && i < nfat; ++i) {
        const std::size_t e = 8 + i * 32;
        put_be64(b, e + 8, slices[i].first);
        put_be64(b, e + 16, slices[i].second);
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

    // 2. Valid FAT32 with two bounded slices.
    {
        auto b = make_fat32(
            2, {{100, 200}, {400, 300}});
        // Extend the container so slices are within bounds.
        b.resize(800, 0);
        const auto r = vphone::macho_validate(b);
        if (!r.valid || !r.is_fat || r.is_fat64 ||
            r.nfat != 2) {
            std::fprintf(
                stderr, "[2] fat32 failed: %s\n",
                r.error.c_str());
            ++failures;
        } else {
            std::printf("MACHO_FAT32_STRUCTURE_PASS\n");
        }
    }

    // 3. Valid FAT64 with two bounded slices.
    {
        auto b = make_fat64(
            2, {{200, 300}, {600, 400}});
        b.resize(1200, 0);
        const auto r = vphone::macho_validate(b);
        if (!r.valid || !r.is_fat || !r.is_fat64 ||
            r.nfat != 2) {
            std::fprintf(
                stderr, "[3] fat64 failed: %s\n",
                r.error.c_str());
            ++failures;
        } else {
            std::printf("MACHO_FAT64_STRUCTURE_PASS\n");
        }
    }

    // 4. Truncated FAT table.
    {
        auto b = make_fat32(4, {{0, 10}});
        b.resize(8 + 20 * 2, 0); // only room for 2 entries
        const auto r = vphone::macho_validate(b);
        if (r.valid) {
            std::fprintf(
                stderr, "[4] truncated fat accepted\n");
            ++failures;
        } else {
            std::printf("MACHO_FAT_TRUNCATED_TABLE_REFUSED_PASS\n");
        }
    }

    // 5. Slice OOB.
    {
        auto b = make_fat32(1, {{100, 900}});
        b.resize(200, 0);
        const auto r = vphone::macho_validate(b);
        if (r.valid) {
            std::fprintf(stderr, "[5] slice OOB accepted\n");
            ++failures;
        } else {
            std::printf("MACHO_FAT_SLICE_OOB_REFUSED_PASS\n");
        }
    }

    // 6. Overlapping slices.
    {
        auto b = make_fat32(
            2, {{100, 300}, {200, 300}});
        b.resize(700, 0);
        const auto r = vphone::macho_validate(b);
        if (r.valid) {
            std::fprintf(
                stderr, "[6] overlapping slices accepted\n");
            ++failures;
        } else {
            std::printf("MACHO_FAT_OVERLAP_REFUSED_PASS\n");
        }
    }

    // 7. Zero-size slice.
    {
        auto b = make_fat32(1, {{100, 0}});
        b.resize(200, 0);
        const auto r = vphone::macho_validate(b);
        if (r.valid) {
            std::fprintf(
                stderr, "[7] zero-size slice accepted\n");
            ++failures;
        } else {
            std::printf("MACHO_FAT_ZERO_SLICE_REFUSED_PASS\n");
        }
    }

    // 8. Load-command bounds violation (thin).
    {
        auto b = make_thin64();
        put_le32(b, 36, 200); // cmdsize exceeds remaining
        const auto r = vphone::macho_validate(b);
        if (r.valid) {
            std::fprintf(
                stderr, "[8] load-command OOB accepted\n");
            ++failures;
        } else {
            std::printf(
                "MACHO_LOAD_COMMAND_BOUNDS_REFUSED_PASS\n");
        }
    }

    // 9. Swapped FAT (CIGAM) refused.
    {
        std::vector<std::uint8_t> b(8 + 20, 0);
        b[0] = 0xBE; b[1] = 0xBA; b[2] = 0xFE; b[3] = 0xCA;
        const auto r = vphone::macho_validate(b);
        if (r.valid) {
            std::fprintf(
                stderr, "[9] swapped FAT accepted\n");
            ++failures;
        } else {
            std::printf("MACHO_FAT_SWAPPED_REFUSED_PASS\n");
        }
    }

    // 10. Nested FAT (FAT magic overwriting a thin Mach-O header)
    //     is refused: the dispatcher treats the bytes as a FAT
    //     container whose bogus nfat makes the table OOB, so it
    //     fails closed instead of being reinterpreted.
    {
        auto inner = make_thin64();
        std::vector<std::uint8_t> b;
        b.insert(b.end(), inner.begin(), inner.end());
        // Overwrite the thin magic with a FAT magic; the thin
        // parser must reject it (not treat it as FAT64 via slice).
        b[0] = 0xCA; b[1] = 0xFE; b[2] = 0xBA; b[3] = 0xBE;
        const auto r = vphone::macho_validate(b);
        if (r.valid) {
            std::fprintf(
                stderr, "[10] nested FAT accepted\n");
            ++failures;
        } else {
            std::printf("MACHO_FAT_NESTED_REFUSED_PASS\n");
        }
    }

    if (failures == 0) {
        std::printf("MACHO_STRUCTURAL_FIXTURE_MATRIX_PASS\n");
        return 0;
    }
    std::fprintf(stderr, "FAILURES=%d\n", failures);
    return 1;
}
