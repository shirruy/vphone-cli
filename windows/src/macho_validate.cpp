#include "vphone/macho_validate.hpp"

#include <cstring>

namespace vphone {

namespace {

std::uint32_t le32(const std::uint8_t* p) {
    return static_cast<std::uint32_t>(p[0]) |
           (static_cast<std::uint32_t>(p[1]) << 8) |
           (static_cast<std::uint32_t>(p[2]) << 16) |
           (static_cast<std::uint32_t>(p[3]) << 24);
}

std::uint32_t be32(const std::uint8_t* p) {
    return (static_cast<std::uint32_t>(p[0]) << 24) |
           (static_cast<std::uint32_t>(p[1]) << 16) |
           (static_cast<std::uint32_t>(p[2]) << 8) |
           static_cast<std::uint32_t>(p[3]);
}

std::uint64_t be64(const std::uint8_t* p) {
    return (static_cast<std::uint64_t>(be32(p)) << 32) |
           be32(p + 4);
}

} // namespace

MachOValidationResult macho_validate(
    const std::vector<std::uint8_t>& bytes
) {
    MachOValidationResult r;
    if (bytes.size() < 4) {
        r.error = "file too short for any Mach-O container";
        return r;
    }

    // Dispatch on the RAW big-endian magic (FAT containers store
    // magic as the literal bytes CA FE BA BE / CA FE BA BF).
    const std::uint32_t raw_be = be32(bytes.data());

    // Swapped FAT containers (FAT_CIGAM 0xbebafeca / FAT64_CIGAM
    // 0xbfbafeca) are explicitly refused. Reading those four bytes
    // as big-endian cannot collide with a genuine little-endian
    // thin Mach-O header (CE/CF FA ED FE).
    if (raw_be == 0xbebafecau || raw_be == 0xbfbafecau) {
        r.error = "swapped FAT container refused";
        return r;
    }

    if (raw_be == 0xcafebabeu || raw_be == 0xcafebabfu) {
        r.is_fat = true;
        r.is_fat64 = (raw_be == 0xcafebabfu);
        if (bytes.size() < 8) {
            r.error = "FAT header truncated";
            return r;
        }
        r.nfat = be32(bytes.data() + 4);
        const std::uint64_t entry_size =
            r.is_fat64 ? 32 : 20;
        if (r.nfat >
            (bytes.size() - 8) / entry_size) {
            r.error = "FAT architecture table out of bounds";
            return r;
        }
        // Collect slice ranges and reject overlap/overflow/OOB.
        struct Slice {
            std::uint64_t off;
            std::uint64_t size;
        };
        std::vector<Slice> slices;
        slices.reserve(r.nfat);
        for (std::uint32_t i = 0; i < r.nfat; ++i) {
            const std::size_t e = 8 + i * entry_size;
            Slice s{};
            if (r.is_fat64) {
                s.off = be64(bytes.data() + e + 8);
                s.size = be64(bytes.data() + e + 16);
            } else {
                s.off = be32(bytes.data() + e + 8);
                s.size = be32(bytes.data() + e + 12);
            }
            if (s.size == 0) {
                r.error = "FAT slice has zero size";
                return r;
            }
            if (s.off > bytes.size() ||
                s.size > bytes.size() - s.off) {
                r.error = "FAT slice out of bounds";
                return r;
            }
            slices.push_back(s);
        }
        for (std::size_t i = 0; i < slices.size(); ++i) {
            for (std::size_t j = i + 1;
                 j < slices.size(); ++j) {
                const auto& a = slices[i];
                const auto& b = slices[j];
                if (a.off < b.off + b.size &&
                    b.off < a.off + a.size) {
                    r.error = "FAT slices overlap";
                    return r;
                }
            }
        }
        r.valid = true;
        return r;
    }

    // Thin Mach-O: little-endian magic.
    const std::uint32_t magic = le32(bytes.data());
    r.is_thin = true;
    r.is_64 = magic == 0xfeedfacfu;
    if (magic != 0xfeedfaceu && !r.is_64) {
        r.error = "unrecognized Mach-O magic";
        return r;
    }
    const std::size_t header_size = r.is_64 ? 32 : 28;
    if (bytes.size() < header_size) {
        r.error = "Mach-O header truncated";
        return r;
    }
    r.cputype = le32(bytes.data() + 4);
    r.cpusubtype = le32(bytes.data() + 8);
    r.filetype = le32(bytes.data() + 12);
    r.ncmds = le32(bytes.data() + 16);
    r.sizeofcmds = le32(bytes.data() + 20);
    r.flags = le32(bytes.data() + 24);

    const std::uint64_t cmds_end =
        static_cast<std::uint64_t>(header_size) +
        r.sizeofcmds;
    if (cmds_end > bytes.size()) {
        r.error = "load commands exceed file bounds";
        return r;
    }
    std::size_t cursor = header_size;
    for (std::uint32_t i = 0; i < r.ncmds; ++i) {
        if (cursor + 8 > cmds_end) {
            r.error = "load command header out of bounds";
            return r;
        }
        const std::uint32_t cmdsize =
            le32(bytes.data() + cursor + 4);
        if (cmdsize < 8 ||
            static_cast<std::uint64_t>(cursor) + cmdsize >
                cmds_end) {
            r.error = "load command size out of bounds";
            return r;
        }
        cursor += cmdsize;
    }
    if (cursor != cmds_end) {
        r.error = "load commands do not cover sizeofcmds exactly";
        return r;
    }
    r.valid = true;
    return r;
}

} // namespace vphone
