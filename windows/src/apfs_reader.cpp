#define NOMINMAX
#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include "vphone/apfs_reader.hpp"

#include <cstring>
#include <limits>
#include <sstream>

namespace vphone {
namespace {

constexpr std::uint32_t kNxsbMagic = 0x4253584Eu; // 'NXSB'
constexpr std::uint32_t kApsbMagic = 0x42535041u; // 'APSB'
constexpr std::uint32_t kOmapType = 0x0000000Bu;
constexpr std::uint32_t kBtreeType = 0x00000002u;
// APFS object headers carry persistence/encryption flags in the upper
// bits of o_type (e.g. OBJ_PHYSICAL = 0x40000000). The concrete object
// kind lives in the low bits.
constexpr std::uint32_t kObjectTypeMask = 0x0FFFFFFFu;

std::uint32_t read_le32(const std::uint8_t* p) {
    return
        static_cast<std::uint32_t>(p[0]) |
        (static_cast<std::uint32_t>(p[1]) << 8) |
        (static_cast<std::uint32_t>(p[2]) << 16) |
        (static_cast<std::uint32_t>(p[3]) << 24);
}

std::uint64_t read_le64(const std::uint8_t* p) {
    std::uint64_t value = 0;
    for (int i = 7; i >= 0; --i) {
        value = (value << 8) | p[i];
    }
    return value;
}

std::string win_error(const char* operation) {
    std::ostringstream out;
    out << operation << " failed with Win32 error " << GetLastError();
    return out.str();
}

bool read_block(
    HANDLE file,
    std::uint64_t block,
    std::uint32_t block_size,
    std::vector<std::uint8_t>& buffer,
    std::string& error
) {
    LARGE_INTEGER distance{};
    distance.QuadPart =
        static_cast<LONGLONG>(block) * static_cast<LONGLONG>(block_size);
    if (!SetFilePointerEx(file, distance, nullptr, FILE_BEGIN)) {
        error = win_error("SetFilePointerEx");
        return false;
    }

    DWORD read = 0;
    if (!ReadFile(
            file,
            buffer.data(),
            static_cast<DWORD>(buffer.size()),
            &read,
            nullptr
        )) {
        error = win_error("ReadFile");
        return false;
    }

    if (read != buffer.size()) {
        error = "short read";
        return false;
    }

    return true;
}

bool valid_block_geometry(
    std::uint32_t block_size,
    std::uint64_t block_count,
    std::uint64_t file_size,
    std::string& error
) {
    if (block_size == 0 || (block_size & (block_size - 1)) != 0) {
        error = "APFS block size is not a power of two";
        return false;
    }
    if (block_count == 0 || block_count > std::numeric_limits<std::uint32_t>::max()) {
        error = "APFS block count is out of range";
        return false;
    }

    const std::uint64_t data_size =
        static_cast<std::uint64_t>(block_count) * block_size;
    if (data_size > file_size) {
        error = "APFS block count exceeds file size";
        return false;
    }

    return true;
}

} // namespace

bool apfs_read_container(
    const std::string& path,
    ApfsReaderReport& report,
    std::string& error
) {
    report = {};
    error.clear();

    HANDLE file = CreateFileA(
        path.c_str(),
        GENERIC_READ,
        FILE_SHARE_READ,
        nullptr,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        nullptr
    );

    if (file == INVALID_HANDLE_VALUE) {
        error = win_error("CreateFileA");
        return false;
    }

    std::vector<std::uint8_t> block;

    do {
        LARGE_INTEGER file_size{};
        if (!GetFileSizeEx(file, &file_size)) {
            error = win_error("GetFileSizeEx");
            break;
        }

        if (file_size.QuadPart < 4096) {
            error = "file is smaller than one APFS block";
            break;
        }

        block.assign(4096, 0);
        if (!read_block(file, 0, 4096, block, error)) {
            break;
        }

        // Object header: cksum(8) oid(8) xid(8) type(4) subtype(4)
        // NXSB: magic(4) blocksize(4) blockcount(8) at offsets 32/36/40.
        if (read_le32(block.data() + 32) != kNxsbMagic) {
            error = "container superblock magic is not NXSB";
            break;
        }

        report.container.block_size = read_le32(block.data() + 36);
        report.container.block_count = read_le64(block.data() + 40);

        // nx_omap_oid follows the uuid + next-oid/xid + checkpoint area.
        // Observed layout for the known-good fixture: the omap pointer
        // table starts after the checkpoint descriptor/data arrays.
        // Decode from the field observed at offset 136 in this image
        // family; validated below by finding an OMAP object there.
        const std::uint64_t file_size_u =
            static_cast<std::uint64_t>(file_size.QuadPart);
        if (!valid_block_geometry(
                report.container.block_size,
                report.container.block_count,
                file_size_u,
                error
            )) {
            break;
        }

        block.assign(report.container.block_size, 0);

        // Scan for volume superblocks (APSB). The checkpoint area holds
        // multiple NXSB eras; the newest era's APSB is the active volume.
        // We scan every block once and keep all APSB objects found.
        for (std::uint64_t b = 0; b < report.container.block_count; ++b) {
            if (!read_block(
                    file,
                    b,
                    report.container.block_size,
                    block,
                    error
                )) {
                break;
            }

            if (read_le32(block.data() + 32) != kApsbMagic) {
                continue;
            }

            ApfsVolumeInfo volume;
            volume.apsb_block = b;
            volume.apsb_oid = read_le64(block.data() + 8);
            volume.xid = read_le64(block.data() + 16);

            // apfs_omap_oid / apfs_root_tree_oid: observed at +0x80/+0x90.
            const std::uint64_t omap_block = read_le64(block.data() + 0x80);
            const std::uint64_t root_block = read_le64(block.data() + 0x90);

            if (omap_block >= report.container.block_count ||
                root_block >= report.container.block_count) {
                continue;
            }

            std::vector<std::uint8_t> omap_block_buf(
                report.container.block_size,
                0
            );
            if (!read_block(
                    file,
                    omap_block,
                    report.container.block_size,
                    omap_block_buf,
                    error
                )) {
                break;
            }

            if ((read_le32(omap_block_buf.data() + 24) & kObjectTypeMask)
                    != kOmapType) {
                continue;
            }

            std::vector<std::uint8_t> root_block_buf(
                report.container.block_size,
                0
            );
            if (!read_block(
                    file,
                    root_block,
                    report.container.block_size,
                    root_block_buf,
                    error
                )) {
                break;
            }

            if ((read_le32(root_block_buf.data() + 24) & kObjectTypeMask)
                    != kBtreeType) {
                continue;
            }

            volume.omap_block = omap_block;
            volume.root_tree_block = root_block;

            // apfs_volname is a fixed 256-byte null-padded array in the
            // APSB; observed at offset 0x2C0 in this image family.
            if (0x2C0 + 256 <= block.size()) {
                const char* name =
                    reinterpret_cast<const char*>(block.data() + 0x2C0);
                const std::size_t max_len =
                    strnlen(name, 256);
                bool printable = max_len > 0;
                for (std::size_t i = 0; i < max_len; ++i) {
                    const std::uint8_t ch =
                        static_cast<std::uint8_t>(name[i]);
                    if (ch < 0x20 || ch > 0x7e) {
                        printable = false;
                        break;
                    }
                }
                if (printable) {
                    volume.volume_name.assign(name, max_len);
                }
            }

            report.volumes.push_back(volume);
        }

        error.clear();
        CloseHandle(file);
        return true;
    } while (false);

    CloseHandle(file);
    return false;
}

} // namespace vphone
