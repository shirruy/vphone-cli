#define NOMINMAX
#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include "vphone/apfs_snapshot_portable.hpp"

#include <algorithm>
#include <array>
#include <cstring>
#include <limits>
#include <sstream>
#include <vector>

namespace vphone {
namespace {

constexpr std::size_t kHashLength = 64;
constexpr std::size_t kWindowSize = 64u * 1024u * 1024u;

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

void write_le64(std::uint8_t* p, std::uint64_t value) {
    for (int i = 0; i < 8; ++i) {
        p[i] = static_cast<std::uint8_t>((value >> (i * 8)) & 0xFFu);
    }
}

bool is_hex(std::uint8_t ch) {
    return
        (ch >= '0' && ch <= '9') ||
        (ch >= 'a' && ch <= 'f') ||
        (ch >= 'A' && ch <= 'F');
}

std::string win_error(const char* operation) {
    std::ostringstream out;
    out << operation << " failed with Win32 error " << GetLastError();
    return out.str();
}

bool seek_file(HANDLE file, std::uint64_t offset, std::string& error) {
    LARGE_INTEGER distance{};
    distance.QuadPart = static_cast<LONGLONG>(offset);
    if (!SetFilePointerEx(file, distance, nullptr, FILE_BEGIN)) {
        error = win_error("SetFilePointerEx");
        return false;
    }
    return true;
}

bool read_exact(
    HANDLE file,
    std::uint64_t offset,
    void* buffer,
    std::size_t size,
    std::string& error
) {
    if (size > std::numeric_limits<DWORD>::max()) {
        error = "read size exceeds Win32 DWORD limit";
        return false;
    }

    if (!seek_file(file, offset, error)) {
        return false;
    }

    DWORD read = 0;
    if (!ReadFile(file, buffer, static_cast<DWORD>(size), &read, nullptr)) {
        error = win_error("ReadFile");
        return false;
    }

    if (read != size) {
        error = "short read";
        return false;
    }

    return true;
}

bool write_exact(
    HANDLE file,
    std::uint64_t offset,
    const void* buffer,
    std::size_t size,
    std::string& error
) {
    if (size > std::numeric_limits<DWORD>::max()) {
        error = "write size exceeds Win32 DWORD limit";
        return false;
    }

    if (!seek_file(file, offset, error)) {
        return false;
    }

    DWORD written = 0;
    if (!WriteFile(file, buffer, static_cast<DWORD>(size), &written, nullptr)) {
        error = win_error("WriteFile");
        return false;
    }

    if (written != size) {
        error = "short write";
        return false;
    }

    return true;
}

void merge_report(ApfsSnapshotReport& target, const ApfsSnapshotReport& source) {
    if (target.snapshot_name.empty() && !source.snapshot_name.empty()) {
        target.snapshot_name = source.snapshot_name;
    }
    target.blocks.insert(target.blocks.end(), source.blocks.begin(), source.blocks.end());
}

} // namespace

std::size_t ApfsSnapshotReport::record_count() const {
    std::size_t count = 0;
    for (const auto& block : blocks) {
        count += block.second.size();
    }
    return count;
}

bool ApfsSnapshotReport::empty() const {
    return blocks.empty();
}

std::uint64_t apfs_snapshot_checksum(const std::uint8_t* block, std::size_t size) {
    if (!block || size != kApfsSnapshotBlockSize) {
        return 0;
    }

    constexpr std::uint64_t modulus = 0xFFFFFFFFull;
    std::uint64_t s1 = 0;
    std::uint64_t s2 = 0;

    for (std::size_t offset = 8; offset < kApfsSnapshotBlockSize; offset += 4) {
        const std::uint64_t word = read_le32(block + offset);
        s1 = (s1 + word) % modulus;
        s2 = (s2 + s1) % modulus;
    }

    const std::uint64_t c1 = modulus - ((s1 + s2) % modulus);
    const std::uint64_t c2 = modulus - ((s1 + c1) % modulus);
    return c1 | (c2 << 32);
}

bool apfs_snapshot_block_valid(const std::uint8_t* block, std::size_t size) {
    if (!block || size != kApfsSnapshotBlockSize) {
        return false;
    }
    return apfs_snapshot_checksum(block, size) == read_le64(block);
}

bool apfs_snapshot_scan_buffer(
    const std::uint8_t* data,
    std::size_t size,
    std::uint64_t base_offset,
    ApfsSnapshotReport& report,
    std::string& error
) {
    report = {};
    error.clear();

    if (!data && size != 0) {
        error = "scan buffer is null";
        return false;
    }

    const std::string old_prefix = kApfsSnapshotOldPrefix;
    const std::size_t need = old_prefix.size() + kHashLength;

    if (size < need) {
        return true;
    }

    std::size_t i = 0;

    while (i + need <= size) {
        const auto found = std::search(
            data + i,
            data + size,
            old_prefix.begin(),
            old_prefix.end()
        );

        if (found == data + size) {
            break;
        }

        i = static_cast<std::size_t>(found - data);

        if (i + need > size) {
            break;
        }

        bool all_hex = true;
        const std::size_t hash_start = i + old_prefix.size();
        for (std::size_t k = 0; k < kHashLength; ++k) {
            if (!is_hex(data[hash_start + k])) {
                all_hex = false;
                break;
            }
        }

        if (!all_hex) {
            ++i;
            continue;
        }

        const std::size_t block_offset = (i / kApfsSnapshotBlockSize) * kApfsSnapshotBlockSize;
        if (block_offset + kApfsSnapshotBlockSize > size) {
            ++i;
            continue;
        }

        const auto* block = data + block_offset;
        if (!apfs_snapshot_block_valid(block, kApfsSnapshotBlockSize)) {
            ++i;
            continue;
        }

        if (report.snapshot_name.empty()) {
            report.snapshot_name.assign(
                reinterpret_cast<const char*>(data + i),
                need
            );
        }

        const std::uint64_t absolute_block = base_offset + block_offset;
        auto it = std::find_if(
            report.blocks.begin(),
            report.blocks.end(),
            [absolute_block](const auto& entry) {
                return entry.first == absolute_block;
            }
        );

        if (it == report.blocks.end()) {
            report.blocks.push_back({absolute_block, {}});
            it = std::prev(report.blocks.end());
        }

        it->second.push_back(i - block_offset);
        ++i;
    }

    std::sort(
        report.blocks.begin(),
        report.blocks.end(),
        [](const auto& a, const auto& b) {
            return a.first < b.first;
        }
    );

    return true;
}

bool apfs_snapshot_rename_file(
    const std::string& path,
    const std::string& new_prefix,
    bool dry_run,
    ApfsSnapshotReport& report,
    std::string& error
) {
    report = {};
    error.clear();

    const std::size_t required_prefix = std::strlen(kApfsSnapshotOldPrefix);
    if (new_prefix.size() != required_prefix) {
        error = "new APFS snapshot prefix must be exactly " +
            std::to_string(required_prefix) + " bytes";
        return false;
    }

    const DWORD access = GENERIC_READ | (dry_run ? 0u : GENERIC_WRITE);
    HANDLE file = CreateFileA(
        path.c_str(),
        access,
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

    LARGE_INTEGER file_size{};
    if (!GetFileSizeEx(file, &file_size)) {
        error = win_error("GetFileSizeEx");
        CloseHandle(file);
        return false;
    }

    const std::uint64_t length = static_cast<std::uint64_t>(file_size.QuadPart);

    for (std::uint64_t offset = 0; offset < length; offset += kWindowSize) {
        const std::uint64_t remaining = length - offset;
        const std::size_t count = static_cast<std::size_t>(
            std::min<std::uint64_t>(remaining, kWindowSize)
        );

        std::vector<std::uint8_t> window(count);
        if (!read_exact(file, offset, window.data(), count, error)) {
            CloseHandle(file);
            return false;
        }

        ApfsSnapshotReport part;
        if (!apfs_snapshot_scan_buffer(window.data(), window.size(), offset, part, error)) {
            CloseHandle(file);
            return false;
        }

        merge_report(report, part);
    }

    if (dry_run || report.empty()) {
        CloseHandle(file);
        return true;
    }

    for (const auto& block_info : report.blocks) {
        std::array<std::uint8_t, kApfsSnapshotBlockSize> block{};

        if (!read_exact(
                file,
                block_info.first,
                block.data(),
                block.size(),
                error
            )) {
            CloseHandle(file);
            return false;
        }

        for (const std::size_t within : block_info.second) {
            if (within + new_prefix.size() > block.size()) {
                error = "snapshot record extends past APFS metadata block";
                CloseHandle(file);
                return false;
            }

            std::memcpy(
                block.data() + within,
                new_prefix.data(),
                new_prefix.size()
            );
        }

        const std::uint64_t checksum =
            apfs_snapshot_checksum(block.data(), block.size());
        write_le64(block.data(), checksum);

        if (!write_exact(
                file,
                block_info.first,
                block.data(),
                block.size(),
                error
            )) {
            CloseHandle(file);
            return false;
        }
    }

    if (!FlushFileBuffers(file)) {
        error = win_error("FlushFileBuffers");
        CloseHandle(file);
        return false;
    }

    CloseHandle(file);
    return true;
}

} // namespace vphone
