#ifdef _WIN32
#ifndef NOMINMAX
#define NOMINMAX
#endif
#endif

#include "vphone/disk_image_windows.hpp"

#include <array>
#include <ctime>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <limits>
#include <string>
#include <vector>

#ifdef _WIN32
#include <windows.h>
#include <initguid.h>
#include <virtdisk.h>
#include <bcrypt.h>
#endif

namespace vphone {
namespace {

constexpr std::size_t kVhdFooterSize = 512;
constexpr std::size_t kCopyBufferSize = 1024 * 1024;
constexpr std::uint32_t kFixedDiskType = 2;
constexpr std::uint32_t kVhdFeatures = 0x00000002u;
constexpr std::uint32_t kVhdVersion = 0x00010000u;
constexpr std::uint64_t kFixedDataOffset = 0xffffffffffffffffull;
constexpr std::uint64_t kVhdEpochUnix = 946684800ull;

void put_be32(std::uint8_t* p, std::uint32_t value) {
    p[0] = static_cast<std::uint8_t>((value >> 24) & 0xff);
    p[1] = static_cast<std::uint8_t>((value >> 16) & 0xff);
    p[2] = static_cast<std::uint8_t>((value >> 8) & 0xff);
    p[3] = static_cast<std::uint8_t>(value & 0xff);
}

void put_be64(std::uint8_t* p, std::uint64_t value) {
    put_be32(p, static_cast<std::uint32_t>((value >> 32) & 0xffffffffu));
    put_be32(p + 4, static_cast<std::uint32_t>(value & 0xffffffffu));
}

std::uint32_t vhd_geometry(std::uint64_t raw_size) {
    std::uint64_t total_sectors = raw_size / 512ull;
    constexpr std::uint64_t kMaxSectors = 65535ull * 16ull * 255ull;
    if (total_sectors > kMaxSectors) {
        total_sectors = kMaxSectors;
    }

    std::uint32_t sectors_per_track = 0;
    std::uint32_t heads = 0;
    std::uint64_t cylinder_times_heads = 0;

    if (total_sectors >= 65535ull * 16ull * 63ull) {
        sectors_per_track = 255;
        heads = 16;
        cylinder_times_heads = total_sectors / sectors_per_track;
    } else {
        sectors_per_track = 17;
        cylinder_times_heads = total_sectors / sectors_per_track;
        heads = static_cast<std::uint32_t>((cylinder_times_heads + 1023ull) / 1024ull);
        if (heads < 4) {
            heads = 4;
        }
        if (cylinder_times_heads >= static_cast<std::uint64_t>(heads) * 1024ull || heads > 16) {
            sectors_per_track = 31;
            heads = 16;
            cylinder_times_heads = total_sectors / sectors_per_track;
        }
        if (cylinder_times_heads >= static_cast<std::uint64_t>(heads) * 1024ull) {
            sectors_per_track = 63;
            heads = 16;
            cylinder_times_heads = total_sectors / sectors_per_track;
        }
    }

    const std::uint32_t cylinders = static_cast<std::uint32_t>(
        cylinder_times_heads / static_cast<std::uint64_t>(heads)
    );

    return ((cylinders & 0xffffu) << 16) |
           ((heads & 0xffu) << 8) |
           (sectors_per_track & 0xffu);
}

std::uint32_t footer_checksum(const std::array<std::uint8_t, kVhdFooterSize>& footer) {
    std::uint32_t sum = 0;
    for (std::uint8_t byte : footer) {
        sum += byte;
    }
    return ~sum;
}

std::string win32_error(const char* prefix, unsigned long code) {
    return std::string(prefix) + " (Win32=" + std::to_string(code) + ")";
}

#ifdef _WIN32
std::string wide_to_utf8(const std::wstring& value) {
    if (value.empty()) return {};
    const int needed = WideCharToMultiByte(
        CP_UTF8, 0, value.data(), static_cast<int>(value.size()),
        nullptr, 0, nullptr, nullptr
    );
    if (needed <= 0) return {};
    std::string out(static_cast<std::size_t>(needed), '\0');
    WideCharToMultiByte(
        CP_UTF8, 0, value.data(), static_cast<int>(value.size()),
        out.data(), needed, nullptr, nullptr
    );
    return out;
}
#endif

} // namespace

bool raw_to_fixed_vhd(
    const std::string& input_path,
    const std::string& output_path,
    FixedVhdResult& result,
    std::string& error
) {
    result = {};
    error.clear();

    std::error_code ec;
    const auto raw_size = std::filesystem::file_size(input_path, ec);
    if (ec) {
        error = "could not stat raw input: " + ec.message();
        return false;
    }
    if (raw_size == 0) {
        error = "raw input is empty";
        return false;
    }
    if ((raw_size % 512ull) != 0) {
        error = "raw input size must be a multiple of 512 bytes";
        return false;
    }
    if (raw_size > static_cast<std::uint64_t>(std::numeric_limits<std::streamoff>::max()) - kVhdFooterSize) {
        error = "raw input is too large for host stream offsets";
        return false;
    }

    std::ifstream input(input_path, std::ios::binary);
    if (!input) {
        error = "could not open raw input";
        return false;
    }

    const std::filesystem::path destination(output_path);
    const std::filesystem::path temp = destination.string() + ".vphone.tmp";
    std::filesystem::remove(temp, ec);

    std::ofstream output(temp, std::ios::binary | std::ios::trunc);
    if (!output) {
        error = "could not create temporary VHD output";
        return false;
    }

    std::vector<char> buffer(kCopyBufferSize);
    std::uint64_t copied = 0;
    while (input) {
        input.read(buffer.data(), static_cast<std::streamsize>(buffer.size()));
        const auto got = input.gcount();
        if (got > 0) {
            output.write(buffer.data(), got);
            if (!output) {
                output.close();
                std::filesystem::remove(temp, ec);
                error = "failed while writing raw payload into fixed VHD";
                return false;
            }
            copied += static_cast<std::uint64_t>(got);
        }
    }
    if (!input.eof()) {
        output.close();
        std::filesystem::remove(temp, ec);
        error = "failed while reading raw input";
        return false;
    }
    if (copied != raw_size) {
        output.close();
        std::filesystem::remove(temp, ec);
        error = "raw input changed while being copied";
        return false;
    }

    std::array<std::uint8_t, kVhdFooterSize> footer{};
    std::memcpy(footer.data() + 0, "conectix", 8);
    put_be32(footer.data() + 8, kVhdFeatures);
    put_be32(footer.data() + 12, kVhdVersion);
    put_be64(footer.data() + 16, kFixedDataOffset);

    const auto now = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());
    std::uint64_t timestamp = 0;
    if (now > static_cast<std::time_t>(kVhdEpochUnix)) {
        timestamp = static_cast<std::uint64_t>(now) - kVhdEpochUnix;
    }
    if (timestamp > 0xffffffffull) timestamp = 0xffffffffull;
    put_be32(footer.data() + 24, static_cast<std::uint32_t>(timestamp));

    std::memcpy(footer.data() + 28, "vphn", 4);
    put_be32(footer.data() + 32, kVhdVersion);
    std::memcpy(footer.data() + 36, "Wi2k", 4);
    put_be64(footer.data() + 40, raw_size);
    put_be64(footer.data() + 48, raw_size);
    put_be32(footer.data() + 56, vhd_geometry(raw_size));
    put_be32(footer.data() + 60, kFixedDiskType);

#ifdef _WIN32
    const NTSTATUS rng_status = BCryptGenRandom(
        nullptr,
        reinterpret_cast<PUCHAR>(footer.data() + 68),
        16,
        BCRYPT_USE_SYSTEM_PREFERRED_RNG
    );
    if (rng_status < 0) {
        output.close();
        std::filesystem::remove(temp, ec);
        error = "BCryptGenRandom failed while creating VHD unique ID";
        return false;
    }
#else
    for (std::size_t i = 0; i < 16; ++i) {
        footer[68 + i] = static_cast<std::uint8_t>(i + 1);
    }
#endif

    footer[84] = 0;

    put_be32(footer.data() + 64, 0);
    const std::uint32_t checksum = footer_checksum(footer);
    put_be32(footer.data() + 64, checksum);

    output.write(
        reinterpret_cast<const char*>(footer.data()),
        static_cast<std::streamsize>(footer.size())
    );
    output.flush();
    if (!output) {
        output.close();
        std::filesystem::remove(temp, ec);
        error = "failed while writing fixed VHD footer";
        return false;
    }
    output.close();

#ifdef _WIN32
    const std::wstring temp_w = temp.wstring();
    const std::wstring destination_w = destination.wstring();
    if (!MoveFileExW(
            temp_w.c_str(),
            destination_w.c_str(),
            MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH
        )) {
        const DWORD code = GetLastError();
        std::filesystem::remove(temp, ec);
        error = win32_error("could not atomically publish fixed VHD", code);
        return false;
    }
#else
    std::filesystem::rename(temp, destination, ec);
    if (ec) {
        std::filesystem::remove(temp, ec);
        error = "could not publish fixed VHD: " + ec.message();
        return false;
    }
#endif

    result.raw_size = raw_size;
    result.vhd_size = raw_size + kVhdFooterSize;
    result.footer_checksum = checksum;
    return true;
}

bool probe_fixed_vhd_attach_readonly(
    const std::string& vhd_path,
    std::string& physical_path,
    std::string& error
) {
    physical_path.clear();
    error.clear();

#ifndef _WIN32
    error = "fixed VHD attach probe is only available on Windows";
    return false;
#else
    const std::wstring path = std::filesystem::path(vhd_path).wstring();

    VIRTUAL_STORAGE_TYPE storage_type{};
    storage_type.DeviceId = VIRTUAL_STORAGE_TYPE_DEVICE_VHD;
    storage_type.VendorId = VIRTUAL_STORAGE_TYPE_VENDOR_MICROSOFT;

    OPEN_VIRTUAL_DISK_PARAMETERS open_params{};
    open_params.Version = OPEN_VIRTUAL_DISK_VERSION_1;
    open_params.Version1.RWDepth = OPEN_VIRTUAL_DISK_RW_DEPTH_DEFAULT;

    HANDLE handle = INVALID_HANDLE_VALUE;
    DWORD code = OpenVirtualDisk(
        &storage_type,
        path.c_str(),
        VIRTUAL_DISK_ACCESS_ATTACH_RO | VIRTUAL_DISK_ACCESS_GET_INFO,
        OPEN_VIRTUAL_DISK_FLAG_NONE,
        &open_params,
        &handle
    );
    if (code != ERROR_SUCCESS) {
        error = win32_error("OpenVirtualDisk failed", code);
        return false;
    }

    ATTACH_VIRTUAL_DISK_PARAMETERS attach_params{};
    attach_params.Version = ATTACH_VIRTUAL_DISK_VERSION_1;
    attach_params.Version1.Reserved = 0;

    code = AttachVirtualDisk(
        handle,
        nullptr,
        static_cast<ATTACH_VIRTUAL_DISK_FLAG>(
            ATTACH_VIRTUAL_DISK_FLAG_READ_ONLY |
            ATTACH_VIRTUAL_DISK_FLAG_NO_DRIVE_LETTER
        ),
        0,
        &attach_params,
        nullptr
    );
    if (code != ERROR_SUCCESS) {
        CloseHandle(handle);
        error = win32_error("AttachVirtualDisk failed", code);
        return false;
    }

    ULONG bytes = 0;
    code = GetVirtualDiskPhysicalPath(handle, &bytes, nullptr);
    if (code != ERROR_INSUFFICIENT_BUFFER || bytes < sizeof(wchar_t)) {
        const DWORD detach_code = DetachVirtualDisk(handle, DETACH_VIRTUAL_DISK_FLAG_NONE, 0);
        CloseHandle(handle);
        error = win32_error("GetVirtualDiskPhysicalPath sizing failed", code);
        if (detach_code != ERROR_SUCCESS) {
            error += "; detach also failed with Win32=" + std::to_string(detach_code);
        }
        return false;
    }

    std::vector<wchar_t> buffer((bytes / sizeof(wchar_t)) + 1u, L'\0');
    code = GetVirtualDiskPhysicalPath(handle, &bytes, buffer.data());
    if (code != ERROR_SUCCESS) {
        const DWORD detach_code = DetachVirtualDisk(handle, DETACH_VIRTUAL_DISK_FLAG_NONE, 0);
        CloseHandle(handle);
        error = win32_error("GetVirtualDiskPhysicalPath failed", code);
        if (detach_code != ERROR_SUCCESS) {
            error += "; detach also failed with Win32=" + std::to_string(detach_code);
        }
        return false;
    }

    physical_path = wide_to_utf8(std::wstring(buffer.data()));

    const DWORD detach_code = DetachVirtualDisk(handle, DETACH_VIRTUAL_DISK_FLAG_NONE, 0);
    CloseHandle(handle);
    if (detach_code != ERROR_SUCCESS) {
        error = win32_error("DetachVirtualDisk failed", detach_code);
        return false;
    }

    if (physical_path.empty()) {
        error = "Windows attached the fixed VHD but returned an empty physical path";
        return false;
    }

    return true;
#endif
}

} // namespace vphone
