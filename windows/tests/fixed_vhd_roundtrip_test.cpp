#include "vphone/disk_image_windows.hpp"

#include <array>
#include <cstdint>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <string>
#include <vector>

namespace {

std::uint32_t read_be32(const std::uint8_t* p) {
    return (static_cast<std::uint32_t>(p[0]) << 24) |
           (static_cast<std::uint32_t>(p[1]) << 16) |
           (static_cast<std::uint32_t>(p[2]) << 8) |
           static_cast<std::uint32_t>(p[3]);
}

std::uint64_t read_be64(const std::uint8_t* p) {
    return (static_cast<std::uint64_t>(read_be32(p)) << 32) |
           static_cast<std::uint64_t>(read_be32(p + 4));
}

std::uint32_t checksum(std::array<std::uint8_t, 512> footer) {
    footer[64] = footer[65] = footer[66] = footer[67] = 0;
    std::uint32_t sum = 0;
    for (const auto byte : footer) sum += byte;
    return ~sum;
}

bool same_prefix(const std::filesystem::path& raw, const std::filesystem::path& vhd, std::uint64_t bytes) {
    std::ifstream a(raw, std::ios::binary);
    std::ifstream b(vhd, std::ios::binary);
    if (!a || !b) return false;

    std::vector<char> ba(1024 * 1024);
    std::vector<char> bb(1024 * 1024);
    std::uint64_t remaining = bytes;

    while (remaining != 0) {
        const auto want = static_cast<std::streamsize>(
            std::min<std::uint64_t>(remaining, ba.size())
        );
        a.read(ba.data(), want);
        b.read(bb.data(), want);
        if (a.gcount() != want || b.gcount() != want) return false;
        if (std::memcmp(ba.data(), bb.data(), static_cast<std::size_t>(want)) != 0) return false;
        remaining -= static_cast<std::uint64_t>(want);
    }
    return true;
}

} // namespace

int main(int argc, char** argv) {
    if (argc != 2) {
        std::cerr << "usage: vphone_fixed_vhd_roundtrip_test <workdir>\n";
        return 64;
    }

    const std::filesystem::path workdir = argv[1];
    const auto raw = workdir / "phase4d4a-test.raw";
    const auto vhd = workdir / "phase4d4a-test.vhd";

    std::error_code ec;
    std::filesystem::create_directories(workdir, ec);
    std::filesystem::remove(raw, ec);
    std::filesystem::remove(vhd, ec);

    constexpr std::uint64_t raw_size = 8ull * 1024ull * 1024ull;

    {
        std::ofstream out(raw, std::ios::binary | std::ios::trunc);
        if (!out) {
            std::cerr << "could not create raw fixture\n";
            return 1;
        }

        std::array<std::uint8_t, 512> sector{};
        for (std::size_t i = 0; i < sector.size(); ++i) {
            sector[i] = static_cast<std::uint8_t>((i * 37u + 11u) & 0xffu);
        }
        sector[510] = 0x55;
        sector[511] = 0xaa;
        out.write(reinterpret_cast<const char*>(sector.data()), sector.size());

        out.seekp(static_cast<std::streamoff>(raw_size - 1));
        out.put('\0');
    }

    vphone::FixedVhdResult result;
    std::string error;
    if (!vphone::raw_to_fixed_vhd(raw.string(), vhd.string(), result, error)) {
        std::cerr << error << "\n";
        return 1;
    }

    if (result.raw_size != raw_size || result.vhd_size != raw_size + 512ull) {
        std::cerr << "unexpected conversion result sizes\n";
        return 1;
    }

    if (std::filesystem::file_size(vhd, ec) != raw_size + 512ull || ec) {
        std::cerr << "unexpected VHD file size\n";
        return 1;
    }

    if (!same_prefix(raw, vhd, raw_size)) {
        std::cerr << "VHD payload does not preserve raw disk bytes\n";
        return 1;
    }

    std::ifstream in(vhd, std::ios::binary);
    in.seekg(static_cast<std::streamoff>(raw_size));
    std::array<std::uint8_t, 512> footer{};
    in.read(reinterpret_cast<char*>(footer.data()), footer.size());
    if (in.gcount() != static_cast<std::streamsize>(footer.size())) {
        std::cerr << "could not read VHD footer\n";
        return 1;
    }

    if (std::memcmp(footer.data(), "conectix", 8) != 0) {
        std::cerr << "invalid fixed VHD cookie\n";
        return 1;
    }
    if (read_be32(footer.data() + 8) != 0x00000002u) {
        std::cerr << "invalid VHD features\n";
        return 1;
    }
    if (read_be32(footer.data() + 12) != 0x00010000u) {
        std::cerr << "invalid VHD version\n";
        return 1;
    }
    if (read_be64(footer.data() + 16) != 0xffffffffffffffffull) {
        std::cerr << "invalid fixed VHD data offset\n";
        return 1;
    }
    if (read_be64(footer.data() + 40) != raw_size ||
        read_be64(footer.data() + 48) != raw_size) {
        std::cerr << "invalid fixed VHD virtual size\n";
        return 1;
    }
    if (read_be32(footer.data() + 60) != 2u) {
        std::cerr << "invalid fixed VHD disk type\n";
        return 1;
    }

    const auto stored_checksum = read_be32(footer.data() + 64);
    if (stored_checksum != checksum(footer) || stored_checksum != result.footer_checksum) {
        std::cerr << "fixed VHD footer checksum mismatch\n";
        return 1;
    }

    std::cout << "FIXED_VHD_ROUNDTRIP_PASS\n";
    std::cout << "raw_size=" << result.raw_size << "\n";
    std::cout << "vhd_size=" << result.vhd_size << "\n";
    std::cout << "footer_checksum=" << result.footer_checksum << "\n";
    return 0;
}
