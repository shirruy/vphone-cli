#pragma once
#include <cstdint>
#include <string>

namespace vphone {
struct VmConfig {
    std::string name;
    std::string manifest_path;
    std::string disk_path;
    std::string nvram_path;
    std::string rom_path;
    std::string sep_storage_path;
    std::uint32_t cpu_count{8};
    std::uint64_t memory_bytes{8ull * 1024ull * 1024ull * 1024ull};
    bool force_dfu{false};
};
}
