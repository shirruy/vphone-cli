#pragma once

#include <cstdint>
#include <string>

namespace vphone {

struct FixedVhdResult {
    std::uint64_t raw_size = 0;
    std::uint64_t vhd_size = 0;
    std::uint32_t footer_checksum = 0;
};

bool raw_to_fixed_vhd(
    const std::string& input_path,
    const std::string& output_path,
    FixedVhdResult& result,
    std::string& error
);

bool probe_fixed_vhd_attach_readonly(
    const std::string& vhd_path,
    std::string& physical_path,
    std::string& error
);

} // namespace vphone
