#pragma once

#include <cstdint>
#include <string>

namespace vphone {

struct UdifInfo {
    std::uint32_t version = 0;
    std::uint32_t flags = 0;
    std::uint64_t data_fork_offset = 0;
    std::uint64_t data_fork_length = 0;
    std::uint64_t xml_offset = 0;
    std::uint64_t xml_length = 0;
    std::uint32_t image_variant = 0;
    std::uint64_t sector_count = 0;
    bool raw_data_fork = false;
};

struct UdifFileResult {
    std::uint64_t input_size = 0;
    std::uint64_t output_size = 0;
    std::uint64_t sector_count = 0;
    std::uint64_t peak_buffer_bytes = 0;
};

bool udif_inspect(
    const std::string& input_path,
    UdifInfo& info,
    std::string& error
);

bool udif_wrap_raw_as_udrw(
    const std::string& input_path,
    const std::string& output_path,
    UdifFileResult& result,
    std::string& error
);

bool udif_extract_raw_data_fork(
    const std::string& input_path,
    const std::string& output_path,
    UdifFileResult& result,
    std::string& error
);

bool udif_decode_to_raw(
    const std::string& input_path,
    const std::string& output_path,
    UdifFileResult& result,
    std::string& error
);

} // namespace vphone
