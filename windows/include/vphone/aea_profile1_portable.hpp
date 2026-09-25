#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace vphone {

struct AeaProfile1Options {
    std::uint32_t segment_size{0x100000};
    std::uint32_t segments_per_cluster{256};
};

struct AeaProfile1Decoded {
    std::vector<std::uint8_t> plaintext;
    std::vector<std::uint8_t> auth_data;
    std::uint32_t segment_size{0};
    std::uint32_t segments_per_cluster{0};
    std::size_t cluster_count{0};
};

bool aea_profile1_encrypt(
    const std::vector<std::uint8_t>& plaintext,
    const std::vector<std::uint8_t>& symmetric_key,
    const std::vector<std::uint8_t>& auth_data,
    const AeaProfile1Options& options,
    std::vector<std::uint8_t>& archive,
    std::string& error
);

bool aea_profile1_decrypt(
    const std::vector<std::uint8_t>& archive,
    const std::vector<std::uint8_t>& symmetric_key,
    AeaProfile1Decoded& decoded,
    std::string& error
);

struct AeaProfile1FileResult {
    std::uint64_t input_size{0};
    std::uint64_t output_size{0};
    std::size_t cluster_count{0};
};

bool aea_profile1_encrypt_file(
    const std::string& input_path,
    const std::string& output_path,
    const std::vector<std::uint8_t>& symmetric_key,
    const std::vector<std::uint8_t>& auth_data,
    const AeaProfile1Options& options,
    AeaProfile1FileResult& result,
    std::string& error
);

bool aea_profile1_decrypt_file(
    const std::string& input_path,
    const std::string& output_path,
    const std::vector<std::uint8_t>& symmetric_key,
    AeaProfile1FileResult& result,
    std::string& error
);

} // namespace vphone
