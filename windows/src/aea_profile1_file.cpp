#include "vphone/aea_profile1_portable.hpp"

namespace vphone {

bool aea_profile1_encrypt_file(
    const std::string& input_path,
    const std::string& output_path,
    const std::vector<std::uint8_t>& symmetric_key,
    const std::vector<std::uint8_t>& auth_data,
    const AeaProfile1Options& options,
    AeaProfile1FileResult& result,
    std::string& error
) {
    return aea_profile1_encrypt_file_streaming(
        input_path,
        output_path,
        symmetric_key,
        auth_data,
        options,
        result,
        error
    );
}

bool aea_profile1_decrypt_file(
    const std::string& input_path,
    const std::string& output_path,
    const std::vector<std::uint8_t>& symmetric_key,
    AeaProfile1FileResult& result,
    std::string& error
) {
    return aea_profile1_decrypt_file_streaming(
        input_path,
        output_path,
        symmetric_key,
        result,
        error
    );
}

} // namespace vphone
