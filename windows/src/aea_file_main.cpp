#include "vphone/aea_profile1_portable.hpp"

#include <charconv>
#include <cstdint>
#include <iostream>
#include <string>
#include <vector>

namespace {

bool decode_hex(const std::string& text, std::vector<std::uint8_t>& out) {
    if ((text.size() % 2) != 0) {
        return false;
    }

    out.clear();
    out.reserve(text.size() / 2);

    for (std::size_t i = 0; i < text.size(); i += 2) {
        unsigned int value = 0;
        const char* first = text.data() + i;
        const char* last = first + 2;
        const auto parsed = std::from_chars(first, last, value, 16);
        if (parsed.ec != std::errc{} || parsed.ptr != last || value > 0xffu) {
            return false;
        }
        out.push_back(static_cast<std::uint8_t>(value));
    }

    return true;
}

bool parse_u32(const std::string& text, std::uint32_t& value) {
    unsigned long parsed = 0;
    try {
        parsed = std::stoul(text, nullptr, 0);
    } catch (...) {
        return false;
    }

    if (parsed > 0xfffffffful) {
        return false;
    }

    value = static_cast<std::uint32_t>(parsed);
    return true;
}

void usage() {
    std::cerr
        << "usage:\n"
        << "  vphone-aea-win encrypt <input> <output> <key-hex> [auth-hex] [segment-size] [segments-per-cluster]\n"
        << "  vphone-aea-win decrypt <input> <output> <key-hex>\n";
}

} // namespace

int main(int argc, char** argv) {
    if (argc < 5) {
        usage();
        return 64;
    }

    const std::string mode = argv[1];
    const std::string input = argv[2];
    const std::string output = argv[3];

    std::vector<std::uint8_t> key;
    if (!decode_hex(argv[4], key) || key.size() != 32) {
        std::cerr << "ERROR: key-hex must contain exactly 32 bytes\n";
        return 64;
    }

    vphone::AeaProfile1FileResult result;
    std::string error;

    if (mode == "decrypt") {
        if (argc != 5) {
            usage();
            return 64;
        }

        if (!vphone::aea_profile1_decrypt_file(
                input,
                output,
                key,
                result,
                error
            )) {
            std::cerr << "ERROR: " << error << "\n";
            return 2;
        }
    } else if (mode == "encrypt") {
        std::vector<std::uint8_t> auth;
        if (argc >= 6 && !decode_hex(argv[5], auth)) {
            std::cerr << "ERROR: invalid auth-hex\n";
            return 64;
        }

        vphone::AeaProfile1Options options;

        if (argc >= 7 && !parse_u32(argv[6], options.segment_size)) {
            std::cerr << "ERROR: invalid segment-size\n";
            return 64;
        }

        if (argc >= 8 && !parse_u32(argv[7], options.segments_per_cluster)) {
            std::cerr << "ERROR: invalid segments-per-cluster\n";
            return 64;
        }

        if (argc > 8) {
            usage();
            return 64;
        }

        if (!vphone::aea_profile1_encrypt_file(
                input,
                output,
                key,
                auth,
                options,
                result,
                error
            )) {
            std::cerr << "ERROR: " << error << "\n";
            return 2;
        }
    } else {
        usage();
        return 64;
    }

    std::cout
        << "{\n"
        << "  \"mode\": \"" << mode << "\",\n"
        << "  \"input_size\": " << result.input_size << ",\n"
        << "  \"output_size\": " << result.output_size << ",\n"
        << "  \"cluster_count\": " << result.cluster_count << ",\n"
        << "  \"peak_buffer_bytes\": " << result.peak_buffer_bytes << "\n"
        << "}\n";

    return 0;
}
