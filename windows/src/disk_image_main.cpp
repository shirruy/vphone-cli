#include "vphone/disk_image_windows.hpp"

#include <iostream>
#include <string>

namespace {

std::string json_escape(const std::string& value) {
    static constexpr char hex[] = "0123456789abcdef";

    std::string out;
    out.reserve(value.size() + 16);

    for (unsigned char ch : value) {
        switch (ch) {
            case '"':
                out += "\\\"";
                break;
            case '\\':
                out += "\\\\";
                break;
            case '\b':
                out += "\\b";
                break;
            case '\f':
                out += "\\f";
                break;
            case '\n':
                out += "\\n";
                break;
            case '\r':
                out += "\\r";
                break;
            case '\t':
                out += "\\t";
                break;
            default:
                if (ch < 0x20) {
                    out += "\\u00";
                    out += hex[(ch >> 4) & 0x0f];
                    out += hex[ch & 0x0f];
                } else {
                    out.push_back(static_cast<char>(ch));
                }
                break;
        }
    }

    return out;
}

void usage() {
    std::cerr
        << "usage:\n"
        << "  vphone-disk-image-win convert-fixed <raw-input> <vhd-output>\n"
        << "  vphone-disk-image-win probe-attach-readonly <fixed-vhd>\n"
        << "  vphone-disk-image-win convert-fixed-and-probe-readonly <raw-input> <vhd-output>\n";
}

} // namespace

int main(int argc, char** argv) {
    if (argc < 2) {
        usage();
        return 64;
    }

    const std::string command = argv[1];

    if (command == "convert-fixed") {
        if (argc != 4) {
            usage();
            return 64;
        }

        vphone::FixedVhdResult result;
        std::string error;

        if (!vphone::raw_to_fixed_vhd(
                argv[2],
                argv[3],
                result,
                error
            )) {
            std::cerr << "ERROR: " << error << "\n";
            return 1;
        }

        std::cout
            << "{\n"
            << "  \"operation\": \"convert-fixed\",\n"
            << "  \"raw_size\": " << result.raw_size << ",\n"
            << "  \"vhd_size\": " << result.vhd_size << ",\n"
            << "  \"footer_checksum\": " << result.footer_checksum << "\n"
            << "}\n";

        return 0;
    }

    if (command == "probe-attach-readonly") {
        if (argc != 3) {
            usage();
            return 64;
        }

        std::string physical_path;
        std::string error;

        if (!vphone::probe_fixed_vhd_attach_readonly(
                argv[2],
                physical_path,
                error
            )) {
            std::cerr << "ERROR: " << error << "\n";
            return 1;
        }

        std::cout
            << "{\n"
            << "  \"operation\": \"probe-attach-readonly\",\n"
            << "  \"physical_path\": \"" << json_escape(physical_path) << "\",\n"
            << "  \"detached\": true\n"
            << "}\n";

        return 0;
    }

    if (command == "convert-fixed-and-probe-readonly") {
        if (argc != 4) {
            usage();
            return 64;
        }

        vphone::FixedVhdResult result;
        std::string error;

        if (!vphone::raw_to_fixed_vhd(
                argv[2],
                argv[3],
                result,
                error
            )) {
            std::cerr << "ERROR: conversion failed: "
                      << error
                      << "\n";
            return 1;
        }

        std::string physical_path;

        if (!vphone::probe_fixed_vhd_attach_readonly(
                argv[3],
                physical_path,
                error
            )) {
            std::cerr << "ERROR: physical attach probe failed: "
                      << error
                      << "\n";
            return 1;
        }

        if (physical_path.empty()) {
            std::cerr << "ERROR: Windows returned no physical disk path\n";
            return 1;
        }

        std::cout
            << "{\n"
            << "  \"operation\": \"convert-fixed-and-probe-readonly\",\n"
            << "  \"raw_size\": " << result.raw_size << ",\n"
            << "  \"vhd_size\": " << result.vhd_size << ",\n"
            << "  \"footer_checksum\": " << result.footer_checksum << ",\n"
            << "  \"physical_path\": \"" << json_escape(physical_path) << "\",\n"
            << "  \"attached_readonly\": true,\n"
            << "  \"detached\": true\n"
            << "}\n";

        return 0;
    }

    usage();
    return 64;
}