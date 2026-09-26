#include "vphone/disk_image_windows.hpp"

#include <iostream>
#include <string>

namespace {

void usage() {
    std::cerr
        << "usage:\n"
        << "  vphone-disk-image-win convert-fixed <raw-input> <vhd-output>\n"
        << "  vphone-disk-image-win probe-attach-readonly <fixed-vhd>\n";
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
        if (!vphone::raw_to_fixed_vhd(argv[2], argv[3], result, error)) {
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
        if (!vphone::probe_fixed_vhd_attach_readonly(argv[2], physical_path, error)) {
            std::cerr << "ERROR: " << error << "\n";
            return 1;
        }

        std::cout
            << "{\n"
            << "  \"operation\": \"probe-attach-readonly\",\n"
            << "  \"physical_path\": \"" << physical_path << "\",\n"
            << "  \"detached\": true\n"
            << "}\n";
        return 0;
    }

    usage();
    return 64;
}
