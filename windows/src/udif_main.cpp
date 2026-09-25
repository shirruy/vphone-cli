#include "vphone/udif_portable.hpp"

#include <iostream>
#include <string>

namespace {

void usage() {
    std::cerr
        << "usage:\n"
        << "  vphone-udif-win raw-to-udrw <raw.img> <output.dmg>\n"
        << "  vphone-udif-win udrw-to-raw <input.dmg> <output.img>\n"
        << "  vphone-udif-win dmg-to-raw <input.dmg> <output.img>\n"
        << "  vphone-udif-win inspect <input.dmg>\n";
}

void print_result(const vphone::UdifFileResult& result) {
    std::cout
        << "{\n"
        << "  \"input_size\": " << result.input_size << ",\n"
        << "  \"output_size\": " << result.output_size << ",\n"
        << "  \"sector_count\": " << result.sector_count << ",\n"
        << "  \"peak_buffer_bytes\": " << result.peak_buffer_bytes << "\n"
        << "}\n";
}

} // namespace

int main(int argc, char** argv) {
    if (argc < 2) {
        usage();
        return 64;
    }

    const std::string command = argv[1];
    std::string error;

    if (command == "raw-to-udrw") {
        if (argc != 4) {
            usage();
            return 64;
        }
        vphone::UdifFileResult result;
        if (!vphone::udif_wrap_raw_as_udrw(
                argv[2],
                argv[3],
                result,
                error
            )) {
            std::cerr << "ERROR: " << error << "\n";
            return 1;
        }
        print_result(result);
        return 0;
    }

    if (command == "udrw-to-raw") {
        if (argc != 4) {
            usage();
            return 64;
        }
        vphone::UdifFileResult result;
        if (!vphone::udif_extract_raw_data_fork(
                argv[2],
                argv[3],
                result,
                error
            )) {
            std::cerr << "ERROR: " << error << "\n";
            return 1;
        }
        print_result(result);
        return 0;
    }

    if (command == "dmg-to-raw") {
        if (argc != 4) {
            usage();
            return 64;
        }
        vphone::UdifFileResult result;
        if (!vphone::udif_decode_to_raw(argv[2], argv[3], result, error)) {
            std::cerr << "ERROR: " << error << "\n";
            return 1;
        }
        print_result(result);
        return 0;
    }

    if (command == "inspect") {
        if (argc != 3) {
            usage();
            return 64;
        }
        vphone::UdifInfo info;
        if (!vphone::udif_inspect(argv[2], info, error)) {
            std::cerr << "ERROR: " << error << "\n";
            return 1;
        }
        std::cout
            << "{\n"
            << "  \"version\": " << info.version << ",\n"
            << "  \"flags\": " << info.flags << ",\n"
            << "  \"data_fork_offset\": " << info.data_fork_offset << ",\n"
            << "  \"data_fork_length\": " << info.data_fork_length << ",\n"
            << "  \"xml_offset\": " << info.xml_offset << ",\n"
            << "  \"xml_length\": " << info.xml_length << ",\n"
            << "  \"image_variant\": " << info.image_variant << ",\n"
            << "  \"sector_count\": " << info.sector_count << ",\n"
            << "  \"raw_data_fork\": "
            << (info.raw_data_fork ? "true" : "false") << "\n"
            << "}\n";
        return 0;
    }

    usage();
    return 64;
}
