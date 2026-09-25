#define NOMINMAX
#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include "vphone/aea_profile1_portable.hpp"

#include <fstream>
#include <limits>
#include <string>
#include <vector>

namespace vphone {
namespace {

bool read_all_file(
    const std::string& path,
    std::vector<std::uint8_t>& data,
    std::string& error
) {
    std::ifstream input(path, std::ios::binary | std::ios::ate);
    if (!input) {
        error = "could not open input file: " + path;
        return false;
    }

    const std::streamoff end = input.tellg();
    if (end < 0) {
        error = "could not determine input file size";
        return false;
    }

    if (static_cast<unsigned long long>(end) >
        static_cast<unsigned long long>(std::numeric_limits<std::size_t>::max())) {
        error = "input file is too large for Phase 4D2B memory-backed file backend";
        return false;
    }

    data.resize(static_cast<std::size_t>(end));
    input.seekg(0, std::ios::beg);

    if (!data.empty()) {
        input.read(
            reinterpret_cast<char*>(data.data()),
            static_cast<std::streamsize>(data.size())
        );
        if (!input || input.gcount() != static_cast<std::streamsize>(data.size())) {
            error = "short read from input file";
            return false;
        }
    }

    return true;
}

bool write_atomic_file(
    const std::string& path,
    const std::vector<std::uint8_t>& data,
    std::string& error
) {
    const std::string temp = path + ".vphone.tmp";
    DeleteFileA(temp.c_str());

    {
        std::ofstream output(temp, std::ios::binary | std::ios::trunc);
        if (!output) {
            error = "could not open temporary output file";
            return false;
        }

        if (!data.empty()) {
            output.write(
                reinterpret_cast<const char*>(data.data()),
                static_cast<std::streamsize>(data.size())
            );
        }

        output.flush();
        if (!output) {
            output.close();
            DeleteFileA(temp.c_str());
            error = "failed while writing temporary output file";
            return false;
        }
    }

    if (!MoveFileExA(
            temp.c_str(),
            path.c_str(),
            MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH
        )) {
        const DWORD code = GetLastError();
        DeleteFileA(temp.c_str());
        error = "MoveFileExA failed with Win32 error " + std::to_string(code);
        return false;
    }

    return true;
}

} // namespace

bool aea_profile1_encrypt_file(
    const std::string& input_path,
    const std::string& output_path,
    const std::vector<std::uint8_t>& symmetric_key,
    const std::vector<std::uint8_t>& auth_data,
    const AeaProfile1Options& options,
    AeaProfile1FileResult& result,
    std::string& error
) {
    result = {};
    error.clear();

    std::vector<std::uint8_t> plaintext;
    if (!read_all_file(input_path, plaintext, error)) {
        return false;
    }

    std::vector<std::uint8_t> archive;
    if (!aea_profile1_encrypt(
            plaintext,
            symmetric_key,
            auth_data,
            options,
            archive,
            error
        )) {
        return false;
    }

    if (!write_atomic_file(output_path, archive, error)) {
        return false;
    }

    const std::uint64_t cluster_size =
        static_cast<std::uint64_t>(options.segment_size) *
        static_cast<std::uint64_t>(options.segments_per_cluster);

    result.input_size = plaintext.size();
    result.output_size = archive.size();
    result.cluster_count = plaintext.empty()
        ? 0
        : static_cast<std::size_t>(
            (static_cast<std::uint64_t>(plaintext.size()) + cluster_size - 1) /
            cluster_size
        );

    return true;
}

bool aea_profile1_decrypt_file(
    const std::string& input_path,
    const std::string& output_path,
    const std::vector<std::uint8_t>& symmetric_key,
    AeaProfile1FileResult& result,
    std::string& error
) {
    result = {};
    error.clear();

    std::vector<std::uint8_t> archive;
    if (!read_all_file(input_path, archive, error)) {
        return false;
    }

    AeaProfile1Decoded decoded;
    if (!aea_profile1_decrypt(
            archive,
            symmetric_key,
            decoded,
            error
        )) {
        return false;
    }

    if (!write_atomic_file(output_path, decoded.plaintext, error)) {
        return false;
    }

    result.input_size = archive.size();
    result.output_size = decoded.plaintext.size();
    result.cluster_count = decoded.cluster_count;
    return true;
}

} // namespace vphone
