#include "vphone/aea_profile1_portable.hpp"

#include <cstdio>
#include <cstdint>
#include <fstream>
#include <string>
#include <vector>

#define CHECK(expr) \
    do { \
        if (!(expr)) { \
            std::fprintf(stderr, "CHECK FAILED at %s:%d: %s\n", __FILE__, __LINE__, #expr); \
            return 1; \
        } \
    } while (0)

static bool write_file(const std::string& path, const std::vector<std::uint8_t>& data) {
    std::ofstream out(path, std::ios::binary | std::ios::trunc);
    if (!out) return false;
    if (!data.empty()) {
        out.write(reinterpret_cast<const char*>(data.data()), static_cast<std::streamsize>(data.size()));
    }
    return static_cast<bool>(out);
}

static bool read_file(const std::string& path, std::vector<std::uint8_t>& data) {
    std::ifstream in(path, std::ios::binary | std::ios::ate);
    if (!in) return false;
    const auto size = in.tellg();
    if (size < 0) return false;
    in.seekg(0, std::ios::beg);
    data.resize(static_cast<std::size_t>(size));
    if (!data.empty()) {
        in.read(reinterpret_cast<char*>(data.data()), size);
    }
    return static_cast<bool>(in);
}

int main(int argc, char** argv) {
    CHECK(argc == 2);

    const std::string root = argv[1];
    const std::string plainPath = root + "\\aea_file_plain.bin";
    const std::string archivePath = root + "\\aea_file_archive.aea";
    const std::string restoredPath = root + "\\aea_file_restored.bin";

    std::vector<std::uint8_t> key(32);
    for (std::size_t i = 0; i < key.size(); ++i) {
        key[i] = static_cast<std::uint8_t>(0xA5u ^ static_cast<unsigned int>(i * 11u));
    }

    const std::vector<std::uint8_t> auth = {
        'v','p','h','o','n','e','-','4','d','2','b'
    };

    vphone::AeaProfile1Options options;
    options.segment_size = 0x4000;
    options.segments_per_cluster = 32;

    const std::size_t clusterSize =
        static_cast<std::size_t>(options.segment_size) *
        options.segments_per_cluster;

    std::vector<std::uint8_t> plain(clusterSize * 2 + 12345);
    for (std::size_t i = 0; i < plain.size(); ++i) {
        plain[i] = static_cast<std::uint8_t>((i * 131u + (i >> 3) + 17u) & 0xffu);
    }

    CHECK(write_file(plainPath, plain));

    vphone::AeaProfile1FileResult enc;
    std::string error;
    CHECK(vphone::aea_profile1_encrypt_file(
        plainPath,
        archivePath,
        key,
        auth,
        options,
        enc,
        error
    ));
    CHECK(enc.cluster_count == 3);
    CHECK(enc.input_size == plain.size());

    vphone::AeaProfile1FileResult dec;
    error.clear();
    CHECK(vphone::aea_profile1_decrypt_file(
        archivePath,
        restoredPath,
        key,
        dec,
        error
    ));
    CHECK(dec.cluster_count == 3);
    CHECK(dec.output_size == plain.size());

    std::vector<std::uint8_t> restored;
    CHECK(read_file(restoredPath, restored));
    CHECK(restored == plain);

    std::remove(plainPath.c_str());
    std::remove(archivePath.c_str());
    std::remove(restoredPath.c_str());
    return 0;
}
