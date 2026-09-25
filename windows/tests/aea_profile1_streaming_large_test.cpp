#include "vphone/aea_profile1_portable.hpp"

#include <cstdio>
#include <cstdint>
#include <fstream>
#include <string>
#include <vector>

#define CHECK(expr) do { if (!(expr)) { std::fprintf(stderr,"CHECK FAILED %s:%d: %s\n",__FILE__,__LINE__,#expr); return 1; } } while(0)

static bool write_pattern_file(const std::string& path, std::uint64_t size) {
    std::ofstream out(path, std::ios::binary | std::ios::trunc);
    if (!out) return false;
    std::vector<std::uint8_t> buf(1024 * 1024);
    std::uint64_t written = 0;
    std::uint32_t state = 0x12345678u;
    while (written < size) {
        const std::size_t n = static_cast<std::size_t>(
            std::min<std::uint64_t>(buf.size(), size - written)
        );
        for (std::size_t i = 0; i < n; ++i) {
            state = state * 1664525u + 1013904223u;
            buf[i] = static_cast<std::uint8_t>((state >> 16) ^ (written + i));
        }
        out.write(reinterpret_cast<const char*>(buf.data()), static_cast<std::streamsize>(n));
        if (!out) return false;
        written += n;
    }
    return true;
}

static bool files_equal(const std::string& a, const std::string& b) {
    std::ifstream fa(a, std::ios::binary);
    std::ifstream fb(b, std::ios::binary);
    if (!fa || !fb) return false;
    std::vector<char> ba(1024 * 1024), bb(1024 * 1024);
    while (true) {
        fa.read(ba.data(), static_cast<std::streamsize>(ba.size()));
        fb.read(bb.data(), static_cast<std::streamsize>(bb.size()));
        const auto na = fa.gcount();
        const auto nb = fb.gcount();
        if (na != nb) return false;
        if (na == 0) return true;
        if (!std::equal(ba.begin(), ba.begin() + na, bb.begin())) return false;
    }
}

int main(int argc, char** argv) {
    CHECK(argc == 2);
    const std::string root = argv[1];
    const std::string src = root + "\\aea_stream_src.bin";
    const std::string arc = root + "\\aea_stream_archive.aea";
    const std::string dst = root + "\\aea_stream_dst.bin";
    const std::string corrupt = root + "\\aea_stream_corrupt.aea";
    const std::string sentinel = root + "\\aea_stream_sentinel.bin";

    const std::uint64_t payloadSize = 80ull * 1024ull * 1024ull + 12345ull;
    CHECK(write_pattern_file(src, payloadSize));

    std::vector<std::uint8_t> key(32);
    for (std::size_t i = 0; i < key.size(); ++i) key[i] = static_cast<std::uint8_t>(i * 7u + 3u);

    vphone::AeaProfile1Options opt;
    opt.segment_size = 256 * 1024;
    opt.segments_per_cluster = 32;

    const std::vector<std::uint8_t> auth = {'4','D','2','C','-','S','T','R','E','A','M'};

    vphone::AeaProfile1FileResult enc;
    std::string error;
    if (!vphone::aea_profile1_encrypt_file(src, arc, key, auth, opt, enc, error)) {
        std::fprintf(stderr, "AEA STREAM ENCRYPT ERROR: %s\n", error.c_str());
        return 1;
    }
    CHECK(enc.input_size == payloadSize);
    CHECK(enc.cluster_count > 1);
    CHECK(enc.peak_buffer_bytes < 16ull * 1024ull * 1024ull);

    vphone::AeaProfile1FileResult dec;
    if (!vphone::aea_profile1_decrypt_file(arc, dst, key, dec, error)) {
        std::fprintf(stderr, "AEA STREAM DECRYPT ERROR: %s\n", error.c_str());
        return 1;
    }
    CHECK(dec.output_size == payloadSize);
    CHECK(dec.peak_buffer_bytes < 16ull * 1024ull * 1024ull);
    CHECK(files_equal(src, dst));

    {
        std::ifstream in(arc, std::ios::binary);
        std::ofstream out(corrupt, std::ios::binary | std::ios::trunc);
        CHECK(in && out);
        std::vector<char> buf(1024 * 1024);
        std::uint64_t pos = 0;
        while (in) {
            in.read(buf.data(), static_cast<std::streamsize>(buf.size()));
            auto n = in.gcount();
            if (n <= 0) break;
            if (pos <= 4096 && 4096 < pos + static_cast<std::uint64_t>(n)) {
                buf[static_cast<std::size_t>(4096 - pos)] ^= 0x55;
            }
            out.write(buf.data(), n);
            pos += static_cast<std::uint64_t>(n);
        }
    }

    {
        std::ofstream out(sentinel, std::ios::binary | std::ios::trunc);
        out << "UNCHANGED";
    }

    vphone::AeaProfile1FileResult bad;
    error.clear();
    CHECK(!vphone::aea_profile1_decrypt_file(corrupt, sentinel, key, bad, error));

    {
        std::ifstream in(sentinel, std::ios::binary);
        std::string value;
        in >> value;
        CHECK(value == "UNCHANGED");
    }

    std::remove(src.c_str());
    std::remove(arc.c_str());
    std::remove(dst.c_str());
    std::remove(corrupt.c_str());
    std::remove(sentinel.c_str());
    return 0;
}
