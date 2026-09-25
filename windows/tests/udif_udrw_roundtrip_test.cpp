#include "vphone/udif_portable.hpp"

#include <algorithm>
#include <cstdio>
#include <fstream>
#include <string>
#include <vector>

#define CHECK(expr) do { \
    if (!(expr)) { \
        std::fprintf(stderr, "CHECK FAILED %s:%d: %s\n", __FILE__, __LINE__, #expr); \
        return 1; \
    } \
} while (0)

static bool write_pattern_file(const std::string& path, std::uint64_t size) {
    std::ofstream out(path, std::ios::binary | std::ios::trunc);
    if (!out) return false;

    std::vector<unsigned char> buffer(1024 * 1024);
    std::uint32_t state = 0x6d2b79f5u;
    std::uint64_t written = 0;

    while (written < size) {
        const std::size_t n = static_cast<std::size_t>(
            std::min<std::uint64_t>(buffer.size(), size - written)
        );

        for (std::size_t i = 0; i < n; ++i) {
            state ^= state << 13;
            state ^= state >> 17;
            state ^= state << 5;
            buffer[i] = static_cast<unsigned char>(
                (state >> 11) ^ static_cast<std::uint32_t>(written + i)
            );
        }

        out.write(
            reinterpret_cast<const char*>(buffer.data()),
            static_cast<std::streamsize>(n)
        );
        if (!out) return false;
        written += n;
    }

    return true;
}

static bool files_equal(const std::string& a, const std::string& b) {
    std::ifstream fa(a, std::ios::binary);
    std::ifstream fb(b, std::ios::binary);
    if (!fa || !fb) return false;

    std::vector<char> ba(1024 * 1024);
    std::vector<char> bb(1024 * 1024);

    while (true) {
        fa.read(ba.data(), static_cast<std::streamsize>(ba.size()));
        fb.read(bb.data(), static_cast<std::streamsize>(bb.size()));

        const std::streamsize na = fa.gcount();
        const std::streamsize nb = fb.gcount();

        if (na != nb) return false;
        if (na == 0) return true;

        if (!std::equal(
                ba.begin(),
                ba.begin() + na,
                bb.begin()
            )) {
            return false;
        }
    }
}

int main(int argc, char** argv) {
    CHECK(argc == 2);

    const std::string root = argv[1];
    const std::string raw = root + "\\udif_source.raw";
    const std::string dmg = root + "\\udif_output.dmg";
    const std::string restored = root + "\\udif_restored.raw";
    const std::string corrupt = root + "\\udif_corrupt.dmg";
    const std::string sentinel = root + "\\udif_sentinel.raw";
    const std::string unaligned = root + "\\udif_unaligned.raw";

    const std::uint64_t raw_size = 32ull * 1024ull * 1024ull;
    CHECK(write_pattern_file(raw, raw_size));

    vphone::UdifFileResult enc;
    std::string error;

    if (!vphone::udif_wrap_raw_as_udrw(
            raw,
            dmg,
            enc,
            error
        )) {
        std::fprintf(stderr, "UDRW ENCODE ERROR: %s\n", error.c_str());
        return 1;
    }

    CHECK(enc.input_size == raw_size);
    CHECK(enc.sector_count == raw_size / 512ull);
    CHECK(enc.peak_buffer_bytes <= 2ull * 1024ull * 1024ull);

    vphone::UdifInfo info;
    CHECK(vphone::udif_inspect(dmg, info, error));
    CHECK(info.version == 4);
    CHECK(info.data_fork_offset == 0);
    CHECK(info.data_fork_length == raw_size);
    CHECK(info.xml_offset == raw_size);
    CHECK(info.sector_count == raw_size / 512ull);
    CHECK(info.image_variant == 1);
    CHECK(info.raw_data_fork);

    vphone::UdifFileResult dec;
    if (!vphone::udif_extract_raw_data_fork(
            dmg,
            restored,
            dec,
            error
        )) {
        std::fprintf(stderr, "UDRW DECODE ERROR: %s\n", error.c_str());
        return 1;
    }

    CHECK(dec.output_size == raw_size);
    CHECK(dec.peak_buffer_bytes <= 2ull * 1024ull * 1024ull);
    CHECK(files_equal(raw, restored));

    {
        std::ifstream in(dmg, std::ios::binary);
        std::ofstream out(corrupt, std::ios::binary | std::ios::trunc);
        CHECK(in && out);

        std::vector<char> buffer(1024 * 1024);
        while (in) {
            in.read(buffer.data(), static_cast<std::streamsize>(buffer.size()));
            const auto n = in.gcount();
            if (n <= 0) break;
            out.write(buffer.data(), n);
        }
    }

    {
        std::fstream file(corrupt, std::ios::binary | std::ios::in | std::ios::out);
        CHECK(file);
        file.seekp(-512, std::ios::end);
        const char bad[4] = {'b','a','d','!'};
        file.write(bad, 4);
        CHECK(file);
    }

    {
        std::ofstream out(sentinel, std::ios::binary | std::ios::trunc);
        CHECK(out);
        out << "UNCHANGED";
    }

    vphone::UdifFileResult bad;
    error.clear();
    CHECK(!vphone::udif_extract_raw_data_fork(
        corrupt,
        sentinel,
        bad,
        error
    ));

    {
        std::ifstream in(sentinel, std::ios::binary);
        std::string value;
        in >> value;
        CHECK(value == "UNCHANGED");
    }

    CHECK(write_pattern_file(unaligned, 513));
    error.clear();
    CHECK(!vphone::udif_wrap_raw_as_udrw(
        unaligned,
        sentinel,
        bad,
        error
    ));

    {
        std::ifstream in(sentinel, std::ios::binary);
        std::string value;
        in >> value;
        CHECK(value == "UNCHANGED");
    }

    std::remove(raw.c_str());
    std::remove(dmg.c_str());
    std::remove(restored.c_str());
    std::remove(corrupt.c_str());
    std::remove(sentinel.c_str());
    std::remove(unaligned.c_str());

    return 0;
}
