#include "vphone/aea_profile1_portable.hpp"

#include <cstdio>
#include <cstdint>
#include <string>
#include <vector>

#define CHECK(expr) \
    do { \
        if (!(expr)) { \
            std::fprintf(stderr, "CHECK FAILED at %s:%d: %s\n", __FILE__, __LINE__, #expr); \
            return 1; \
        } \
    } while (0)

int main()
{
    std::vector<std::uint8_t> key(32);
    for (std::size_t i = 0; i < key.size(); ++i) {
        key[i] = static_cast<std::uint8_t>(i * 7 + 3);
    }

    std::vector<std::uint8_t> auth = {
        0x10, 0x00, 0x00, 0x00,
        'e','n','c','r','y','p','t','i','o','n','_','k','e','y',0x00
    };

    vphone::AeaProfile1Options options;
    options.segment_size = 0x4000;
    options.segments_per_cluster = 32;

    const std::size_t cluster_size =
        static_cast<std::size_t>(options.segment_size) *
        options.segments_per_cluster;

    std::vector<std::uint8_t> plaintext(cluster_size * 2 + 7311);

    for (std::size_t i = 0; i < plaintext.size(); ++i) {
        if (i < cluster_size / 2) {
            plaintext[i] = static_cast<std::uint8_t>('A' + (i % 3));
        } else {
            std::uint32_t x = static_cast<std::uint32_t>(i * 2654435761u);
            x ^= x >> 13;
            x *= 2246822519u;
            plaintext[i] = static_cast<std::uint8_t>(x & 0xffu);
        }
    }

    std::vector<std::uint8_t> archive;
    std::string error;

    CHECK(vphone::aea_profile1_encrypt(
        plaintext,
        key,
        auth,
        options,
        archive,
        error
    ));

    CHECK(archive.size() > 156);
    CHECK(archive[0] == 'A');
    CHECK(archive[1] == 'E');
    CHECK(archive[2] == 'A');
    CHECK(archive[3] == '1');
    CHECK(archive[4] == 1);
    CHECK(archive[5] == 0);
    CHECK(archive[6] == 0);
    CHECK(archive[7] == 0);

    vphone::AeaProfile1Decoded decoded;
    error.clear();

    CHECK(vphone::aea_profile1_decrypt(
        archive,
        key,
        decoded,
        error
    ));

    CHECK(decoded.plaintext == plaintext);
    CHECK(decoded.auth_data == auth);
    CHECK(decoded.segment_size == options.segment_size);
    CHECK(decoded.segments_per_cluster == options.segments_per_cluster);
    CHECK(decoded.cluster_count == 3);

    // Wrong key must fail closed.
    auto wrong_key = key;
    wrong_key[0] ^= 0x55;
    vphone::AeaProfile1Decoded wrong;
    error.clear();
    CHECK(!vphone::aea_profile1_decrypt(
        archive,
        wrong_key,
        wrong,
        error
    ));
    CHECK(!error.empty());

    // Ciphertext mutation must be authenticated.
    auto corrupted = archive;
    corrupted.back() ^= 0x80;
    vphone::AeaProfile1Decoded tampered;
    error.clear();
    CHECK(!vphone::aea_profile1_decrypt(
        corrupted,
        key,
        tampered,
        error
    ));
    CHECK(!error.empty());

    // Invalid profile must fail closed.
    auto wrong_profile = archive;
    wrong_profile[4] = 2;
    vphone::AeaProfile1Decoded rejected;
    error.clear();
    CHECK(!vphone::aea_profile1_decrypt(
        wrong_profile,
        key,
        rejected,
        error
    ));

    return 0;
}
