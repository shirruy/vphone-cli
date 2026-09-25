#define NOMINMAX
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <bcrypt.h>

#include "vphone/aea_profile1_portable.hpp"

#include <lzfse.h>

#include <algorithm>
#include <array>
#include <cstring>
#include <fstream>
#include <cstdio>
#include <limits>
#include <string>
#include <vector>

#pragma comment(lib, "bcrypt.lib")

namespace vphone {
namespace {

constexpr std::uint32_t kProfileSymmetric = 1;
constexpr std::uint8_t kScryptStrength = 0;
constexpr std::uint8_t kCompressionLzfse = static_cast<std::uint8_t>('e');
constexpr std::uint8_t kChecksumSha256 = 2;
constexpr std::size_t kSha256Size = 32;
constexpr std::size_t kKeyMaterialSize = 80;
constexpr std::size_t kRootHeaderSize = 48;
constexpr std::size_t kSegmentHeaderSize = 40;
constexpr std::size_t kFileHeaderSize = 12;
constexpr std::size_t kPrologueFixedSize =
    kFileHeaderSize + 32 + 32 + kRootHeaderSize + 32;

using Bytes = std::vector<std::uint8_t>;
using Digest = std::array<std::uint8_t, kSha256Size>;

struct KeyMaterial {
    Digest mac{};
    std::array<std::uint8_t, 32> aes{};
    std::array<std::uint8_t, 16> iv{};
};

struct RootHeader {
    std::uint64_t original_size{0};
    std::uint64_t archive_size{0};
    std::uint32_t segment_size{0};
    std::uint32_t segments_per_cluster{0};
    std::uint8_t compression{0};
    std::uint8_t checksum{0};
};

void append_u32(Bytes& out, std::uint32_t value) {
    for (int i = 0; i < 4; ++i) {
        out.push_back(static_cast<std::uint8_t>((value >> (8 * i)) & 0xffu));
    }
}

void append_u64(Bytes& out, std::uint64_t value) {
    for (int i = 0; i < 8; ++i) {
        out.push_back(static_cast<std::uint8_t>((value >> (8 * i)) & 0xffu));
    }
}

std::uint32_t read_u32(const std::uint8_t* p) {
    return
        static_cast<std::uint32_t>(p[0]) |
        (static_cast<std::uint32_t>(p[1]) << 8) |
        (static_cast<std::uint32_t>(p[2]) << 16) |
        (static_cast<std::uint32_t>(p[3]) << 24);
}

std::uint64_t read_u64(const std::uint8_t* p) {
    std::uint64_t value = 0;
    for (int i = 7; i >= 0; --i) {
        value = (value << 8) | p[i];
    }
    return value;
}

void put_u32(std::uint8_t* p, std::uint32_t value) {
    for (int i = 0; i < 4; ++i) {
        p[i] = static_cast<std::uint8_t>((value >> (8 * i)) & 0xffu);
    }
}

void put_u64(std::uint8_t* p, std::uint64_t value) {
    for (int i = 0; i < 8; ++i) {
        p[i] = static_cast<std::uint8_t>((value >> (8 * i)) & 0xffu);
    }
}

bool random_bytes(std::uint8_t* data, std::size_t size, std::string& error) {
    if (size > std::numeric_limits<ULONG>::max()) {
        error = "random request too large";
        return false;
    }

    const NTSTATUS status = BCryptGenRandom(
        nullptr,
        data,
        static_cast<ULONG>(size),
        BCRYPT_USE_SYSTEM_PREFERRED_RNG
    );

    if (status < 0) {
        error = "BCryptGenRandom failed";
        return false;
    }

    return true;
}

bool sha256(const std::uint8_t* data, std::size_t size, Digest& out, std::string& error) {
    BCRYPT_ALG_HANDLE alg = nullptr;
    BCRYPT_HASH_HANDLE hash = nullptr;

    if (BCryptOpenAlgorithmProvider(&alg, BCRYPT_SHA256_ALGORITHM, nullptr, 0) < 0) {
        error = "BCryptOpenAlgorithmProvider(SHA256) failed";
        return false;
    }

    DWORD object_length = 0;
    DWORD result_length = 0;
    if (BCryptGetProperty(
            alg,
            BCRYPT_OBJECT_LENGTH,
            reinterpret_cast<PUCHAR>(&object_length),
            sizeof(object_length),
            &result_length,
            0
        ) < 0) {
        BCryptCloseAlgorithmProvider(alg, 0);
        error = "BCryptGetProperty(SHA256 object length) failed";
        return false;
    }

    Bytes object(object_length);
    if (BCryptCreateHash(
            alg,
            &hash,
            object.data(),
            object_length,
            nullptr,
            0,
            0
        ) < 0) {
        BCryptCloseAlgorithmProvider(alg, 0);
        error = "BCryptCreateHash(SHA256) failed";
        return false;
    }

    bool ok = true;
    if (size != 0 && BCryptHashData(
            hash,
            const_cast<PUCHAR>(data),
            static_cast<ULONG>(size),
            0
        ) < 0) {
        error = "BCryptHashData(SHA256) failed";
        ok = false;
    } else if (BCryptFinishHash(hash, out.data(), static_cast<ULONG>(out.size()), 0) < 0) {
        error = "BCryptFinishHash(SHA256) failed";
        ok = false;
    }

    BCryptDestroyHash(hash);
    BCryptCloseAlgorithmProvider(alg, 0);
    return ok;
}

bool hmac_sha256(
    const std::uint8_t* key,
    std::size_t key_size,
    const std::uint8_t* data,
    std::size_t data_size,
    Digest& out,
    std::string& error
) {
    BCRYPT_ALG_HANDLE alg = nullptr;
    BCRYPT_HASH_HANDLE hash = nullptr;

    if (key_size > std::numeric_limits<ULONG>::max() ||
        data_size > std::numeric_limits<ULONG>::max()) {
        error = "HMAC input too large";
        return false;
    }

    if (BCryptOpenAlgorithmProvider(
            &alg,
            BCRYPT_SHA256_ALGORITHM,
            nullptr,
            BCRYPT_ALG_HANDLE_HMAC_FLAG
        ) < 0) {
        error = "BCryptOpenAlgorithmProvider(HMAC-SHA256) failed";
        return false;
    }

    DWORD object_length = 0;
    DWORD result_length = 0;
    if (BCryptGetProperty(
            alg,
            BCRYPT_OBJECT_LENGTH,
            reinterpret_cast<PUCHAR>(&object_length),
            sizeof(object_length),
            &result_length,
            0
        ) < 0) {
        BCryptCloseAlgorithmProvider(alg, 0);
        error = "BCryptGetProperty(HMAC object length) failed";
        return false;
    }

    Bytes object(object_length);
    if (BCryptCreateHash(
            alg,
            &hash,
            object.data(),
            object_length,
            const_cast<PUCHAR>(key),
            static_cast<ULONG>(key_size),
            0
        ) < 0) {
        BCryptCloseAlgorithmProvider(alg, 0);
        error = "BCryptCreateHash(HMAC-SHA256) failed";
        return false;
    }

    bool ok = true;
    if (data_size != 0 && BCryptHashData(
            hash,
            const_cast<PUCHAR>(data),
            static_cast<ULONG>(data_size),
            0
        ) < 0) {
        error = "BCryptHashData(HMAC-SHA256) failed";
        ok = false;
    } else if (BCryptFinishHash(hash, out.data(), static_cast<ULONG>(out.size()), 0) < 0) {
        error = "BCryptFinishHash(HMAC-SHA256) failed";
        ok = false;
    }

    BCryptDestroyHash(hash);
    BCryptCloseAlgorithmProvider(alg, 0);
    return ok;
}

bool hkdf_sha256(
    const Bytes& ikm,
    const Bytes& salt,
    const Bytes& info,
    std::size_t output_size,
    Bytes& output,
    std::string& error
) {
    Digest zero_salt{};
    const std::uint8_t* salt_ptr = salt.empty() ? zero_salt.data() : salt.data();
    const std::size_t salt_size = salt.empty() ? zero_salt.size() : salt.size();

    Digest prk{};
    if (!hmac_sha256(salt_ptr, salt_size, ikm.data(), ikm.size(), prk, error)) {
        return false;
    }

    output.clear();
    output.reserve(output_size);

    Bytes previous;
    std::uint8_t counter = 1;

    while (output.size() < output_size) {
        Bytes input;
        input.reserve(previous.size() + info.size() + 1);
        input.insert(input.end(), previous.begin(), previous.end());
        input.insert(input.end(), info.begin(), info.end());
        input.push_back(counter);

        Digest block{};
        if (!hmac_sha256(prk.data(), prk.size(), input.data(), input.size(), block, error)) {
            return false;
        }

        const std::size_t take = std::min(block.size(), output_size - output.size());
        output.insert(output.end(), block.begin(), block.begin() + static_cast<std::ptrdiff_t>(take));
        previous.assign(block.begin(), block.end());

        if (counter == 255 && output.size() < output_size) {
            error = "HKDF output too large";
            return false;
        }
        ++counter;
    }

    return true;
}

bool derive_key(
    const Bytes& ikm,
    const Bytes& salt,
    const Bytes& info,
    std::size_t size,
    Bytes& output,
    std::string& error
) {
    return hkdf_sha256(ikm, salt, info, size, output, error);
}

bool to_key_material(const Bytes& bytes, KeyMaterial& out, std::string& error) {
    if (bytes.size() != kKeyMaterialSize) {
        error = "invalid AEA key material length";
        return false;
    }

    std::copy_n(bytes.begin(), 32, out.mac.begin());
    std::copy_n(bytes.begin() + 32, 32, out.aes.begin());
    std::copy_n(bytes.begin() + 64, 16, out.iv.begin());
    return true;
}

void increment_counter(std::array<std::uint8_t, 16>& counter) {
    for (int i = 15; i >= 0; --i) {
        ++counter[static_cast<std::size_t>(i)];
        if (counter[static_cast<std::size_t>(i)] != 0) {
            break;
        }
    }
}

bool aes_ctr(
    const Bytes& input,
    const std::array<std::uint8_t, 32>& key,
    const std::array<std::uint8_t, 16>& iv,
    Bytes& output,
    std::string& error
) {
    BCRYPT_ALG_HANDLE alg = nullptr;
    BCRYPT_KEY_HANDLE key_handle = nullptr;

    if (BCryptOpenAlgorithmProvider(&alg, BCRYPT_AES_ALGORITHM, nullptr, 0) < 0) {
        error = "BCryptOpenAlgorithmProvider(AES) failed";
        return false;
    }

    if (BCryptSetProperty(
            alg,
            BCRYPT_CHAINING_MODE,
            reinterpret_cast<PUCHAR>(const_cast<wchar_t*>(BCRYPT_CHAIN_MODE_ECB)),
            static_cast<ULONG>(sizeof(BCRYPT_CHAIN_MODE_ECB)),
            0
        ) < 0) {
        BCryptCloseAlgorithmProvider(alg, 0);
        error = "BCryptSetProperty(AES ECB) failed";
        return false;
    }

    DWORD object_length = 0;
    DWORD result_length = 0;
    if (BCryptGetProperty(
            alg,
            BCRYPT_OBJECT_LENGTH,
            reinterpret_cast<PUCHAR>(&object_length),
            sizeof(object_length),
            &result_length,
            0
        ) < 0) {
        BCryptCloseAlgorithmProvider(alg, 0);
        error = "BCryptGetProperty(AES object length) failed";
        return false;
    }

    Bytes object(object_length);
    if (BCryptGenerateSymmetricKey(
            alg,
            &key_handle,
            object.data(),
            object_length,
            const_cast<PUCHAR>(key.data()),
            static_cast<ULONG>(key.size()),
            0
        ) < 0) {
        BCryptCloseAlgorithmProvider(alg, 0);
        error = "BCryptGenerateSymmetricKey(AES) failed";
        return false;
    }

    output.resize(input.size());
    auto counter = iv;

    for (std::size_t offset = 0; offset < input.size(); offset += 16) {
        std::array<std::uint8_t, 16> stream{};
        ULONG written = 0;

        if (BCryptEncrypt(
                key_handle,
                counter.data(),
                static_cast<ULONG>(counter.size()),
                nullptr,
                nullptr,
                0,
                stream.data(),
                static_cast<ULONG>(stream.size()),
                &written,
                0
            ) < 0 || written != stream.size()) {
            BCryptDestroyKey(key_handle);
            BCryptCloseAlgorithmProvider(alg, 0);
            error = "BCryptEncrypt(AES-CTR keystream block) failed";
            return false;
        }

        const std::size_t count = std::min<std::size_t>(16, input.size() - offset);
        for (std::size_t i = 0; i < count; ++i) {
            output[offset + i] = input[offset + i] ^ stream[i];
        }

        increment_counter(counter);
    }

    BCryptDestroyKey(key_handle);
    BCryptCloseAlgorithmProvider(alg, 0);
    return true;
}

bool secure_equal(const std::uint8_t* a, const std::uint8_t* b, std::size_t size) {
    std::uint8_t diff = 0;
    for (std::size_t i = 0; i < size; ++i) {
        diff |= static_cast<std::uint8_t>(a[i] ^ b[i]);
    }
    return diff == 0;
}

bool calculate_mac(
    const Digest& key,
    const Bytes& data,
    const Bytes& salt,
    Digest& out,
    std::string& error
) {
    Bytes input;
    input.reserve(salt.size() + data.size() + 8);
    input.insert(input.end(), salt.begin(), salt.end());
    input.insert(input.end(), data.begin(), data.end());
    append_u64(input, static_cast<std::uint64_t>(salt.size()));
    return hmac_sha256(key.data(), key.size(), input.data(), input.size(), out, error);
}

Bytes info_with_index(const char* label, std::uint32_t index) {
    Bytes info(label, label + std::strlen(label));
    append_u32(info, index);
    return info;
}

Bytes profile_main_info() {
    Bytes info{'A','E','A','_','A','M','K'};
    append_u32(info, kProfileSymmetric);
    return info;
}

bool derive_main_key(
    const Bytes& symmetric_key,
    const Bytes& main_salt,
    Bytes& main_key,
    std::string& error
) {
    return derive_key(
        symmetric_key,
        main_salt,
        profile_main_info(),
        32,
        main_key,
        error
    );
}

bool derive_material(
    const Bytes& ikm,
    const Bytes& info,
    KeyMaterial& material,
    std::string& error
) {
    Bytes bytes;
    if (!derive_key(ikm, {}, info, kKeyMaterialSize, bytes, error)) {
        return false;
    }
    return to_key_material(bytes, material, error);
}

Bytes encode_root_header(const RootHeader& root) {
    Bytes data(kRootHeaderSize, 0);
    put_u64(data.data(), root.original_size);
    put_u64(data.data() + 8, root.archive_size);
    put_u32(data.data() + 16, root.segment_size);
    put_u32(data.data() + 20, root.segments_per_cluster);
    data[24] = root.compression;
    data[25] = root.checksum;
    return data;
}

bool decode_root_header(const Bytes& data, RootHeader& root, std::string& error) {
    if (data.size() != kRootHeaderSize) {
        error = "invalid AEA root header size";
        return false;
    }

    root.original_size = read_u64(data.data());
    root.archive_size = read_u64(data.data() + 8);
    root.segment_size = read_u32(data.data() + 16);
    root.segments_per_cluster = read_u32(data.data() + 20);
    root.compression = data[24];
    root.checksum = data[25];

    if (root.segment_size < 0x4000) {
        error = "AEA segment size is below the format minimum";
        return false;
    }
    if (root.segments_per_cluster < 32) {
        error = "AEA segments-per-cluster is below the format minimum";
        return false;
    }
    if (root.compression != kCompressionLzfse) {
        error = "unsupported AEA compression algorithm";
        return false;
    }
    if (root.checksum != kChecksumSha256) {
        error = "unsupported AEA checksum algorithm";
        return false;
    }

    return true;
}

bool lzfse_compress_or_raw(
    const std::uint8_t* data,
    std::size_t size,
    Bytes& output,
    std::string& error
) {
    if (size == 0) {
        output.clear();
        return true;
    }

    const std::size_t scratch_size = lzfse_encode_scratch_size();
    Bytes scratch(scratch_size);
    Bytes compressed(size + 4096);

    const std::size_t written = lzfse_encode_buffer(
        compressed.data(),
        compressed.size(),
        data,
        size,
        scratch.data()
    );

    if (written == 0 || written >= size) {
        output.assign(data, data + size);
        return true;
    }

    compressed.resize(written);
    output = std::move(compressed);
    return true;
}

bool lzfse_decompress_exact(
    const Bytes& compressed,
    std::size_t expected,
    Bytes& output,
    std::string& error
) {
    const std::size_t scratch_size = lzfse_decode_scratch_size();
    Bytes scratch(scratch_size);
    output.resize(expected);

    const std::size_t written = lzfse_decode_buffer(
        output.data(),
        output.size(),
        compressed.data(),
        compressed.size(),
        scratch.data()
    );

    if (written != expected) {
        error = "LZFSE decompression size mismatch";
        return false;
    }

    return true;
}

bool validate_options(const AeaProfile1Options& options, std::string& error) {
    if (options.segment_size < 0x4000) {
        error = "segment_size must be at least 0x4000";
        return false;
    }
    if (options.segments_per_cluster < 32) {
        error = "segments_per_cluster must be at least 32";
        return false;
    }
    if (options.segment_size > std::numeric_limits<std::uint32_t>::max()) {
        error = "segment_size is too large";
        return false;
    }
    return true;
}

} // namespace

bool aea_profile1_encrypt(
    const std::vector<std::uint8_t>& plaintext,
    const std::vector<std::uint8_t>& symmetric_key,
    const std::vector<std::uint8_t>& auth_data,
    const AeaProfile1Options& options,
    std::vector<std::uint8_t>& archive,
    std::string& error
) {
    archive.clear();
    error.clear();

    if (symmetric_key.size() != 32) {
        error = "AEA profile 1 symmetric key must be exactly 32 bytes";
        return false;
    }
    if (!validate_options(options, error)) {
        return false;
    }
    if (auth_data.size() > std::numeric_limits<std::uint32_t>::max()) {
        error = "AEA auth data is too large";
        return false;
    }

    Bytes main_salt(32);
    if (!random_bytes(main_salt.data(), main_salt.size(), error)) {
        return false;
    }

    Bytes main_key;
    if (!derive_main_key(symmetric_key, main_salt, main_key, error)) {
        return false;
    }

    const std::uint64_t cluster_size =
        static_cast<std::uint64_t>(options.segment_size) *
        static_cast<std::uint64_t>(options.segments_per_cluster);

    const std::size_t cluster_count = plaintext.empty()
        ? 0
        : static_cast<std::size_t>(
            (static_cast<std::uint64_t>(plaintext.size()) + cluster_size - 1) /
            cluster_size
        );

    std::vector<Bytes> clusters(cluster_count);
    Digest next_cluster_mac{};
    if (!random_bytes(next_cluster_mac.data(), next_cluster_mac.size(), error)) {
        return false;
    }

    for (std::size_t reverse = cluster_count; reverse > 0; --reverse) {
        const std::size_t cluster_index = reverse - 1;

        Bytes cluster_key;
        if (!derive_key(
                main_key,
                {},
                info_with_index("AEA_CK", static_cast<std::uint32_t>(cluster_index)),
                32,
                cluster_key,
                error
            )) {
            return false;
        }

        KeyMaterial cluster_header_key;
        if (!derive_material(
                cluster_key,
                Bytes{'A','E','A','_','C','H','E','K'},
                cluster_header_key,
                error
            )) {
            return false;
        }

        Bytes segment_headers(
            static_cast<std::size_t>(options.segments_per_cluster) * kSegmentHeaderSize,
            0
        );
        Bytes segment_macs(
            static_cast<std::size_t>(options.segments_per_cluster) * kSha256Size,
            0
        );
        Bytes encrypted_segments;

        for (std::uint32_t segment_index = 0;
             segment_index < options.segments_per_cluster;
             ++segment_index) {
            const std::uint64_t absolute =
                static_cast<std::uint64_t>(cluster_index) * cluster_size +
                static_cast<std::uint64_t>(segment_index) * options.segment_size;

            std::uint8_t* header =
                segment_headers.data() +
                static_cast<std::size_t>(segment_index) * kSegmentHeaderSize;
            std::uint8_t* mac_slot =
                segment_macs.data() +
                static_cast<std::size_t>(segment_index) * kSha256Size;

            if (absolute >= plaintext.size()) {
                if (!random_bytes(mac_slot, kSha256Size, error)) {
                    return false;
                }
                continue;
            }

            const std::size_t original_size = std::min<std::size_t>(
                options.segment_size,
                plaintext.size() - static_cast<std::size_t>(absolute)
            );

            Digest checksum{};
            if (!sha256(
                    plaintext.data() + static_cast<std::size_t>(absolute),
                    original_size,
                    checksum,
                    error
                )) {
                return false;
            }

            Bytes compressed;
            if (!lzfse_compress_or_raw(
                    plaintext.data() + static_cast<std::size_t>(absolute),
                    original_size,
                    compressed,
                    error
                )) {
                return false;
            }

            Bytes segment_key_bytes;
            if (!derive_key(
                    cluster_key,
                    {},
                    info_with_index("AEA_SK", segment_index),
                    kKeyMaterialSize,
                    segment_key_bytes,
                    error
                )) {
                return false;
            }

            KeyMaterial segment_key;
            if (!to_key_material(segment_key_bytes, segment_key, error)) {
                return false;
            }

            Bytes encrypted;
            if (!aes_ctr(compressed, segment_key.aes, segment_key.iv, encrypted, error)) {
                return false;
            }

            Digest segment_mac{};
            if (!calculate_mac(segment_key.mac, encrypted, {}, segment_mac, error)) {
                return false;
            }

            put_u32(header, static_cast<std::uint32_t>(original_size));
            put_u32(header + 4, static_cast<std::uint32_t>(compressed.size()));
            std::copy(checksum.begin(), checksum.end(), header + 8);
            std::copy(segment_mac.begin(), segment_mac.end(), mac_slot);

            encrypted_segments.insert(
                encrypted_segments.end(),
                encrypted.begin(),
                encrypted.end()
            );
        }

        Bytes encrypted_headers;
        if (!aes_ctr(
                segment_headers,
                cluster_header_key.aes,
                cluster_header_key.iv,
                encrypted_headers,
                error
            )) {
            return false;
        }

        Bytes cluster_salt;
        cluster_salt.reserve(next_cluster_mac.size() + segment_macs.size());
        cluster_salt.insert(
            cluster_salt.end(),
            next_cluster_mac.begin(),
            next_cluster_mac.end()
        );
        cluster_salt.insert(
            cluster_salt.end(),
            segment_macs.begin(),
            segment_macs.end()
        );

        Digest cluster_mac{};
        if (!calculate_mac(
                cluster_header_key.mac,
                encrypted_headers,
                cluster_salt,
                cluster_mac,
                error
            )) {
            return false;
        }

        Bytes blob;
        blob.reserve(
            encrypted_headers.size() +
            next_cluster_mac.size() +
            segment_macs.size() +
            encrypted_segments.size()
        );
        blob.insert(blob.end(), encrypted_headers.begin(), encrypted_headers.end());
        blob.insert(blob.end(), next_cluster_mac.begin(), next_cluster_mac.end());
        blob.insert(blob.end(), segment_macs.begin(), segment_macs.end());
        blob.insert(blob.end(), encrypted_segments.begin(), encrypted_segments.end());

        clusters[cluster_index] = std::move(blob);
        next_cluster_mac = cluster_mac;
    }

    std::uint64_t archive_size =
        static_cast<std::uint64_t>(kPrologueFixedSize + auth_data.size());
    for (const auto& cluster : clusters) {
        archive_size += static_cast<std::uint64_t>(cluster.size());
    }

    RootHeader root{
        static_cast<std::uint64_t>(plaintext.size()),
        archive_size,
        options.segment_size,
        options.segments_per_cluster,
        kCompressionLzfse,
        kChecksumSha256
    };

    Bytes root_key_bytes;
    if (!derive_key(
            main_key,
            {},
            Bytes{'A','E','A','_','R','H','E','K'},
            kKeyMaterialSize,
            root_key_bytes,
            error
        )) {
        return false;
    }

    KeyMaterial root_key;
    if (!to_key_material(root_key_bytes, root_key, error)) {
        return false;
    }

    const Bytes root_plain = encode_root_header(root);
    Bytes root_encrypted;
    if (!aes_ctr(root_plain, root_key.aes, root_key.iv, root_encrypted, error)) {
        return false;
    }

    Bytes root_salt;
    root_salt.reserve(next_cluster_mac.size() + auth_data.size());
    root_salt.insert(root_salt.end(), next_cluster_mac.begin(), next_cluster_mac.end());
    root_salt.insert(root_salt.end(), auth_data.begin(), auth_data.end());

    Digest root_mac{};
    if (!calculate_mac(root_key.mac, root_encrypted, root_salt, root_mac, error)) {
        return false;
    }

    archive.reserve(static_cast<std::size_t>(archive_size));
    archive.insert(archive.end(), {'A','E','A','1'});
    append_u32(archive, kProfileSymmetric);
    append_u32(archive, static_cast<std::uint32_t>(auth_data.size()));
    archive.insert(archive.end(), auth_data.begin(), auth_data.end());
    archive.insert(archive.end(), main_salt.begin(), main_salt.end());
    archive.insert(archive.end(), root_mac.begin(), root_mac.end());
    archive.insert(archive.end(), root_encrypted.begin(), root_encrypted.end());
    archive.insert(archive.end(), next_cluster_mac.begin(), next_cluster_mac.end());

    for (const auto& cluster : clusters) {
        archive.insert(archive.end(), cluster.begin(), cluster.end());
    }

    if (archive.size() != archive_size) {
        error = "AEA encoded size reconciliation failed";
        archive.clear();
        return false;
    }

    return true;
}

bool aea_profile1_decrypt(
    const std::vector<std::uint8_t>& archive,
    const std::vector<std::uint8_t>& symmetric_key,
    AeaProfile1Decoded& decoded,
    std::string& error
) {
    decoded = {};
    error.clear();

    if (symmetric_key.size() != 32) {
        error = "AEA profile 1 symmetric key must be exactly 32 bytes";
        return false;
    }

    if (archive.size() < kPrologueFixedSize) {
        error = "AEA archive is too small";
        return false;
    }

    if (std::memcmp(archive.data(), "AEA1", 4) != 0) {
        error = "invalid AEA magic";
        return false;
    }

    const std::uint32_t profile_and_strength = read_u32(archive.data() + 4);
    const std::uint32_t profile = profile_and_strength & 0x00ffffffu;
    const std::uint8_t strength = static_cast<std::uint8_t>(profile_and_strength >> 24);

    if (profile != kProfileSymmetric || strength != kScryptStrength) {
        error = "unsupported AEA profile or scrypt strength";
        return false;
    }

    const std::uint32_t auth_size = read_u32(archive.data() + 8);
    const std::size_t prologue_size =
        kPrologueFixedSize + static_cast<std::size_t>(auth_size);

    if (prologue_size > archive.size()) {
        error = "AEA auth data length exceeds archive size";
        return false;
    }

    std::size_t cursor = kFileHeaderSize;
    decoded.auth_data.assign(
        archive.begin() + static_cast<std::ptrdiff_t>(cursor),
        archive.begin() + static_cast<std::ptrdiff_t>(cursor + auth_size)
    );
    cursor += auth_size;

    Bytes main_salt(
        archive.begin() + static_cast<std::ptrdiff_t>(cursor),
        archive.begin() + static_cast<std::ptrdiff_t>(cursor + 32)
    );
    cursor += 32;

    Digest root_mac{};
    std::copy_n(archive.begin() + static_cast<std::ptrdiff_t>(cursor), 32, root_mac.begin());
    cursor += 32;

    Bytes root_encrypted(
        archive.begin() + static_cast<std::ptrdiff_t>(cursor),
        archive.begin() + static_cast<std::ptrdiff_t>(cursor + kRootHeaderSize)
    );
    cursor += kRootHeaderSize;

    Digest cluster_mac{};
    std::copy_n(archive.begin() + static_cast<std::ptrdiff_t>(cursor), 32, cluster_mac.begin());
    cursor += 32;

    Bytes main_key;
    if (!derive_main_key(symmetric_key, main_salt, main_key, error)) {
        return false;
    }

    Bytes root_key_bytes;
    if (!derive_key(
            main_key,
            {},
            Bytes{'A','E','A','_','R','H','E','K'},
            kKeyMaterialSize,
            root_key_bytes,
            error
        )) {
        return false;
    }

    KeyMaterial root_key;
    if (!to_key_material(root_key_bytes, root_key, error)) {
        return false;
    }

    Bytes root_salt;
    root_salt.insert(root_salt.end(), cluster_mac.begin(), cluster_mac.end());
    root_salt.insert(root_salt.end(), decoded.auth_data.begin(), decoded.auth_data.end());

    Digest calculated_root_mac{};
    if (!calculate_mac(
            root_key.mac,
            root_encrypted,
            root_salt,
            calculated_root_mac,
            error
        )) {
        return false;
    }

    if (!secure_equal(root_mac.data(), calculated_root_mac.data(), root_mac.size())) {
        error = "AEA root header HMAC validation failed";
        return false;
    }

    Bytes root_plain;
    if (!aes_ctr(root_encrypted, root_key.aes, root_key.iv, root_plain, error)) {
        return false;
    }

    RootHeader root;
    if (!decode_root_header(root_plain, root, error)) {
        return false;
    }

    if (root.archive_size != archive.size()) {
        error = "AEA archive size field does not reconcile";
        return false;
    }

    decoded.segment_size = root.segment_size;
    decoded.segments_per_cluster = root.segments_per_cluster;
    decoded.plaintext.reserve(static_cast<std::size_t>(root.original_size));

    if (root.original_size == 0) {
        return true;
    }

    const std::size_t segment_headers_size =
        static_cast<std::size_t>(root.segments_per_cluster) * kSegmentHeaderSize;
    const std::size_t segment_macs_size =
        static_cast<std::size_t>(root.segments_per_cluster) * kSha256Size;

    std::uint32_t cluster_index = 0;

    while (decoded.plaintext.size() < root.original_size) {
        if (cursor + segment_headers_size + 32 + segment_macs_size > archive.size()) {
            error = "AEA cluster header exceeds archive size";
            return false;
        }

        Bytes cluster_key;
        if (!derive_key(
                main_key,
                {},
                info_with_index("AEA_CK", cluster_index),
                32,
                cluster_key,
                error
            )) {
            return false;
        }

        KeyMaterial cluster_header_key;
        if (!derive_material(
                cluster_key,
                Bytes{'A','E','A','_','C','H','E','K'},
                cluster_header_key,
                error
            )) {
            return false;
        }

        Bytes encrypted_headers(
            archive.begin() + static_cast<std::ptrdiff_t>(cursor),
            archive.begin() + static_cast<std::ptrdiff_t>(cursor + segment_headers_size)
        );
        cursor += segment_headers_size;

        Digest next_cluster_mac{};
        std::copy_n(
            archive.begin() + static_cast<std::ptrdiff_t>(cursor),
            32,
            next_cluster_mac.begin()
        );
        cursor += 32;

        Bytes segment_macs(
            archive.begin() + static_cast<std::ptrdiff_t>(cursor),
            archive.begin() + static_cast<std::ptrdiff_t>(cursor + segment_macs_size)
        );
        cursor += segment_macs_size;

        Bytes cluster_salt;
        cluster_salt.insert(
            cluster_salt.end(),
            next_cluster_mac.begin(),
            next_cluster_mac.end()
        );
        cluster_salt.insert(
            cluster_salt.end(),
            segment_macs.begin(),
            segment_macs.end()
        );

        Digest calculated_cluster_mac{};
        if (!calculate_mac(
                cluster_header_key.mac,
                encrypted_headers,
                cluster_salt,
                calculated_cluster_mac,
                error
            )) {
            return false;
        }

        if (!secure_equal(
                cluster_mac.data(),
                calculated_cluster_mac.data(),
                cluster_mac.size()
            )) {
            error = "AEA cluster header HMAC validation failed";
            return false;
        }

        Bytes segment_headers;
        if (!aes_ctr(
                encrypted_headers,
                cluster_header_key.aes,
                cluster_header_key.iv,
                segment_headers,
                error
            )) {
            return false;
        }

        for (std::uint32_t segment_index = 0;
             segment_index < root.segments_per_cluster &&
             decoded.plaintext.size() < root.original_size;
             ++segment_index) {
            const std::uint8_t* header =
                segment_headers.data() +
                static_cast<std::size_t>(segment_index) * kSegmentHeaderSize;

            const std::uint32_t original_size = read_u32(header);
            const std::uint32_t compressed_size = read_u32(header + 4);

            if (original_size == 0) {
                if (compressed_size != 0) {
                    error = "AEA empty segment has non-zero compressed size";
                    return false;
                }
                continue;
            }

            if (compressed_size == 0 || compressed_size > original_size) {
                error = "AEA segment has invalid compressed size";
                return false;
            }

            if (cursor + compressed_size > archive.size()) {
                error = "AEA segment data exceeds archive size";
                return false;
            }

            Bytes encrypted_segment(
                archive.begin() + static_cast<std::ptrdiff_t>(cursor),
                archive.begin() + static_cast<std::ptrdiff_t>(cursor + compressed_size)
            );
            cursor += compressed_size;

            Bytes segment_key_bytes;
            if (!derive_key(
                    cluster_key,
                    {},
                    info_with_index("AEA_SK", segment_index),
                    kKeyMaterialSize,
                    segment_key_bytes,
                    error
                )) {
                return false;
            }

            KeyMaterial segment_key;
            if (!to_key_material(segment_key_bytes, segment_key, error)) {
                return false;
            }

            Digest expected_segment_mac{};
            std::copy_n(
                segment_macs.begin() +
                    static_cast<std::ptrdiff_t>(segment_index * kSha256Size),
                kSha256Size,
                expected_segment_mac.begin()
            );

            Digest calculated_segment_mac{};
            if (!calculate_mac(
                    segment_key.mac,
                    encrypted_segment,
                    {},
                    calculated_segment_mac,
                    error
                )) {
                return false;
            }

            if (!secure_equal(
                    expected_segment_mac.data(),
                    calculated_segment_mac.data(),
                    expected_segment_mac.size()
                )) {
                error = "AEA segment HMAC validation failed";
                return false;
            }

            Bytes compressed;
            if (!aes_ctr(
                    encrypted_segment,
                    segment_key.aes,
                    segment_key.iv,
                    compressed,
                    error
                )) {
                return false;
            }

            Bytes plain;
            if (original_size > compressed_size) {
                if (!lzfse_decompress_exact(
                        compressed,
                        original_size,
                        plain,
                        error
                    )) {
                    return false;
                }
            } else {
                plain = std::move(compressed);
            }

            if (plain.size() != original_size) {
                error = "AEA segment plaintext size mismatch";
                return false;
            }

            Digest checksum{};
            if (!sha256(plain.data(), plain.size(), checksum, error)) {
                return false;
            }

            if (!secure_equal(header + 8, checksum.data(), checksum.size())) {
                error = "AEA segment SHA256 validation failed";
                return false;
            }

            const std::size_t remaining =
                static_cast<std::size_t>(root.original_size) -
                decoded.plaintext.size();

            if (plain.size() > remaining) {
                error = "AEA plaintext exceeds declared original size";
                return false;
            }

            decoded.plaintext.insert(
                decoded.plaintext.end(),
                plain.begin(),
                plain.end()
            );
        }

        cluster_mac = next_cluster_mac;
        ++cluster_index;
        ++decoded.cluster_count;
    }

    if (decoded.plaintext.size() != root.original_size) {
        error = "AEA plaintext size did not reconcile";
        return false;
    }

    if (cursor != archive.size()) {
        error = "AEA trailing bytes are not supported by the Phase 4D2A core";
        return false;
    }

    return true;
}


namespace {

constexpr std::uint64_t kStreamingCopyBuffer = 1024ull * 1024ull;
constexpr std::uint64_t kStreamingMaxAuthData = 16ull * 1024ull * 1024ull;

struct StreamingTempCleanup {
    std::vector<std::string> paths;
    ~StreamingTempCleanup() {
        for (const auto& path : paths) {
            DeleteFileA(path.c_str());
        }
    }
};

void note_peak(
    AeaProfile1FileResult& result,
    std::initializer_list<std::size_t> sizes
) {
    std::uint64_t total = 0;
    for (const auto value : sizes) {
        total += static_cast<std::uint64_t>(value);
    }
    result.peak_buffer_bytes = std::max(result.peak_buffer_bytes, total);
}

bool stream_file_size(
    std::ifstream& input,
    std::uint64_t& size,
    std::string& error
) {
    input.clear();
    input.seekg(0, std::ios::end);
    if (!input) {
        error = "could not seek input file";
        return false;
    }

    const std::streamoff end = input.tellg();
    if (end < 0) {
        error = "could not determine input file size";
        return false;
    }

    size = static_cast<std::uint64_t>(end);
    input.clear();
    input.seekg(0, std::ios::beg);
    return static_cast<bool>(input);
}

bool stream_read_exact(
    std::istream& input,
    void* data,
    std::size_t size,
    std::string& error
) {
    if (size == 0) {
        return true;
    }

    if (size > static_cast<std::size_t>(std::numeric_limits<std::streamsize>::max())) {
        error = "stream read size exceeds streamsize range";
        return false;
    }

    input.read(static_cast<char*>(data), static_cast<std::streamsize>(size));
    if (!input || input.gcount() != static_cast<std::streamsize>(size)) {
        error = "unexpected end of file";
        return false;
    }
    return true;
}

bool stream_read_region(
    std::ifstream& input,
    std::uint64_t offset,
    std::size_t size,
    Bytes& output,
    std::string& error
) {
    if (offset > static_cast<std::uint64_t>(std::numeric_limits<std::streamoff>::max())) {
        error = "file offset exceeds streamoff range";
        return false;
    }

    input.clear();
    input.seekg(static_cast<std::streamoff>(offset), std::ios::beg);
    if (!input) {
        error = "could not seek input region";
        return false;
    }

    output.resize(size);
    return stream_read_exact(input, output.data(), size, error);
}

bool stream_write_all(
    std::ostream& output,
    const void* data,
    std::size_t size,
    std::string& error
) {
    if (size == 0) {
        return true;
    }

    if (size > static_cast<std::size_t>(std::numeric_limits<std::streamsize>::max())) {
        error = "stream write size exceeds streamsize range";
        return false;
    }

    output.write(static_cast<const char*>(data), static_cast<std::streamsize>(size));
    if (!output) {
        error = "stream write failed";
        return false;
    }
    return true;
}

bool stream_write_bytes(
    std::ostream& output,
    const Bytes& data,
    std::string& error
) {
    return stream_write_all(output, data.data(), data.size(), error);
}

bool stream_replace_atomic(
    const std::string& temp,
    const std::string& target,
    std::string& error
) {
    if (!MoveFileExA(
            temp.c_str(),
            target.c_str(),
            MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH
        )) {
        const DWORD code = GetLastError();
        error = "MoveFileExA failed with Win32 error " + std::to_string(code);
        return false;
    }
    return true;
}

bool stream_copy_region(
    std::fstream& spool,
    std::uint64_t offset,
    std::uint64_t length,
    std::ofstream& output,
    Bytes& buffer,
    std::string& error
) {
    if (offset > static_cast<std::uint64_t>(std::numeric_limits<std::streamoff>::max())) {
        error = "spool offset exceeds streamoff range";
        return false;
    }

    spool.clear();
    spool.seekg(static_cast<std::streamoff>(offset), std::ios::beg);
    if (!spool) {
        error = "could not seek spool region";
        return false;
    }

    std::uint64_t remaining = length;
    while (remaining != 0) {
        const std::size_t chunk = static_cast<std::size_t>(
            std::min<std::uint64_t>(remaining, buffer.size())
        );
        if (!stream_read_exact(spool, buffer.data(), chunk, error)) {
            return false;
        }
        if (!stream_write_all(output, buffer.data(), chunk, error)) {
            return false;
        }
        remaining -= chunk;
    }

    return true;
}

bool stream_write_index_record(
    std::ofstream& index,
    std::uint64_t offset,
    std::uint64_t size,
    std::string& error
) {
    std::array<std::uint8_t, 16> record{};
    put_u64(record.data(), offset);
    put_u64(record.data() + 8, size);
    return stream_write_all(index, record.data(), record.size(), error);
}

bool stream_read_index_record(
    std::ifstream& index,
    std::uint64_t record_offset,
    std::uint64_t& offset,
    std::uint64_t& size,
    std::string& error
) {
    if (record_offset > static_cast<std::uint64_t>(std::numeric_limits<std::streamoff>::max())) {
        error = "index offset exceeds streamoff range";
        return false;
    }

    index.clear();
    index.seekg(static_cast<std::streamoff>(record_offset), std::ios::beg);
    if (!index) {
        error = "could not seek spool index";
        return false;
    }

    std::array<std::uint8_t, 16> record{};
    if (!stream_read_exact(index, record.data(), record.size(), error)) {
        return false;
    }

    offset = read_u64(record.data());
    size = read_u64(record.data() + 8);
    return true;
}

} // namespace

bool aea_profile1_encrypt_file_streaming(
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

    if (symmetric_key.size() != 32) {
        error = "AEA profile 1 symmetric key must be exactly 32 bytes";
        return false;
    }
    if (!validate_options(options, error)) {
        return false;
    }
    if (auth_data.size() > kStreamingMaxAuthData) {
        error = "AEA auth data exceeds Phase 4D2C streaming limit";
        return false;
    }

    std::ifstream input(input_path, std::ios::binary);
    if (!input) {
        error = "could not open input file: " + input_path;
        return false;
    }

    std::uint64_t input_size = 0;
    if (!stream_file_size(input, input_size, error)) {
        return false;
    }

    const std::uint64_t cluster_size =
        static_cast<std::uint64_t>(options.segment_size) *
        static_cast<std::uint64_t>(options.segments_per_cluster);

    const std::uint64_t cluster_count64 = input_size == 0
        ? 0
        : (input_size + cluster_size - 1) / cluster_size;

    if (cluster_count64 > std::numeric_limits<std::uint32_t>::max()) {
        error = "AEA cluster count exceeds profile 1 index range";
        return false;
    }

    const std::string spool_path = output_path + ".vphone.spool";
    const std::string index_path = output_path + ".vphone.spool.idx";
    const std::string temp_path = output_path + ".vphone.tmp";

    DeleteFileA(spool_path.c_str());
    DeleteFileA(index_path.c_str());
    DeleteFileA(temp_path.c_str());

    StreamingTempCleanup cleanup{{spool_path, index_path, temp_path}};

    std::fstream spool(
        spool_path,
        std::ios::binary | std::ios::in | std::ios::out | std::ios::trunc
    );
    std::ofstream index(index_path, std::ios::binary | std::ios::trunc);

    if (!spool || !index) {
        error = "could not create streaming spool files";
        return false;
    }

    Bytes main_salt(32);
    if (!random_bytes(main_salt.data(), main_salt.size(), error)) {
        return false;
    }

    Bytes main_key;
    if (!derive_main_key(symmetric_key, main_salt, main_key, error)) {
        return false;
    }

    Digest next_cluster_mac{};
    if (!random_bytes(next_cluster_mac.data(), next_cluster_mac.size(), error)) {
        return false;
    }

    Bytes plain;
    Bytes compressed;
    Bytes encrypted;
    Bytes encrypted_headers;
    Bytes cluster_salt;

    for (std::uint64_t reverse = cluster_count64; reverse > 0; --reverse) {
        const std::uint32_t cluster_index =
            static_cast<std::uint32_t>(reverse - 1);

        Bytes cluster_key;
        if (!derive_key(
                main_key,
                {},
                info_with_index("AEA_CK", cluster_index),
                32,
                cluster_key,
                error
            )) {
            return false;
        }

        KeyMaterial cluster_header_key;
        if (!derive_material(
                cluster_key,
                Bytes{'A','E','A','_','C','H','E','K'},
                cluster_header_key,
                error
            )) {
            return false;
        }

        Bytes segment_headers(
            static_cast<std::size_t>(options.segments_per_cluster) * kSegmentHeaderSize,
            0
        );
        Bytes segment_macs(
            static_cast<std::size_t>(options.segments_per_cluster) * kSha256Size,
            0
        );

        for (std::uint32_t segment_index = 0;
             segment_index < options.segments_per_cluster;
             ++segment_index) {
            const std::uint64_t absolute =
                static_cast<std::uint64_t>(cluster_index) * cluster_size +
                static_cast<std::uint64_t>(segment_index) * options.segment_size;

            std::uint8_t* header =
                segment_headers.data() +
                static_cast<std::size_t>(segment_index) * kSegmentHeaderSize;

            std::uint8_t* mac_slot =
                segment_macs.data() +
                static_cast<std::size_t>(segment_index) * kSha256Size;

            if (absolute >= input_size) {
                if (!random_bytes(mac_slot, kSha256Size, error)) {
                    return false;
                }
                continue;
            }

            const std::size_t original_size = static_cast<std::size_t>(
                std::min<std::uint64_t>(options.segment_size, input_size - absolute)
            );

            if (!stream_read_region(input, absolute, original_size, plain, error)) {
                return false;
            }

            Digest checksum{};
            if (!sha256(plain.data(), plain.size(), checksum, error)) {
                return false;
            }

            if (!lzfse_compress_or_raw(
                    plain.data(),
                    plain.size(),
                    compressed,
                    error
                )) {
                return false;
            }

            Bytes segment_key_bytes;
            if (!derive_key(
                    cluster_key,
                    {},
                    info_with_index("AEA_SK", segment_index),
                    kKeyMaterialSize,
                    segment_key_bytes,
                    error
                )) {
                return false;
            }

            KeyMaterial segment_key;
            if (!to_key_material(segment_key_bytes, segment_key, error)) {
                return false;
            }

            if (!aes_ctr(
                    compressed,
                    segment_key.aes,
                    segment_key.iv,
                    encrypted,
                    error
                )) {
                return false;
            }

            Digest segment_mac{};
            if (!calculate_mac(
                    segment_key.mac,
                    encrypted,
                    {},
                    segment_mac,
                    error
                )) {
                return false;
            }

            put_u32(header, static_cast<std::uint32_t>(plain.size()));
            put_u32(header + 4, static_cast<std::uint32_t>(compressed.size()));
            std::copy(checksum.begin(), checksum.end(), header + 8);
            std::copy(segment_mac.begin(), segment_mac.end(), mac_slot);

            note_peak(
                result,
                {
                    plain.capacity(),
                    compressed.capacity(),
                    encrypted.capacity(),
                    segment_headers.capacity(),
                    segment_macs.capacity()
                }
            );
        }

        if (!aes_ctr(
                segment_headers,
                cluster_header_key.aes,
                cluster_header_key.iv,
                encrypted_headers,
                error
            )) {
            return false;
        }

        cluster_salt.clear();
        cluster_salt.reserve(next_cluster_mac.size() + segment_macs.size());
        cluster_salt.insert(
            cluster_salt.end(),
            next_cluster_mac.begin(),
            next_cluster_mac.end()
        );
        cluster_salt.insert(
            cluster_salt.end(),
            segment_macs.begin(),
            segment_macs.end()
        );

        Digest cluster_mac{};
        if (!calculate_mac(
                cluster_header_key.mac,
                encrypted_headers,
                cluster_salt,
                cluster_mac,
                error
            )) {
            return false;
        }

        spool.clear();
        spool.seekp(0, std::ios::end);
        const std::streamoff begin_off = spool.tellp();
        if (begin_off < 0) {
            error = "could not determine spool offset";
            return false;
        }

        const std::uint64_t blob_offset = static_cast<std::uint64_t>(begin_off);

        if (!stream_write_bytes(spool, encrypted_headers, error) ||
            !stream_write_all(
                spool,
                next_cluster_mac.data(),
                next_cluster_mac.size(),
                error
            ) ||
            !stream_write_bytes(spool, segment_macs, error)) {
            return false;
        }

        for (std::uint32_t segment_index = 0;
             segment_index < options.segments_per_cluster;
             ++segment_index) {
            const std::uint8_t* header =
                segment_headers.data() +
                static_cast<std::size_t>(segment_index) * kSegmentHeaderSize;

            const std::uint32_t original_size = read_u32(header);
            const std::uint32_t compressed_size = read_u32(header + 4);

            if (original_size == 0) {
                continue;
            }

            const std::uint64_t absolute =
                static_cast<std::uint64_t>(cluster_index) * cluster_size +
                static_cast<std::uint64_t>(segment_index) * options.segment_size;

            if (!stream_read_region(input, absolute, original_size, plain, error)) {
                return false;
            }

            if (!lzfse_compress_or_raw(
                    plain.data(),
                    plain.size(),
                    compressed,
                    error
                )) {
                return false;
            }

            if (compressed.size() != compressed_size) {
                error = "AEA streaming compression was not deterministic";
                return false;
            }

            Bytes segment_key_bytes;
            if (!derive_key(
                    cluster_key,
                    {},
                    info_with_index("AEA_SK", segment_index),
                    kKeyMaterialSize,
                    segment_key_bytes,
                    error
                )) {
                return false;
            }

            KeyMaterial segment_key;
            if (!to_key_material(segment_key_bytes, segment_key, error)) {
                return false;
            }

            if (!aes_ctr(
                    compressed,
                    segment_key.aes,
                    segment_key.iv,
                    encrypted,
                    error
                )) {
                return false;
            }

            if (!stream_write_bytes(spool, encrypted, error)) {
                return false;
            }

            note_peak(
                result,
                {
                    plain.capacity(),
                    compressed.capacity(),
                    encrypted.capacity(),
                    segment_headers.capacity(),
                    segment_macs.capacity(),
                    encrypted_headers.capacity(),
                    cluster_salt.capacity()
                }
            );
        }

        const std::streamoff end_off = spool.tellp();
        if (end_off < begin_off) {
            error = "spool offset reconciliation failed";
            return false;
        }

        const std::uint64_t blob_size =
            static_cast<std::uint64_t>(end_off - begin_off);

        if (!stream_write_index_record(
                index,
                blob_offset,
                blob_size,
                error
            )) {
            return false;
        }

        next_cluster_mac = cluster_mac;
    }

    spool.flush();
    index.flush();
    if (!spool || !index) {
        error = "could not flush streaming spool";
        return false;
    }

    spool.seekp(0, std::ios::end);
    const std::streamoff spool_end = spool.tellp();
    if (spool_end < 0) {
        error = "could not determine spool size";
        return false;
    }

    const std::uint64_t payload_size = static_cast<std::uint64_t>(spool_end);
    const std::uint64_t archive_size =
        static_cast<std::uint64_t>(kPrologueFixedSize) +
        static_cast<std::uint64_t>(auth_data.size()) +
        payload_size;

    RootHeader root{
        input_size,
        archive_size,
        options.segment_size,
        options.segments_per_cluster,
        kCompressionLzfse,
        kChecksumSha256
    };

    Bytes root_key_bytes;
    if (!derive_key(
            main_key,
            {},
            Bytes{'A','E','A','_','R','H','E','K'},
            kKeyMaterialSize,
            root_key_bytes,
            error
        )) {
        return false;
    }

    KeyMaterial root_key;
    if (!to_key_material(root_key_bytes, root_key, error)) {
        return false;
    }

    const Bytes root_plain = encode_root_header(root);
    Bytes root_encrypted;
    if (!aes_ctr(
            root_plain,
            root_key.aes,
            root_key.iv,
            root_encrypted,
            error
        )) {
        return false;
    }

    Bytes root_salt;
    root_salt.reserve(next_cluster_mac.size() + auth_data.size());
    root_salt.insert(
        root_salt.end(),
        next_cluster_mac.begin(),
        next_cluster_mac.end()
    );
    root_salt.insert(
        root_salt.end(),
        auth_data.begin(),
        auth_data.end()
    );

    Digest root_mac{};
    if (!calculate_mac(
            root_key.mac,
            root_encrypted,
            root_salt,
            root_mac,
            error
        )) {
        return false;
    }

    std::ofstream output(temp_path, std::ios::binary | std::ios::trunc);
    if (!output) {
        error = "could not create temporary AEA output";
        return false;
    }

    Bytes file_header;
    file_header.insert(file_header.end(), {'A','E','A','1'});
    append_u32(file_header, kProfileSymmetric);
    append_u32(file_header, static_cast<std::uint32_t>(auth_data.size()));

    if (!stream_write_bytes(output, file_header, error) ||
        !stream_write_bytes(output, auth_data, error) ||
        !stream_write_bytes(output, main_salt, error) ||
        !stream_write_all(output, root_mac.data(), root_mac.size(), error) ||
        !stream_write_bytes(output, root_encrypted, error) ||
        !stream_write_all(
            output,
            next_cluster_mac.data(),
            next_cluster_mac.size(),
            error
        )) {
        return false;
    }

    index.close();
    std::ifstream index_read(index_path, std::ios::binary);
    if (!index_read) {
        error = "could not reopen spool index";
        return false;
    }

    Bytes copy_buffer(static_cast<std::size_t>(kStreamingCopyBuffer));
    note_peak(
        result,
        {
            copy_buffer.capacity(),
            auth_data.size(),
            root_salt.capacity(),
            root_encrypted.capacity()
        }
    );

    for (std::uint64_t record = 0; record < cluster_count64; ++record) {
        const std::uint64_t reverse_record =
            cluster_count64 - 1 - record;

        const std::uint64_t record_offset = reverse_record * 16ull;
        std::uint64_t blob_offset = 0;
        std::uint64_t blob_size = 0;

        if (!stream_read_index_record(
                index_read,
                record_offset,
                blob_offset,
                blob_size,
                error
            )) {
            return false;
        }

        if (!stream_copy_region(
                spool,
                blob_offset,
                blob_size,
                output,
                copy_buffer,
                error
            )) {
            return false;
        }
    }

    output.flush();
    if (!output) {
        error = "could not flush final AEA output";
        return false;
    }
    output.close();
    spool.close();
    index_read.close();

    std::ifstream reconcile(temp_path, std::ios::binary);
    if (!reconcile) {
        error = "could not reopen final AEA output";
        return false;
    }

    std::uint64_t final_size = 0;
    if (!stream_file_size(reconcile, final_size, error)) {
        return false;
    }

    if (final_size != archive_size) {
        error = "AEA streaming encoded size reconciliation failed";
        return false;
    }

    // Windows does not allow MoveFileEx(REPLACE_EXISTING) while this process
    // still holds the temporary file open without delete sharing.
    reconcile.close();

    if (!stream_replace_atomic(temp_path, output_path, error)) {
        return false;
    }

    result.input_size = input_size;
    result.output_size = archive_size;
    result.cluster_count = static_cast<std::size_t>(cluster_count64);
    return true;
}

bool aea_profile1_decrypt_file_streaming(
    const std::string& input_path,
    const std::string& output_path,
    const std::vector<std::uint8_t>& symmetric_key,
    AeaProfile1FileResult& result,
    std::string& error
) {
    result = {};
    error.clear();

    if (symmetric_key.size() != 32) {
        error = "AEA profile 1 symmetric key must be exactly 32 bytes";
        return false;
    }

    std::ifstream input(input_path, std::ios::binary);
    if (!input) {
        error = "could not open AEA input file";
        return false;
    }

    std::uint64_t archive_size = 0;
    if (!stream_file_size(input, archive_size, error)) {
        return false;
    }

    if (archive_size < kPrologueFixedSize) {
        error = "AEA archive is too small";
        return false;
    }

    std::array<std::uint8_t, kFileHeaderSize> file_header{};
    if (!stream_read_exact(
            input,
            file_header.data(),
            file_header.size(),
            error
        )) {
        return false;
    }

    if (std::memcmp(file_header.data(), "AEA1", 4) != 0) {
        error = "invalid AEA magic";
        return false;
    }

    const std::uint32_t profile_and_strength =
        read_u32(file_header.data() + 4);

    const std::uint32_t profile =
        profile_and_strength & 0x00ffffffu;

    const std::uint8_t strength =
        static_cast<std::uint8_t>(profile_and_strength >> 24);

    if (profile != kProfileSymmetric || strength != kScryptStrength) {
        error = "unsupported AEA profile or scrypt strength";
        return false;
    }

    const std::uint32_t auth_size =
        read_u32(file_header.data() + 8);

    if (auth_size > kStreamingMaxAuthData) {
        error = "AEA auth data exceeds Phase 4D2C streaming limit";
        return false;
    }

    const std::uint64_t prologue_size =
        static_cast<std::uint64_t>(kPrologueFixedSize) +
        static_cast<std::uint64_t>(auth_size);

    if (prologue_size > archive_size) {
        error = "AEA auth data length exceeds archive size";
        return false;
    }

    Bytes auth_data(auth_size);
    Bytes main_salt(32);
    Digest root_mac{};
    Bytes root_encrypted(kRootHeaderSize);
    Digest cluster_mac{};

    if (!stream_read_exact(input, auth_data.data(), auth_data.size(), error) ||
        !stream_read_exact(input, main_salt.data(), main_salt.size(), error) ||
        !stream_read_exact(input, root_mac.data(), root_mac.size(), error) ||
        !stream_read_exact(
            input,
            root_encrypted.data(),
            root_encrypted.size(),
            error
        ) ||
        !stream_read_exact(
            input,
            cluster_mac.data(),
            cluster_mac.size(),
            error
        )) {
        return false;
    }

    std::uint64_t consumed = prologue_size;

    Bytes main_key;
    if (!derive_main_key(symmetric_key, main_salt, main_key, error)) {
        return false;
    }

    Bytes root_key_bytes;
    if (!derive_key(
            main_key,
            {},
            Bytes{'A','E','A','_','R','H','E','K'},
            kKeyMaterialSize,
            root_key_bytes,
            error
        )) {
        return false;
    }

    KeyMaterial root_key;
    if (!to_key_material(root_key_bytes, root_key, error)) {
        return false;
    }

    Bytes root_salt;
    root_salt.insert(
        root_salt.end(),
        cluster_mac.begin(),
        cluster_mac.end()
    );
    root_salt.insert(
        root_salt.end(),
        auth_data.begin(),
        auth_data.end()
    );

    Digest calculated_root_mac{};
    if (!calculate_mac(
            root_key.mac,
            root_encrypted,
            root_salt,
            calculated_root_mac,
            error
        )) {
        return false;
    }

    if (!secure_equal(
            root_mac.data(),
            calculated_root_mac.data(),
            root_mac.size()
        )) {
        error = "AEA root header HMAC validation failed";
        return false;
    }

    Bytes root_plain;
    if (!aes_ctr(
            root_encrypted,
            root_key.aes,
            root_key.iv,
            root_plain,
            error
        )) {
        return false;
    }

    RootHeader root;
    if (!decode_root_header(root_plain, root, error)) {
        return false;
    }

    if (root.archive_size != archive_size) {
        error = "AEA archive size field does not reconcile";
        return false;
    }

    const std::string temp_path = output_path + ".vphone.tmp";
    DeleteFileA(temp_path.c_str());
    StreamingTempCleanup cleanup{{temp_path}};

    std::ofstream output(temp_path, std::ios::binary | std::ios::trunc);
    if (!output) {
        error = "could not create temporary plaintext output";
        return false;
    }

    if (root.original_size == 0) {
        if (consumed != archive_size) {
            error = "AEA empty archive contains unexpected payload";
            return false;
        }

        output.close();
        if (!stream_replace_atomic(temp_path, output_path, error)) {
            return false;
        }

        result.input_size = archive_size;
        result.output_size = 0;
        result.cluster_count = 0;
        note_peak(
            result,
            {
                auth_data.capacity(),
                root_salt.capacity(),
                root_plain.capacity(),
                root_encrypted.capacity()
            }
        );
        return true;
    }

    const std::size_t segment_headers_size =
        static_cast<std::size_t>(root.segments_per_cluster) *
        kSegmentHeaderSize;

    const std::size_t segment_macs_size =
        static_cast<std::size_t>(root.segments_per_cluster) *
        kSha256Size;

    std::uint64_t written_plain = 0;
    std::uint32_t cluster_index = 0;

    Bytes encrypted_headers(segment_headers_size);
    Bytes segment_macs(segment_macs_size);
    Bytes cluster_salt;
    Bytes segment_headers;
    Bytes encrypted_segment;
    Bytes compressed;
    Bytes plain;

    while (written_plain < root.original_size) {
        const std::uint64_t fixed_cluster_header =
            static_cast<std::uint64_t>(segment_headers_size) +
            32ull +
            static_cast<std::uint64_t>(segment_macs_size);

        if (consumed + fixed_cluster_header > archive_size) {
            error = "AEA cluster header exceeds archive size";
            return false;
        }

        Bytes cluster_key;
        if (!derive_key(
                main_key,
                {},
                info_with_index("AEA_CK", cluster_index),
                32,
                cluster_key,
                error
            )) {
            return false;
        }

        KeyMaterial cluster_header_key;
        if (!derive_material(
                cluster_key,
                Bytes{'A','E','A','_','C','H','E','K'},
                cluster_header_key,
                error
            )) {
            return false;
        }

        Digest next_cluster_mac{};

        if (!stream_read_exact(
                input,
                encrypted_headers.data(),
                encrypted_headers.size(),
                error
            ) ||
            !stream_read_exact(
                input,
                next_cluster_mac.data(),
                next_cluster_mac.size(),
                error
            ) ||
            !stream_read_exact(
                input,
                segment_macs.data(),
                segment_macs.size(),
                error
            )) {
            return false;
        }

        consumed += fixed_cluster_header;

        cluster_salt.clear();
        cluster_salt.insert(
            cluster_salt.end(),
            next_cluster_mac.begin(),
            next_cluster_mac.end()
        );
        cluster_salt.insert(
            cluster_salt.end(),
            segment_macs.begin(),
            segment_macs.end()
        );

        Digest calculated_cluster_mac{};
        if (!calculate_mac(
                cluster_header_key.mac,
                encrypted_headers,
                cluster_salt,
                calculated_cluster_mac,
                error
            )) {
            return false;
        }

        if (!secure_equal(
                cluster_mac.data(),
                calculated_cluster_mac.data(),
                cluster_mac.size()
            )) {
            error = "AEA cluster header HMAC validation failed";
            return false;
        }

        if (!aes_ctr(
                encrypted_headers,
                cluster_header_key.aes,
                cluster_header_key.iv,
                segment_headers,
                error
            )) {
            return false;
        }

        for (std::uint32_t segment_index = 0;
             segment_index < root.segments_per_cluster &&
             written_plain < root.original_size;
             ++segment_index) {
            const std::uint8_t* header =
                segment_headers.data() +
                static_cast<std::size_t>(segment_index) * kSegmentHeaderSize;

            const std::uint32_t original_size = read_u32(header);
            const std::uint32_t compressed_size = read_u32(header + 4);

            if (original_size == 0) {
                if (compressed_size != 0) {
                    error = "AEA empty segment has non-zero compressed size";
                    return false;
                }
                continue;
            }

            if (compressed_size == 0 || compressed_size > original_size) {
                error = "AEA segment has invalid compressed size";
                return false;
            }

            if (consumed + compressed_size > archive_size) {
                error = "AEA segment data exceeds archive size";
                return false;
            }

            encrypted_segment.resize(compressed_size);
            if (!stream_read_exact(
                    input,
                    encrypted_segment.data(),
                    encrypted_segment.size(),
                    error
                )) {
                return false;
            }
            consumed += compressed_size;

            Bytes segment_key_bytes;
            if (!derive_key(
                    cluster_key,
                    {},
                    info_with_index("AEA_SK", segment_index),
                    kKeyMaterialSize,
                    segment_key_bytes,
                    error
                )) {
                return false;
            }

            KeyMaterial segment_key;
            if (!to_key_material(segment_key_bytes, segment_key, error)) {
                return false;
            }

            Digest expected_segment_mac{};
            std::copy_n(
                segment_macs.begin() +
                    static_cast<std::ptrdiff_t>(segment_index * kSha256Size),
                kSha256Size,
                expected_segment_mac.begin()
            );

            Digest calculated_segment_mac{};
            if (!calculate_mac(
                    segment_key.mac,
                    encrypted_segment,
                    {},
                    calculated_segment_mac,
                    error
                )) {
                return false;
            }

            if (!secure_equal(
                    expected_segment_mac.data(),
                    calculated_segment_mac.data(),
                    expected_segment_mac.size()
                )) {
                error = "AEA segment HMAC validation failed";
                return false;
            }

            if (!aes_ctr(
                    encrypted_segment,
                    segment_key.aes,
                    segment_key.iv,
                    compressed,
                    error
                )) {
                return false;
            }

            if (original_size > compressed_size) {
                if (!lzfse_decompress_exact(
                        compressed,
                        original_size,
                        plain,
                        error
                    )) {
                    return false;
                }
            } else {
                plain = compressed;
            }

            if (plain.size() != original_size) {
                error = "AEA segment plaintext size mismatch";
                return false;
            }

            Digest checksum{};
            if (!sha256(plain.data(), plain.size(), checksum, error)) {
                return false;
            }

            if (!secure_equal(
                    header + 8,
                    checksum.data(),
                    checksum.size()
                )) {
                error = "AEA segment SHA256 validation failed";
                return false;
            }

            const std::uint64_t remaining =
                root.original_size - written_plain;

            if (plain.size() > remaining) {
                error = "AEA plaintext exceeds declared original size";
                return false;
            }

            if (!stream_write_bytes(output, plain, error)) {
                return false;
            }

            written_plain += plain.size();

            note_peak(
                result,
                {
                    auth_data.capacity(),
                    encrypted_headers.capacity(),
                    segment_macs.capacity(),
                    cluster_salt.capacity(),
                    segment_headers.capacity(),
                    encrypted_segment.capacity(),
                    compressed.capacity(),
                    plain.capacity()
                }
            );
        }

        cluster_mac = next_cluster_mac;
        ++cluster_index;
    }

    if (written_plain != root.original_size) {
        error = "AEA plaintext size did not reconcile";
        return false;
    }

    if (consumed != archive_size) {
        error = "AEA trailing bytes are not supported by streaming backend";
        return false;
    }

    output.flush();
    if (!output) {
        error = "could not flush plaintext output";
        return false;
    }
    output.close();

    if (!stream_replace_atomic(temp_path, output_path, error)) {
        return false;
    }

    result.input_size = archive_size;
    result.output_size = root.original_size;
    result.cluster_count = cluster_index;
    return true;
}

} // namespace vphone
