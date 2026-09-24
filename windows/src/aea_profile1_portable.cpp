#define NOMINMAX
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <bcrypt.h>

#include "vphone/aea_profile1_portable.hpp"

#include <lzfse.h>

#include <algorithm>
#include <array>
#include <cstring>
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

} // namespace vphone
