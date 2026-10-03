// Semantic plist integration driver: proves the REAL
// apfs_resize_plist_payload_safe function is invoked through the
// same validate-first wrapper used by the unit spy test, against
// the private (never committed) real fixture.
//
// Usage:
//   vphone_apfs_semantic_integration_test \
//       <source-image> <output-image> <payload-file> <cnid>
//   vphone_apfs_semantic_integration_test \
//       --invalid <source-image> <output-image> <bad-payload> <cnid>
//
// Valid payload path requirements:
//   - real_apfs_call_count == 1
//   - output image exists and structural reread succeeds
//   - reread payload length == 712 and SHA-256 equals the
//     semantic fixture hash
//   - source image SHA-256 unchanged
// Invalid payload path requirements:
//   - stale output removed as SETUP ONLY (no post-call deletion)
//   - real_apfs_call_count == 0
//   - output absent after the run
//   - source SHA-256 unchanged

#include "vphone/apfs_reader.hpp"
#include "vphone/semantic_wrapper.hpp"

#include <windows.h>
#include <wincrypt.h>

#include <cstdlib>
#include <cstdint>
#include <cstdio>
#include <fstream>
#include <string>
#include <vector>

namespace {

// SHA-256 of a FILE (the source-image immutability check).
std::string sha256_file_hex(const std::string& path) {
    HCRYPTPROV prov = 0;
    HCRYPTHASH hash = 0;
    std::string out;
    if (!CryptAcquireContextW(
            &prov, nullptr, nullptr, PROV_RSA_AES,
            CRYPT_VERIFYCONTEXT)) {
        return out;
    }
    if (!CryptCreateHash(prov, CALG_SHA_256, 0, 0, &hash)) {
        CryptReleaseContext(prov, 0);
        return out;
    }
    HANDLE f = CreateFileA(
        path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr,
        OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (f != INVALID_HANDLE_VALUE) {
        std::vector<unsigned char> buf(1 << 20);
        DWORD n = 0;
        while (ReadFile(f, buf.data(),
                        static_cast<DWORD>(buf.size()),
                        &n, nullptr) &&
               n > 0) {
            CryptHashData(hash, buf.data(), n, 0);
        }
        CloseHandle(f);
    }
    BYTE digest[32];
    DWORD len = 32;
    if (CryptGetHashParam(
            hash, HP_HASHVAL, digest, &len, 0) &&
        len == 32) {
        char hex[65];
        for (DWORD i = 0; i < 32; ++i) {
            std::snprintf(
                hex + i * 2, 3, "%02x", digest[i]);
        }
        hex[64] = '\0';
        out = hex;
    }
    CryptDestroyHash(hash);
    CryptReleaseContext(prov, 0);
    return out;
}

// SHA-256 of an in-memory buffer (the reread payload check).
std::string sha256_hex(
    const std::vector<std::uint8_t>& data
) {
    HCRYPTPROV prov = 0;
    HCRYPTHASH hash = 0;
    std::string out;
    if (!CryptAcquireContextW(
            &prov, nullptr, nullptr, PROV_RSA_AES,
            CRYPT_VERIFYCONTEXT)) {
        return out;
    }
    if (CryptCreateHash(prov, CALG_SHA_256, 0, 0, &hash)) {
        if (CryptHashData(
                hash,
                const_cast<BYTE*>(data.data()),
                static_cast<DWORD>(data.size()), 0)) {
            BYTE digest[32];
            DWORD len = 32;
            if (CryptGetHashParam(
                    hash, HP_HASHVAL, digest, &len, 0) &&
                len == 32) {
                char hex[65];
                for (DWORD i = 0; i < 32; ++i) {
                    std::snprintf(
                        hex + i * 2, 3,
                        "%02x", digest[i]);
                }
                hex[64] = '\0';
                out = hex;
            }
        }
        CryptDestroyHash(hash);
    }
    CryptReleaseContext(prov, 0);
    return out;
}

bool read_file(
    const std::string& path, std::vector<std::uint8_t>& out
) {
    std::ifstream f(path, std::ios::binary | std::ios::ate);
    if (!f) {
        return false;
    }
    const std::streamsize size = f.tellg();
    if (size < 0) {
        return false;
    }
    out.resize(static_cast<std::size_t>(size));
    f.seekg(0, std::ios::beg);
    f.read(reinterpret_cast<char*>(out.data()), size);
    return static_cast<std::streamsize>(f.gcount()) == size;
}

bool file_exists(const std::string& path) {
    const DWORD attr = GetFileAttributesA(path.c_str());
    return attr != INVALID_FILE_ATTRIBUTES;
}

bool read_reread_payload(
    const std::string& image_path,
    std::uint64_t cnid,
    std::vector<std::uint8_t>& payload,
    std::string& error
) {
    vphone::ApfsReaderReport report;
    if (!vphone::apfs_read_container(
            image_path, report, error)) {
        error = "reread failed: " + error;
        return false;
    }
    if (report.plist_file.status != "READ_OK" ||
        report.plist_file.drec_cnid != cnid) {
        error =
            "reread plist not READ_OK or CNID mismatch ("
            "status=" + report.plist_file.status + ")";
        return false;
    }
    payload = report.plist_file.bytes;
    return true;
}

} // namespace

int main(int argc, char** argv) {
    const bool invalid_mode =
        argc >= 2 && std::string(argv[1]) == "--invalid";
    const int expected_argc = invalid_mode ? 6 : 5;
    if (argc != expected_argc) {
        std::fprintf(
            stderr,
            "usage: %s <source> <output> <payload> <cnid>\n"
            "       %s --invalid <source> <output> <bad-payload> <cnid>\n",
            argv[0], argv[0]);
        return 64;
    }

    const int path_base = invalid_mode ? 2 : 1;
    const std::string source =
        argv[path_base];
    const std::string output =
        argv[path_base + 1];
    const std::string payload_path =
        argv[path_base + 2];
    const std::uint64_t cnid =
        static_cast<std::uint64_t>(
            std::strtoull(argv[path_base + 3], nullptr, 10));

    int failures = 0;
    std::vector<std::uint8_t> payload;
    if (!read_file(payload_path, payload)) {
        std::fprintf(
            stderr, "cannot read payload file: %s\n",
            payload_path.c_str());
        return 1;
    }

    // SETUP ONLY: remove a stale output before running so the
    // absence check measures this run, not a previous one.
    DeleteFileA(output.c_str());

    const std::string source_before = sha256_file_hex(source);
    if (source_before.empty()) {
        std::fprintf(
            stderr, "cannot hash source image: %s\n",
            source.c_str());
        return 1;
    }

    // The resize API's expected_source_sha256 is the SHA-256 of the
    // EMBEDDED PLIST PAYLOAD, not of the whole image. Resolve it
    // structurally from the source so the driver never hardcodes a
    // source hash.
    std::string source_plist_sha;
    {
        vphone::ApfsReaderReport report;
        std::string read_error;
        if (!vphone::apfs_read_container(
                source, report, read_error) ||
            report.plist_file.status != "READ_OK" ||
            report.plist_file.drec_cnid != cnid) {
            std::fprintf(
                stderr,
                "source plist not READ_OK for CNID %llu: %s\n",
                static_cast<unsigned long long>(cnid),
                read_error.c_str());
            return 1;
        }
        source_plist_sha =
            sha256_hex(report.plist_file.bytes);
        if (source_plist_sha.empty()) {
            std::fprintf(
                stderr, "cannot hash source plist payload\n");
            return 1;
        }
    }

    // Count REAL apfs_resize_plist_payload_safe invocations.
    int real_apfs_call_count = 0;
    vphone::SemanticMutationFn mutation_fn =
        [&](const std::vector<std::uint8_t>& p,
            std::string& error) -> bool {
        ++real_apfs_call_count;
        vphone::ApfsMutationResult result;
        if (!vphone::apfs_resize_plist_payload_safe(
                source, output, source_plist_sha, cnid, p,
                result, error)) {
            return false;
        }
        if (!result.success || !result.reread_verified) {
            error =
                "resize succeeded but certification failed";
            return false;
        }
        return true;
    };

    const vphone::SemanticMutationResult r =
        vphone::semantic_mutate(payload, mutation_fn);

    const std::string source_after = sha256_file_hex(source);

    if (invalid_mode) {
        // Validation must refuse BEFORE any real APFS call.
        if (r.exit_code != 1 ||
            r.mutation_invoked ||
            real_apfs_call_count != 0) {
            std::fprintf(
                stderr,
                "[invalid] exit=%d invoked=%d "
                "real_calls=%d\n",
                r.exit_code,
                r.mutation_invoked ? 1 : 0,
                real_apfs_call_count);
            ++failures;
        } else {
            std::printf(
                "SEMANTIC_INVALID_PLIST_PREWRITE_REFUSED_PASS\n");
            std::printf(
                "SEMANTIC_INVALID_PLIST_NO_APFS_WRITE_PASS "
                "call_count=0\n");
        }
        // No post-call deletion: assert the output is absent.
        if (file_exists(output)) {
            std::fprintf(
                stderr, "[invalid] output exists\n");
            ++failures;
        } else {
            std::printf(
                "SEMANTIC_INVALID_PLIST_NO_OUTPUT_PASS\n");
        }
        if (source_after != source_before) {
            std::fprintf(
                stderr, "[invalid] source changed\n");
            ++failures;
        } else {
            std::printf(
                "SEMANTIC_INVALID_PLIST_SOURCE_UNCHANGED_PASS\n");
        }
    } else {
        // The semantic fixture payload is exactly 712 bytes.
        if (payload.size() != 712) {
            std::fprintf(
                stderr,
                "[valid] payload size is %zu, expected 712\n",
                payload.size());
            ++failures;
        }
        if (r.exit_code != 0 ||
            !r.mutation_invoked ||
            !r.mutation_ok ||
            real_apfs_call_count != 1) {
            std::fprintf(
                stderr,
                "[valid] exit=%d invoked=%d real_calls=%d "
                "err=%s\n",
                r.exit_code,
                r.mutation_invoked ? 1 : 0,
                real_apfs_call_count, r.error.c_str());
            ++failures;
        } else {
            std::printf(
                "SEMANTIC_REAL_APFS_CALL_PASS "
                "real_apfs_call_count=1\n");
        }

        if (!file_exists(output)) {
            std::fprintf(
                stderr, "[valid] output missing\n");
            ++failures;
        } else {
            std::printf(
                "SEMANTIC_REAL_OUTPUT_CREATED_PASS\n");
        }

        std::vector<std::uint8_t> reread;
        std::string reread_error;
        if (!read_reread_payload(
                output, cnid, reread, reread_error)) {
            std::fprintf(
                stderr,
                "[valid] structural reread failed: %s\n",
                reread_error.c_str());
            ++failures;
        } else {
            std::printf(
                "SEMANTIC_REAL_STRUCTURAL_REREAD_PASS\n");
            const std::string expected_sha =
                "642f2bd79231aeb2993c22c740c7d08eac"
                "325bcb8e60857c2f46bba16f934859";
            const std::string reread_sha =
                sha256_hex(reread);
            if (reread.size() != 712 ||
                reread_sha != expected_sha) {
                std::fprintf(
                    stderr,
                    "[valid] reread mismatch: size=%zu "
                    "sha=%s\n",
                    reread.size(), reread_sha.c_str());
                ++failures;
            } else {
                std::printf(
                    "SEMANTIC_REAL_712_PAYLOAD_MATCH_PASS "
                    "size=%zu sha=%s\n",
                    reread.size(), reread_sha.c_str());
            }
        }

        if (source_after != source_before) {
            std::fprintf(
                stderr, "[valid] source changed\n");
            ++failures;
        } else {
            std::printf(
                "SEMANTIC_REAL_SOURCE_UNCHANGED_PASS\n");
        }
    }

    if (failures == 0) {
        std::printf(
            "SEMANTIC_INTEGRATION_TEST_PASS\n");
        return 0;
    }
    std::fprintf(
        stderr, "FAILURES=%d\n", failures);
    return 1;
}
