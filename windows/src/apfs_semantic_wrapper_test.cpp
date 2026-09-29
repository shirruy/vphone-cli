// Semantic plist wrapper unit test: correct Apple binary-plist
// marker grammar, injected mutation function, spy control-flow
// assertions, and a corrected negative matrix. This test proves
// WRAPPER CONTROL FLOW ONLY; the real apfs_resize_plist_payload_safe
// invocation is proven by vphone_apfs_semantic_integration_test.
//
// Marker grammar (marker = high nibble type, low nibble info):
//   0x00 null | 0x08 false | 0x09 true | 0x0F fill
//   0x1n integer (size 2^n) | 0x2n real | 0x33 date
//   0x4n data | 0x5n ASCII string | 0x6n UTF-16BE string
//   0x8n UID (n+1) | 0xAn array | 0xCn set | 0xDn dict
// Types 0x7, 0x9, 0xB, 0xE are rejected.

#include "vphone/semantic_wrapper.hpp"

#include <windows.h>

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <string>
#include <vector>

namespace {

void put_be64(
    std::vector<std::uint8_t>& b, std::size_t off,
    std::uint64_t v
) {
    for (int i = 7; i >= 0; --i) {
        b[off + (7 - i)] =
            static_cast<std::uint8_t>((v >> (i * 8)) & 0xff);
    }
}

void finish_bplist(
    std::vector<std::uint8_t>& b,
    std::uint64_t num_objects,
    std::uint64_t top_object
) {
    const std::size_t off = b.size();
    b.resize(off + 32, 0);
    std::uint8_t* t = b.data() + off;
    t[5] = 0;  // sort version
    t[6] = 1;  // offset table entry size
    t[7] = 1;  // object reference size
    put_be64(b, off + 8, num_objects);
    put_be64(b, off + 16, top_object);
    put_be64(b, off + 24, 0);  // patched by caller
}

// Build a real binary plist (offset table entry size 1, ref size 1)
// from serialized objects. Returns false on inconsistent layout.
bool build_bplist(
    std::vector<std::uint8_t> objects,
    std::vector<std::uint64_t> offsets,
    std::uint64_t top_object,
    std::vector<std::uint8_t>& out
) {
    out.assign(8, 0);
    std::memcpy(out.data(), "bplist00", 8);
    for (std::uint8_t c : objects) {
        out.push_back(c);
    }
    // Offset table starts immediately after the objects.
    const std::size_t table_off = out.size();
    for (std::size_t i = 0; i < offsets.size(); ++i) {
        if (offsets[i] < 8 || offsets[i] > 255) {
            return false;
        }
        out.push_back(
            static_cast<std::uint8_t>(offsets[i]));
    }
    finish_bplist(
        out, offsets.size(), top_object);
    // Patch the offset table offset into the trailer.
    put_be64(out, out.size() - 8, table_off);
    return true;
}

// Real Apple-grammar synthetic dictionary with ASCII string keys,
// integer, false, true, array, and nested dictionary values.
// Objects are laid out as [marker][payload] back to back.
bool build_valid_dict(std::vector<std::uint8_t>& out) {
    // Offsets of each object relative to the header.
    //   object 0 at 8:  dict (marker D2) + 4 refs = 5 bytes
    //   object 1 at 13: ASCII string "A" (5x1) + 'A' = 2 bytes
    //   object 2 at 15: ASCII string "B" (5x1) + 'B' = 2 bytes
    //   object 3 at 17: integer 1 (10 01) = 2 bytes
    //   object 4 at 19: false (08) = 1 byte
    //   object 5 at 20: true (09) = 1 byte
    //   object 6 at 21: array (A2) + 2 refs = 3 bytes
    //   object 7 at 24: nested dict (D1) + 2 refs = 3 bytes
    std::vector<std::uint8_t> objects = {
        0xD2, 1, 2, 3, 4,        // dict: keys {1,2}, vals {3,4}
        0x51, 'A',               // ASCII string "A"
        0x51, 'B',               // ASCII string "B"
        0x10, 0x01,              // integer 1
        0x08,                    // false
        0x09,                    // true
        0xA2, 4, 5,              // array [false, true]
        0xD1, 2, 3,              // nested dict { "B": 1 }
    };
    std::vector<std::uint64_t> offsets =
        {8, 13, 15, 17, 19, 20, 21, 24};
    return build_bplist(objects, offsets, 0, out);
}

bool read_file(
    const std::string& path, std::vector<std::uint8_t>& out
) {
    std::ifstream f(
        path, std::ios::binary | std::ios::ate);
    if (!f) {
        return false;
    }
    const std::streamsize size = f.tellg();
    if (size < 0) {
        return false;
    }
    out.resize(static_cast<std::size_t>(size));
    f.seekg(0, std::ios::beg);
    f.read(
        reinterpret_cast<char*>(out.data()), size);
    return f.good() ||
        static_cast<std::streamsize>(
            f.gcount()) == size;
}

} // namespace

int main(int argc, char** argv) {
    int failures = 0;

    // ---- External input mode ----
    // Usage: vphone_apfs_semantic_wrapper_test --file <path>
    // Validates a real (private, never committed) plist fixture.
    if (argc == 3 && std::string(argv[1]) == "--file") {
        std::vector<std::uint8_t> payload;
        if (!read_file(argv[2], payload)) {
            std::fprintf(
                stderr, "cannot read payload file: %s\n",
                argv[2]);
            return 1;
        }
        const std::string err = vphone::bplist_validate(payload);
        if (!err.empty()) {
            std::fprintf(
                stderr, "payload validation failed: %s\n",
                err.c_str());
            return 1;
        }
        std::printf(
            "SEMANTIC_REAL_712_BPLIST_VALIDATOR_PASS "
            "size=%zu\n", payload.size());
        return 0;
    }

    // ---- Unit spy: negative control flow ----
    {
        int spy_calls = 0;
        vphone::SemanticMutationFn spy =
            [&spy_calls](
                const std::vector<std::uint8_t>&,
                std::string&
            ) -> bool {
            ++spy_calls;
            return true;
        };

        std::vector<std::uint8_t> garbage(100, 0xAB);
        const vphone::SemanticMutationResult r =
            vphone::semantic_mutate(garbage, spy);
        if (r.exit_code != 1 ||
            r.mutation_invoked ||
            spy_calls != 0) {
            std::fprintf(
                stderr,
                "[spy-negative] exit=%d invoked=%d "
                "calls=%d\n",
                r.exit_code,
                r.mutation_invoked ? 1 : 0,
                spy_calls);
            ++failures;
        } else {
            std::printf(
                "SEMANTIC_WRAPPER_NEGATIVE_SPY_PASS "
                "call_count=0\n");
        }
    }

    // ---- Unit spy: positive control flow ----
    {
        int spy_calls = 0;
        vphone::SemanticMutationFn spy =
            [&spy_calls](
                const std::vector<std::uint8_t>&,
                std::string&
            ) -> bool {
            ++spy_calls;
            return true;
        };

        std::vector<std::uint8_t> valid;
        if (!build_valid_dict(valid)) {
            std::fprintf(
                stderr, "[spy-positive] fixture build failed\n");
            ++failures;
        } else {
            const vphone::SemanticMutationResult r =
                vphone::semantic_mutate(valid, spy);
            if (r.exit_code != 0 ||
                !r.mutation_invoked ||
                !r.mutation_ok ||
                spy_calls != 1) {
                std::fprintf(
                    stderr,
                    "[spy-positive] exit=%d invoked=%d "
                    "calls=%d err=%s\n",
                    r.exit_code,
                    r.mutation_invoked ? 1 : 0,
                    spy_calls, r.error.c_str());
                ++failures;
            } else {
                std::printf(
                    "SEMANTIC_WRAPPER_POSITIVE_SPY_PASS "
                    "call_count=1\n");
            }
        }
    }

    // ---- Grammar family acceptance ----
    {
        std::vector<std::uint8_t> dict;
        if (build_valid_dict(dict)) {
            const std::string err =
                vphone::bplist_validate(dict);
            if (err.empty()) {
                std::printf(
                    "BPLIST_VALID_BOOLEAN_FALSE_PASS\n");
                std::printf(
                    "BPLIST_VALID_BOOLEAN_TRUE_PASS\n");
                std::printf(
                    "BPLIST_VALID_STRING_PASS\n");
                std::printf(
                    "BPLIST_VALID_ARRAY_PASS\n");
                std::printf(
                    "BPLIST_VALID_DICT_PASS\n");
            } else {
                std::fprintf(
                    stderr,
                    "[valid-dict] rejected: %s\n",
                    err.c_str());
                ++failures;
            }
        } else {
            ++failures;
        }
    }

    // ---- Negative matrix (each must be REFUSED with
    //      mutation not invoked) ----
    {
        int spy_calls = 0;
        vphone::SemanticMutationFn spy =
            [&spy_calls](
                const std::vector<std::uint8_t>&,
                std::string&
            ) -> bool {
            ++spy_calls;
            return true;
        };
        const auto expect_refused =
            [&](const char* name,
                const std::vector<std::uint8_t>& payload)
            -> bool {
            const vphone::SemanticMutationResult r =
                vphone::semantic_mutate(payload, spy);
            if (r.exit_code != 1 ||
                r.mutation_invoked) {
                std::fprintf(
                    stderr,
                    "[%s] accepted: exit=%d invoked=%d\n",
                    name, r.exit_code,
                    r.mutation_invoked ? 1 : 0);
                return false;
            }
            std::printf(
                "SEMANTIC_NEGATIVE_%s_REFUSED_PASS\n",
                name);
            return true;
        };

        // 1. Garbage (non-bplist bytes).
        {
            std::vector<std::uint8_t> payload(100, 0xAB);
            if (!expect_refused("GARBAGE", payload)) {
                ++failures;
            }
        }

        // 2. Truncated bplist (magic only, no trailer).
        {
            std::vector<std::uint8_t> payload(20, 0);
            std::memcpy(payload.data(), "bplist00", 8);
            if (!expect_refused(
                    "TRUNCATED_BPLIST", payload)) {
                ++failures;
            }
        }

        // 3. Corrupt object span: object claims 0x30 more bytes
        //    than remain before the offset table.
        {
            std::vector<std::uint8_t> objects = {
                0x52, 'A', 'B',        // string len 2
            };
            std::vector<std::uint64_t> offsets = {8};
            std::vector<std::uint8_t> payload;
            if (!build_bplist(
                    objects, offsets, 0, payload)) {
                ++failures;
            } else {
                // Trailer says the object has 0x30 payload bytes.
                payload[8] = 0x5F;
                payload[9] = 0x10;
                payload[10] = 0x30;
                if (!expect_refused(
                        "CORRUPT_OBJECT_SPAN", payload)) {
                    ++failures;
                }
            }
        }

        // 4. Offset-table entry pointing INSIDE the offset table.
        {
            std::vector<std::uint8_t> objects = {
                0x08,  // false
            };
            std::vector<std::uint64_t> offsets = {8};
            std::vector<std::uint8_t> payload;
            if (!build_bplist(
                    objects, offsets, 0, payload)) {
                ++failures;
            } else {
                // Rewrite the single offset-table entry to point
                // at the table itself (table starts at offset 9).
                payload[9] = 9;
                if (!expect_refused(
                        "OFFSET_ENTRY_IN_OBJECT_TABLE",
                        payload)) {
                    ++failures;
                }
            }
        }

        // 5. Container reference >= num_objects.
        {
            // Array (A1) referencing object 99 with 3 objects.
            std::vector<std::uint8_t> objects = {
                0xA1, 99,   // array ref 99
                0x08,       // false (object 1)
                0x08,       // false (object 2)
            };
            std::vector<std::uint64_t> offsets = {8, 10, 11};
            std::vector<std::uint8_t> payload;
            if (!build_bplist(
                    objects, offsets, 0, payload)) {
                ++failures;
            } else if (!expect_refused(
                           "INVALID_CONTAINER_REFERENCE",
                           payload)) {
                ++failures;
            }
        }

        // 6. Invalid extended-length integer: string (5F) followed
        //    by a non-integer length marker (0x51).
        {
            std::vector<std::uint8_t> objects = {
                0x5F, 0x51, 'A',
            };
            std::vector<std::uint64_t> offsets = {8};
            std::vector<std::uint8_t> payload;
            if (!build_bplist(
                    objects, offsets, 0, payload)) {
                ++failures;
            } else if (!expect_refused(
                           "INVALID_EXTENDED_LENGTH_INTEGER",
                           payload)) {
                ++failures;
            }
        }

        // 7. Object payload overlapping the offset table: an
        //    extended-length dict (DF + integer length marker)
        //    whose key-reference region starts inside the object
        //    area but extends into the offset table.
        {
            std::vector<std::uint8_t> objects = {
                0xDF,           // dict, extended length
                0x10,           // length integer, 1 byte
                0x04,           // count = 4 entries
            };
            std::vector<std::uint64_t> offsets = {8};
            std::vector<std::uint8_t> payload;
            if (!build_bplist(
                    objects, offsets, 0, payload)) {
                ++failures;
            } else if (!expect_refused(
                           "OBJECT_PAYLOAD_OVERLAPS_OFFSET_TABLE",
                           payload)) {
                ++failures;
            }
        }

        // No negative case may have invoked the mutation function.
        if (spy_calls != 0) {
            std::fprintf(
                stderr,
                "[negative-matrix] spy called %d times\n",
                spy_calls);
            ++failures;
        }
    }

    if (failures == 0) {
        std::printf(
            "SEMANTIC_WRAPPER_TEST_PASS\n");
        return 0;
    }
    std::fprintf(
        stderr, "FAILURES=%d\n", failures);
    return 1;
}
