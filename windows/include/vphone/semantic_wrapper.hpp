// Semantic mutation wrapper: validate the replacement payload as a
// binary plist BEFORE invoking the injected mutation function.
// Invalid payloads are REFUSED without invoking the mutation
// function; valid payloads invoke it exactly once. Shared by the
// unit spy test and the real-APFS integration driver so both prove
// the identical control flow.

#pragma once

#include "vphone/bplist_validator.hpp"

#include <cstdint>
#include <functional>
#include <string>
#include <vector>

namespace vphone {

struct SemanticMutationResult {
    int exit_code = 0;
    bool mutation_invoked = false;
    bool mutation_ok = false;
    std::string error;
};

// Injected mutation function: receives the validated payload and
// returns true on success, false with error populated on failure.
using SemanticMutationFn = std::function<bool(
    const std::vector<std::uint8_t>& payload,
    std::string& error
)>;

inline SemanticMutationResult semantic_mutate(
    const std::vector<std::uint8_t>& payload,
    const SemanticMutationFn& mutation_fn
) {
    SemanticMutationResult r;

    const std::string validation_error = bplist_validate(payload);
    if (!validation_error.empty()) {
        r.exit_code = 1;
        r.error =
            "REFUSED_INVALID_PLIST: " + validation_error;
        return r;
    }

    // Valid payload: invoke the mutation function exactly once.
    r.mutation_invoked = true;
    std::string mutation_error;
    r.mutation_ok = mutation_fn(payload, mutation_error);
    r.exit_code = r.mutation_ok ? 0 : 2;
    if (!r.mutation_ok) {
        r.error = mutation_error;
    }
    return r;
}

} // namespace vphone
