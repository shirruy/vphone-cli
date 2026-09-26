#include "vphone/runtime_foundation.hpp"

#include <iostream>
#include <string>

#define CHECK(expr) \
    do { \
        if (!(expr)) { \
            std::cerr \
                << "CHECK FAILED at " \
                << __FILE__ \
                << ":" \
                << __LINE__ \
                << ": " #expr \
                << "\n"; \
            return 1; \
        } \
    } while (0)

int main() {
    const auto status =
        vphone::probe_runtime_foundation();

    CHECK(!status.host_architecture.empty());

    CHECK(
        status.provider == vphone::RuntimeProvider::none ||
        status.provider == vphone::RuntimeProvider::qemu_tcg_candidate ||
        status.provider == vphone::RuntimeProvider::windows_arm64_candidate
    );

    CHECK(
        status.apple_machine_model_implemented == false
    );

    CHECK(
        status.boot_ready == false
    );

    CHECK(
        !status.reason.empty()
    );

    const auto json =
        vphone::runtime_foundation_json(status);

    CHECK(
        json.find("\"boot_ready\": false") !=
        std::string::npos
    );

    CHECK(
        json.find(
            "\"apple_machine_model_implemented\": false"
        ) != std::string::npos
    );

    std::cout
        << "RUNTIME_FOUNDATION_CONTRACT_PASS\n";

    std::cout << json;

    return 0;
}