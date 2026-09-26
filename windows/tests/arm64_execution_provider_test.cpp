#include "vphone/arm64_execution_provider.hpp"

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
        vphone::
            probe_arm64_execution_provider();

    CHECK(
        !status.host_architecture.empty()
    );

    CHECK(
        status.kind ==
            vphone::
                Arm64ExecutionProviderKind::
                    none ||
        status.kind ==
            vphone::
                Arm64ExecutionProviderKind::
                    qemu_tcg ||
        status.kind ==
            vphone::
                Arm64ExecutionProviderKind::
                    windows_arm64_native
    );

    CHECK(
        status.apple_machine_model_implemented ==
        false
    );

    CHECK(
        status.windows_guest_boot_ready ==
        false
    );

    CHECK(
        !status.reason.empty()
    );

    if (
        status.kind ==
        vphone::
            Arm64ExecutionProviderKind::
                qemu_tcg
    ) {
        CHECK(status.available);
        CHECK(status.qemu_present);
        CHECK(status.qemu_virt_machine);
        CHECK(status.qemu_tcg_accelerator);
        CHECK(!status.executable_path.empty());
    }

    const auto json =
        vphone::
            arm64_execution_provider_json(
                status
            );

    CHECK(
        json.find(
            "\"windows_guest_boot_ready\": false"
        ) != std::string::npos
    );

    CHECK(
        json.find(
            "\"apple_machine_model_implemented\": false"
        ) != std::string::npos
    );

    std::cout
        << "ARM64_EXECUTION_PROVIDER_CONTRACT_PASS\n";

    std::cout << json;

    return 0;
}