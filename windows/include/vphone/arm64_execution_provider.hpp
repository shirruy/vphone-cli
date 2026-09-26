#pragma once

#include <string>

namespace vphone {

enum class Arm64ExecutionProviderKind {
    none,
    qemu_tcg,
    windows_arm64_native
};

struct Arm64ExecutionProviderStatus {
    Arm64ExecutionProviderKind kind{
        Arm64ExecutionProviderKind::none
    };

    std::string host_architecture;
    std::string executable_path;
    std::string version;

    bool available{false};
    bool qemu_present{false};
    bool qemu_virt_machine{false};
    bool qemu_tcg_accelerator{false};

    bool apple_machine_model_implemented{false};
    bool windows_guest_boot_ready{false};

    std::string reason;
};

const char* to_string(
    Arm64ExecutionProviderKind kind
);

Arm64ExecutionProviderStatus
probe_arm64_execution_provider();

std::string arm64_execution_provider_json(
    const Arm64ExecutionProviderStatus& status
);

} // namespace vphone