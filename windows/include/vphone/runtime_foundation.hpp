#pragma once

#include <string>

namespace vphone {

enum class RuntimeProvider {
    none,
    qemu_tcg_candidate,
    windows_arm64_candidate
};

struct RuntimeFoundationStatus {
    RuntimeProvider provider{RuntimeProvider::none};

    std::string host_architecture;
    std::string provider_path;

    bool qemu_system_aarch64_present{false};
    bool arm64_execution_provider_detected{false};

    bool apple_machine_model_implemented{false};
    bool boot_ready{false};

    std::string reason;
};

const char* to_string(RuntimeProvider provider);

RuntimeFoundationStatus probe_runtime_foundation();

std::string runtime_foundation_json(
    const RuntimeFoundationStatus& status
);

} // namespace vphone