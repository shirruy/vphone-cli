#include "vphone/backend.hpp"
#include "vphone/runtime_foundation.hpp"

#include <iostream>

namespace vphone {

const char* to_string(CapabilityState state) {
    switch (state) {
    case CapabilityState::supported:
        return "supported";

    case CapabilityState::unsupported:
        return "unsupported";

    default:
        return "unknown";
    }
}

class WindowsResearchBackend final
    : public IVirtualMachineBackend {

public:
    std::string name() const override {
        return "windows-research-stub";
    }

    BackendCapabilities probe() const override {
        BackendCapabilities c;

        const auto runtime =
            probe_runtime_foundation();

        c.persistent_storage =
            CapabilityState::supported;

        c.arm64_execution =
            runtime.arm64_execution_provider_detected
                ? CapabilityState::unknown
                : CapabilityState::unsupported;

        c.apple_machine_model =
            runtime.apple_machine_model_implemented
                ? CapabilityState::unknown
                : CapabilityState::unsupported;

        c.serial_console =
            CapabilityState::unknown;

        c.display =
            CapabilityState::unknown;

        c.input =
            CapabilityState::unknown;

        c.guest_transport =
            CapabilityState::unknown;

        c.sep_model =
            CapabilityState::unknown;

        return c;
    }

    int launch(const VmConfig&) override {
        const auto runtime =
            probe_runtime_foundation();

        std::cerr
            << "BLOCKED: Windows VM runtime has not passed "
               "Phase 5 boot feasibility. "
            << runtime.reason
            << "\n";

        return 78;
    }

    int stop(const std::string&) override {
        return 0;
    }
};

IVirtualMachineBackend* create_windows_backend() {
    static WindowsResearchBackend backend;
    return &backend;
}

} // namespace vphone