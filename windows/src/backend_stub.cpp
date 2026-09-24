#include "vphone/backend.hpp"
#include <iostream>

namespace vphone {

const char* to_string(CapabilityState state) {
    switch (state) {
        case CapabilityState::supported: return "supported";
        case CapabilityState::unsupported: return "unsupported";
        default: return "unknown";
    }
}

class WindowsResearchBackend final : public IVirtualMachineBackend {
public:
    std::string name() const override { return "windows-research-stub"; }

    BackendCapabilities probe() const override {
        BackendCapabilities c;
        c.persistent_storage = CapabilityState::supported; // host-side file handling only
        c.serial_console = CapabilityState::unknown;
        c.arm64_execution = CapabilityState::unknown;
        c.apple_machine_model = CapabilityState::unknown;
        c.display = CapabilityState::unknown;
        c.input = CapabilityState::unknown;
        c.guest_transport = CapabilityState::unknown;
        c.sep_model = CapabilityState::unknown;
        return c;
    }

    int launch(const VmConfig&) override {
        std::cerr << "BLOCKED: Windows VM runtime has not passed Phase 5 boot feasibility.\n";
        return 78;
    }

    int stop(const std::string&) override { return 0; }
};

IVirtualMachineBackend* create_windows_backend() {
    static WindowsResearchBackend backend;
    return &backend;
}

}
