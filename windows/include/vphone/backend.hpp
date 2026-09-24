#pragma once
#include "vphone/vm_config.hpp"
#include <string>

namespace vphone {

enum class CapabilityState { supported, unsupported, unknown };

struct BackendCapabilities {
    CapabilityState arm64_execution{CapabilityState::unknown};
    CapabilityState apple_machine_model{CapabilityState::unknown};
    CapabilityState persistent_storage{CapabilityState::unknown};
    CapabilityState serial_console{CapabilityState::unknown};
    CapabilityState display{CapabilityState::unknown};
    CapabilityState input{CapabilityState::unknown};
    CapabilityState guest_transport{CapabilityState::unknown};
    CapabilityState sep_model{CapabilityState::unknown};
};

class IVirtualMachineBackend {
public:
    virtual ~IVirtualMachineBackend() = default;
    virtual std::string name() const = 0;
    virtual BackendCapabilities probe() const = 0;
    virtual int launch(const VmConfig& config) = 0;
    virtual int stop(const std::string& vm_name) = 0;
};

const char* to_string(CapabilityState state);

}
