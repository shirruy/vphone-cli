#pragma once

#include <cstdint>
#include <string>

namespace vphone {

struct AppleMachineModelDescriptor {
    std::string platform_type;

    std::uint32_t platform_version{0};
    std::uint32_t board_id{0};
    std::uint64_t isa{0};
    std::uint32_t udid_chip_id{0};

    bool descriptor_complete{false};
    bool upstream_parity_verified{false};

    bool qemu_provider_required{true};

    bool qemu_machine_model_implemented{false};
    bool apple_virtualization_private_api_available{false};
    bool guest_boot_ready{false};

    std::string reason;
};

AppleMachineModelDescriptor
canonical_apple_machine_model();

bool validate_apple_machine_model(
    const AppleMachineModelDescriptor& descriptor,
    std::string& error
);

std::string apple_machine_model_json(
    const AppleMachineModelDescriptor& descriptor
);

} // namespace vphone