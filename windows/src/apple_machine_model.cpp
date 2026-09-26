#include "vphone/apple_machine_model.hpp"

#include <iomanip>
#include <sstream>
#include <string>

namespace vphone {
namespace {

std::string json_escape(
    const std::string& value
) {
    std::string out;
    out.reserve(value.size() + 16);

    for (const char ch : value) {
        switch (ch) {
        case '\\':
            out += "\\\\";
            break;

        case '"':
            out += "\\\"";
            break;

        case '\n':
            out += "\\n";
            break;

        case '\r':
            out += "\\r";
            break;

        case '\t':
            out += "\\t";
            break;

        default:
            out.push_back(ch);
            break;
        }
    }

    return out;
}

std::string hex_u32(
    std::uint32_t value
) {
    std::ostringstream out;

    out
        << "0x"
        << std::uppercase
        << std::hex
        << value;

    return out.str();
}

} // namespace

AppleMachineModelDescriptor
canonical_apple_machine_model() {

    AppleMachineModelDescriptor model;

    /*
        Canonical values mirror:

        VPhoneVirtualMachineHardwareModel.swift

        platformVersion = 3
        boardID         = 0x90
        ISA             = 2
        CPID            = 0xFE01

        VPhoneVirtualMachineManifest.swift

        platformType    = vresearch101
    */

    model.platform_type =
        "vresearch101";

    model.platform_version =
        3;

    model.board_id =
        0x90;

    model.isa =
        2;

    model.udid_chip_id =
        0xFE01;

    model.descriptor_complete =
        true;

    model.upstream_parity_verified =
        true;

    /*
        IMPORTANT:

        This phase defines the canonical Apple machine identity
        contract only.

        It DOES NOT claim that QEMU already implements Apple's
        private PV=3 machine model.

        It DOES NOT claim Windows guest boot.
    */

    model.qemu_machine_model_implemented =
        false;

    model.apple_virtualization_private_api_available =
        false;

    model.guest_boot_ready =
        false;

    model.reason =
        "Canonical vresearch101 PV=3 machine descriptor is "
        "represented on Windows with upstream parity. "
        "QEMU Apple machine implementation and Windows guest "
        "boot remain intentionally fail-closed.";

    return model;
}

bool validate_apple_machine_model(
    const AppleMachineModelDescriptor& model,
    std::string& error
) {
    if (
        model.platform_type !=
        "vresearch101"
    ) {
        error =
            "platform_type must be vresearch101";

        return false;
    }

    if (
        model.platform_version !=
        3
    ) {
        error =
            "platform_version must be 3";

        return false;
    }

    if (
        model.board_id !=
        0x90
    ) {
        error =
            "board_id must be 0x90";

        return false;
    }

    if (
        model.isa !=
        2
    ) {
        error =
            "ISA must be 2";

        return false;
    }

    if (
        model.udid_chip_id !=
        0xFE01
    ) {
        error =
            "UDID CPID must be 0xFE01";

        return false;
    }

    if (
        !model.descriptor_complete
    ) {
        error =
            "machine descriptor is incomplete";

        return false;
    }

    if (
        !model.upstream_parity_verified
    ) {
        error =
            "upstream parity is not verified";

        return false;
    }

    if (
        model.guest_boot_ready
    ) {
        error =
            "guest boot cannot be promoted during Phase 5C";

        return false;
    }

    error.clear();

    return true;
}

std::string apple_machine_model_json(
    const AppleMachineModelDescriptor& model
) {
    std::ostringstream out;

    out
        << "{\n"

        << "  \"platform_type\": \""
        << json_escape(model.platform_type)
        << "\",\n"

        << "  \"platform_version\": "
        << model.platform_version
        << ",\n"

        << "  \"board_id\": \""
        << hex_u32(model.board_id)
        << "\",\n"

        << "  \"isa\": "
        << model.isa
        << ",\n"

        << "  \"udid_chip_id\": \""
        << hex_u32(model.udid_chip_id)
        << "\",\n"

        << "  \"descriptor_complete\": "
        << (
            model.descriptor_complete
                ? "true"
                : "false"
        )
        << ",\n"

        << "  \"upstream_parity_verified\": "
        << (
            model.upstream_parity_verified
                ? "true"
                : "false"
        )
        << ",\n"

        << "  \"qemu_provider_required\": "
        << (
            model.qemu_provider_required
                ? "true"
                : "false"
        )
        << ",\n"

        << "  \"qemu_machine_model_implemented\": "
        << (
            model.qemu_machine_model_implemented
                ? "true"
                : "false"
        )
        << ",\n"

        << "  \"apple_virtualization_private_api_available\": "
        << (
            model.apple_virtualization_private_api_available
                ? "true"
                : "false"
        )
        << ",\n"

        << "  \"guest_boot_ready\": "
        << (
            model.guest_boot_ready
                ? "true"
                : "false"
        )
        << ",\n"

        << "  \"reason\": \""
        << json_escape(model.reason)
        << "\"\n"

        << "}\n";

    return out.str();
}

} // namespace vphone