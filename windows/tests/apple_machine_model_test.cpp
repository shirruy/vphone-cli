#include "vphone/apple_machine_model.hpp"

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

    const auto model =
        vphone::canonical_apple_machine_model();

    CHECK(
        model.platform_type ==
        "vresearch101"
    );

    CHECK(
        model.platform_version ==
        3
    );

    CHECK(
        model.board_id ==
        0x90
    );

    CHECK(
        model.isa ==
        2
    );

    CHECK(
        model.udid_chip_id ==
        0xFE01
    );

    CHECK(
        model.descriptor_complete ==
        true
    );

    CHECK(
        model.upstream_parity_verified ==
        true
    );

    CHECK(
        model.qemu_provider_required ==
        true
    );

    CHECK(
        model.qemu_machine_model_implemented ==
        false
    );

    CHECK(
        model.apple_virtualization_private_api_available ==
        false
    );

    CHECK(
        model.guest_boot_ready ==
        false
    );

    std::string error;

    CHECK(
        vphone::validate_apple_machine_model(
            model,
            error
        )
    );

    CHECK(
        error.empty()
    );

    const auto json =
        vphone::apple_machine_model_json(
            model
        );

    CHECK(
        json.find(
            "\"platform_type\": \"vresearch101\""
        ) != std::string::npos
    );

    CHECK(
        json.find(
            "\"platform_version\": 3"
        ) != std::string::npos
    );

    CHECK(
        json.find(
            "\"board_id\": \"0x90\""
        ) != std::string::npos
    );

    CHECK(
        json.find(
            "\"udid_chip_id\": \"0xFE01\""
        ) != std::string::npos
    );

    CHECK(
        json.find(
            "\"guest_boot_ready\": false"
        ) != std::string::npos
    );

    std::cout
        << "APPLE_MACHINE_MODEL_FOUNDATION_PASS\n";

    std::cout << json;

    return 0;
}