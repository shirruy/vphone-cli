#include "vphone/apple_machine_model.hpp"

#include <iostream>
#include <string>

static void usage() {
    std::cout
        << "usage: vphone-apple-machine-win "
        << "[probe|validate|--help]\n";
}

int main(
    int argc,
    char** argv
) {
    if (
        argc >= 2 &&
        (
            std::string(argv[1]) == "--help" ||
            std::string(argv[1]) == "-h" ||
            std::string(argv[1]) == "help"
        )
    ) {
        usage();
        return 0;
    }

    const std::string command =
        argc >= 2
            ? argv[1]
            : "probe";

    if (
        command != "probe" &&
        command != "validate"
    ) {
        std::cerr
            << "ERROR: unknown command\n";

        usage();

        return 64;
    }

    const auto model =
        vphone::canonical_apple_machine_model();

    std::cout
        << vphone::apple_machine_model_json(
            model
        );

    if (
        command ==
        "validate"
    ) {
        std::string error;

        if (
            !vphone::validate_apple_machine_model(
                model,
                error
            )
        ) {
            std::cerr
                << "ERROR: "
                << error
                << "\n";

            return 78;
        }

        std::cout
            << "APPLE_MACHINE_MODEL_CONTRACT_PASS\n";
    }

    return 0;
}