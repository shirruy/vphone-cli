#include "vphone/arm64_execution_provider.hpp"

#include <iostream>
#include <string>

static void print_usage() {
    std::cout
        << "usage: vphone-arm64-provider-win "
        << "[probe|--help]\n";
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
        print_usage();
        return 0;
    }

    if (
        argc >= 2 &&
        std::string(argv[1]) != "probe"
    ) {
        std::cerr
            << "ERROR: unknown command\n";

        print_usage();

        return 64;
    }

    const auto status =
        vphone::
            probe_arm64_execution_provider();

    std::cout <<
        vphone::
            arm64_execution_provider_json(
                status
            );

    return status.available
        ? 0
        : 78;
}