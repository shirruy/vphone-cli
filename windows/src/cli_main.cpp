#include "vphone/cli_core.hpp"

#include <iostream>
#include <string>
#include <vector>

int main(int argc, char** argv) {
    std::vector<std::string> args;
    args.reserve(argc > 1 ? static_cast<std::size_t>(argc - 1) : 0);

    for (int i = 1; i < argc; ++i) {
        args.emplace_back(argv[i]);
    }

    const auto parsed = vphone::parse_native_cli(args);

    if (!parsed.ok) {
        std::cerr << "ERROR: " << parsed.error << "\n";
        std::cerr << vphone::native_cli_usage();
        return 64;
    }

    if (parsed.show_help) {
        std::cout << vphone::native_cli_usage();
        return 0;
    }

    if (parsed.show_version) {
        std::cout << "vphone-cli-win phase3 protocol/" << vphone::kBackendProtocolVersion << "\n";
        return 0;
    }

    if (args.size() == 1 && args[0] == "protocol-version") {
        std::cout << vphone::kBackendProtocolVersion << "\n";
        return 0;
    }

    if (parsed.dry_run) {
        std::cout << vphone::canonical_backend_request_json(parsed.request);
        return 0;
    }

    std::cerr << "ERROR: unreachable native CLI state\n";
    return 70;
}
