#include "vphone/backend.hpp"
#include "vphone/backend_protocol.hpp"
#include "vphone/runtime_foundation.hpp"

#include <fstream>
#include <iostream>
#include <sstream>
#include <string>

namespace vphone { IVirtualMachineBackend* create_windows_backend(); }

static std::string read_file(const std::string& path) {
    std::ifstream input(path, std::ios::binary);
    if (!input) {
        return {};
    }

    std::ostringstream buffer;
    buffer << input.rdbuf();
    return buffer.str();
}

static void print_capabilities(vphone::IVirtualMachineBackend* backend) {
    const auto c = backend->probe();
    std::cout << "{\n"
              << "  \"backend\": \"" << backend->name() << "\",\n"
              << "  \"arm64_execution\": \"" << vphone::to_string(c.arm64_execution) << "\",\n"
              << "  \"apple_machine_model\": \"" << vphone::to_string(c.apple_machine_model) << "\",\n"
              << "  \"persistent_storage\": \"" << vphone::to_string(c.persistent_storage) << "\",\n"
              << "  \"serial_console\": \"" << vphone::to_string(c.serial_console) << "\",\n"
              << "  \"display\": \"" << vphone::to_string(c.display) << "\",\n"
              << "  \"input\": \"" << vphone::to_string(c.input) << "\",\n"
              << "  \"guest_transport\": \"" << vphone::to_string(c.guest_transport) << "\",\n"
              << "  \"sep_model\": \"" << vphone::to_string(c.sep_model) << "\"\n"
              << "}\n";
}

static void print_runtime_foundation() {
    const auto status =
        vphone::probe_runtime_foundation();

    std::cout <<
        vphone::runtime_foundation_json(status);
}

static void print_usage() {
    std::cout
        << "usage: vphone-vm-win [probe|--capabilities|runtime-foundation|protocol-version|validate-request FILE|launch-request FILE|launch|--help]\n";
}

int main(int argc, char** argv) {
    auto* backend = vphone::create_windows_backend();

    if (argc < 2) {
        print_capabilities(backend);
        return 0;
    }

    const std::string command = argv[1];

    if (command == "probe" || command == "--capabilities" || command == "capabilities") {
        print_capabilities(backend);
        return 0;
    }

    if (command == "runtime-foundation") {
        print_runtime_foundation();
        return 0;
    }

    if (command == "protocol-version") {
        std::cout << vphone::kBackendProtocolVersion << "\n";
        return 0;
    }

    if (command == "--help" || command == "-h" || command == "help") {
        print_usage();
        return 0;
    }

    if (command == "validate-request" || command == "launch-request") {
        if (argc != 3) {
            std::cerr << "ERROR: " << command << " requires exactly one JSON request file\n";
            return 64;
        }

        const std::string json = read_file(argv[2]);
        if (json.empty()) {
            std::cerr << "ERROR: request file is missing or empty: " << argv[2] << "\n";
            return 66;
        }

        vphone::BackendRequest request;
        std::string error;
        if (!vphone::parse_backend_request_json(json, request, error)) {
            std::cerr << "ERROR: " << error << "\n";
            return 64;
        }

        if (command == "validate-request") {
            std::cout << vphone::canonical_backend_request_json(request);
            return 0;
        }

        vphone::VmConfig cfg;
        cfg.manifest_path = request.boot->config;
        cfg.force_dfu = request.boot->dfu;
        return backend->launch(cfg);
    }

    if (command == "launch") {
        vphone::VmConfig cfg;
        return backend->launch(cfg);
    }

    std::cerr << "ERROR: unknown command: " << command << "\n";
    print_usage();
    return 64;
}
