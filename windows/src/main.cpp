#include "vphone/backend.hpp"
#include <iostream>
#include <string>

namespace vphone { IVirtualMachineBackend* create_windows_backend(); }

int main(int argc, char** argv) {
    auto* backend = vphone::create_windows_backend();
    if (argc < 2 || std::string(argv[1]) == "probe") {
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
        return 0;
    }
    if (std::string(argv[1]) == "launch") {
        vphone::VmConfig cfg;
        return backend->launch(cfg);
    }
    std::cerr << "usage: vphone-vm-win [probe|launch]\n";
    return 64;
}
