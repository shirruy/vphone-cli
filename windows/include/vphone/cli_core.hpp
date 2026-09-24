#pragma once

#include "vphone/backend_protocol.hpp"

#include <string>
#include <vector>

namespace vphone {

struct NativeCliParseResult {
    bool ok{false};
    bool show_help{false};
    bool show_version{false};
    bool show_firmware_capabilities{false};
    bool show_archive_capabilities{false};
    bool dry_run{false};
    BackendRequest request{};
    std::string error;
};

NativeCliParseResult parse_native_cli(const std::vector<std::string>& args);
std::string native_cli_usage();

} // namespace vphone
