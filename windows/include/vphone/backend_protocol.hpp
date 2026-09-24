#pragma once

#include <optional>
#include <string>

namespace vphone {

inline constexpr int kBackendProtocolVersion = 1;

struct BackendBootRequest {
    std::string config;
    bool dfu{false};
    bool headless{false};
    std::optional<std::string> api_listen;
    std::optional<int> kernel_debug_port;
    std::string vphoned_bin{".vphoned.signed"};
    std::optional<std::string> install_ipa;
};

struct BackendRequest {
    int protocol_version{kBackendProtocolVersion};
    std::string operation{"boot"};
    std::optional<BackendBootRequest> boot;
};

bool parse_backend_request_json(
    const std::string& json,
    BackendRequest& request,
    std::string& error
);

bool validate_backend_request(
    const BackendRequest& request,
    std::string& error
);

std::string canonical_backend_request_json(const BackendRequest& request);

} // namespace vphone
