#include "vphone/backend_protocol.hpp"

#include <cassert>
#include <fstream>
#include <sstream>
#include <string>

static std::string read_all(const char* path) {
    std::ifstream input(path, std::ios::binary);
    assert(input.good());
    std::ostringstream buffer;
    buffer << input.rdbuf();
    return buffer.str();
}

int main(int argc, char** argv) {
    assert(argc == 2);

    const std::string fixture = read_all(argv[1]);

    vphone::BackendRequest request;
    std::string error;

    assert(vphone::parse_backend_request_json(fixture, request, error));
    assert(request.protocol_version == 1);
    assert(request.operation == "boot");
    assert(request.boot.has_value());

    const auto& boot = *request.boot;
    assert(boot.config == "/tmp/vphone/demo/config.plist");
    assert(!boot.dfu);
    assert(boot.headless);
    assert(boot.api_listen == std::optional<std::string>("127.0.0.1:8765"));
    assert(boot.kernel_debug_port == std::optional<int>(62000));
    assert(boot.vphoned_bin == ".vphoned.signed");
    assert(!boot.install_ipa.has_value());

    const std::string canonical = vphone::canonical_backend_request_json(request);
    vphone::BackendRequest reparsed;
    error.clear();
    assert(vphone::parse_backend_request_json(canonical, reparsed, error));
    assert(reparsed.protocol_version == request.protocol_version);
    assert(reparsed.operation == request.operation);
    assert(reparsed.boot->config == request.boot->config);

    std::string wrong_version = fixture;
    const std::string from = "\"protocol_version\": 1";
    const auto pos = wrong_version.find(from);
    assert(pos != std::string::npos);
    wrong_version.replace(pos, from.size(), "\"protocol_version\": 999");

    vphone::BackendRequest rejected;
    error.clear();
    assert(!vphone::parse_backend_request_json(wrong_version, rejected, error));
    assert(error.find("unsupported backend protocol version") != std::string::npos);

    std::string invalid_dfu = fixture;
    const std::string dfu_false = "\"dfu\": false";
    const auto dfu_pos = invalid_dfu.find(dfu_false);
    assert(dfu_pos != std::string::npos);
    invalid_dfu.replace(dfu_pos, dfu_false.size(), "\"dfu\": true");

    error.clear();
    assert(!vphone::parse_backend_request_json(invalid_dfu, rejected, error));
    assert(error.find("api_listen is unavailable in DFU mode") != std::string::npos);

    return 0;
}
