#include "vphone/backend_protocol.hpp"

#include <fstream>
#include <iostream>
#include <optional>
#include <sstream>
#include <string>

#define CHECK(expr) \
    do { \
        if (!(expr)) { \
            std::cerr << "CHECK FAILED at " << __FILE__ << ":" << __LINE__ << ": " #expr "\n"; \
            return 1; \
        } \
    } while (0)

static bool read_all(const char* path, std::string& output) {
    std::ifstream input(path, std::ios::binary);
    if (!input.good()) {
        return false;
    }
    std::ostringstream buffer;
    buffer << input.rdbuf();
    output = buffer.str();
    return true;
}

int main(int argc, char** argv) {
    CHECK(argc == 2);

    std::string fixture;
    CHECK(read_all(argv[1], fixture));
    CHECK(!fixture.empty());

    vphone::BackendRequest request;
    std::string error;

    // Regression: the string value "boot" in "operation": "boot" appears
    // before the separate "boot": {...} object. Key lookup must not confuse
    // a string value for a JSON object key.
    CHECK(vphone::parse_backend_request_json(fixture, request, error));
    CHECK(request.protocol_version == 1);
    CHECK(request.operation == "boot");
    CHECK(request.boot.has_value());

    const auto& boot = *request.boot;
    CHECK(boot.config == "/tmp/vphone/demo/config.plist");
    CHECK(!boot.dfu);
    CHECK(boot.headless);
    CHECK(boot.api_listen == std::optional<std::string>("127.0.0.1:8765"));
    CHECK(boot.kernel_debug_port == std::optional<int>(62000));
    CHECK(boot.vphoned_bin == ".vphoned.signed");
    CHECK(!boot.install_ipa.has_value());

    const std::string canonical = vphone::canonical_backend_request_json(request);
    vphone::BackendRequest reparsed;
    error.clear();
    CHECK(vphone::parse_backend_request_json(canonical, reparsed, error));
    CHECK(reparsed.protocol_version == request.protocol_version);
    CHECK(reparsed.operation == request.operation);
    CHECK(reparsed.boot.has_value());
    CHECK(reparsed.boot->config == request.boot->config);

    std::string wrong_version = fixture;
    const std::string from = "\"protocol_version\": 1";
    const auto pos = wrong_version.find(from);
    CHECK(pos != std::string::npos);
    wrong_version.replace(pos, from.size(), "\"protocol_version\": 999");

    vphone::BackendRequest rejected;
    error.clear();
    CHECK(!vphone::parse_backend_request_json(wrong_version, rejected, error));
    CHECK(error.find("unsupported backend protocol version") != std::string::npos);

    std::string invalid_dfu = fixture;
    const std::string dfu_false = "\"dfu\": false";
    const auto dfu_pos = invalid_dfu.find(dfu_false);
    CHECK(dfu_pos != std::string::npos);
    invalid_dfu.replace(dfu_pos, dfu_false.size(), "\"dfu\": true");

    error.clear();
    CHECK(!vphone::parse_backend_request_json(invalid_dfu, rejected, error));
    CHECK(error.find("api_listen is unavailable in DFU mode") != std::string::npos);

    const std::string value_collision =
        "{\"protocol_version\":1,\"operation\":\"boot\",\"note\":\"boot\","
        "\"boot\":{\"config\":\"/tmp/test.plist\",\"dfu\":false,"
        "\"headless\":false,\"api_listen\":null,\"kernel_debug_port\":null,"
        "\"vphoned_bin\":\".vphoned.signed\",\"install_ipa\":null}}";

    error.clear();
    CHECK(vphone::parse_backend_request_json(value_collision, request, error));
    CHECK(request.boot.has_value());
    CHECK(request.boot->config == "/tmp/test.plist");

    return 0;
}
