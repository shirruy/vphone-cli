#include "vphone/cli_core.hpp"

#include <iostream>
#include <optional>
#include <string>
#include <vector>

#define CHECK(expr) \
    do { \
        if (!(expr)) { \
            std::cerr << "CHECK FAILED at " << __FILE__ << ":" << __LINE__ << ": " #expr "\n"; \
            return 1; \
        } \
    } while (0)

int main() {
    const std::vector<std::string> valid = {
        "vm", "launch",
        "--config", "/tmp/vphone/demo/config.plist",
        "--headless",
        "--api-listen", "127.0.0.1:8765",
        "--kernel-debug-port", "62000",
        "--dry-run"
    };

    const auto parsed = vphone::parse_native_cli(valid);
    CHECK(parsed.ok);
    CHECK(parsed.dry_run);
    CHECK(parsed.request.protocol_version == 1);
    CHECK(parsed.request.operation == "boot");
    CHECK(parsed.request.boot.has_value());
    CHECK(parsed.request.boot->config == "/tmp/vphone/demo/config.plist");
    CHECK(!parsed.request.boot->dfu);
    CHECK(parsed.request.boot->headless);
    CHECK(parsed.request.boot->api_listen == std::optional<std::string>("127.0.0.1:8765"));
    CHECK(parsed.request.boot->kernel_debug_port == std::optional<int>(62000));
    CHECK(parsed.request.boot->vphoned_bin == ".vphoned.signed");
    CHECK(!parsed.request.boot->install_ipa.has_value());

    const auto duplicate = vphone::parse_native_cli({
        "vm", "launch",
        "--config", "/tmp/a.plist",
        "--config", "/tmp/b.plist",
        "--dry-run"
    });
    CHECK(!duplicate.ok);
    CHECK(duplicate.error.find("duplicate option") != std::string::npos);

    const auto invalid_dfu = vphone::parse_native_cli({
        "vm", "launch",
        "--config", "/tmp/a.plist",
        "--dfu",
        "--api-listen", "127.0.0.1:8765",
        "--dry-run"
    });
    CHECK(!invalid_dfu.ok);
    CHECK(invalid_dfu.error.find("api_listen is unavailable in DFU mode") != std::string::npos);

    const auto missing_config = vphone::parse_native_cli({
        "vm", "launch",
        "--headless",
        "--dry-run"
    });
    CHECK(!missing_config.ok);
    CHECK(missing_config.error == "--config is required");

    const auto bad_port = vphone::parse_native_cli({
        "vm", "launch",
        "--config", "/tmp/a.plist",
        "--kernel-debug-port", "5999",
        "--dry-run"
    });
    CHECK(!bad_port.ok);
    CHECK(bad_port.error.find("6000 through 65535") != std::string::npos);

    const auto capabilities = vphone::parse_native_cli({"firmware-capabilities"});
    CHECK(capabilities.ok);
    CHECK(capabilities.show_firmware_capabilities);

    const auto archiveCapabilities = vphone::parse_native_cli({"archive-capabilities"});
    CHECK(archiveCapabilities.ok);
    CHECK(archiveCapabilities.show_archive_capabilities);

    const auto restoreCapabilities = vphone::parse_native_cli({"restore-capabilities"});
    CHECK(restoreCapabilities.ok);
    CHECK(restoreCapabilities.show_restore_capabilities);

    const auto live_launch = vphone::parse_native_cli({
        "vm", "launch",
        "--config", "/tmp/a.plist"
    });
    CHECK(!live_launch.ok);
    CHECK(live_launch.error.find("not enabled in Phase 3") != std::string::npos);

    return 0;
}
