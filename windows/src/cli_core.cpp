#include "vphone/cli_core.hpp"

#include <charconv>
#include <set>
#include <string_view>

namespace vphone {
namespace {

bool take_value(
    const std::vector<std::string>& args,
    std::size_t& index,
    std::string_view option,
    std::string& value,
    std::string& error
) {
    if (index + 1 >= args.size()) {
        error = std::string(option) + " requires a value";
        return false;
    }

    value = args[++index];
    if (value.empty()) {
        error = std::string(option) + " requires a non-empty value";
        return false;
    }
    return true;
}

bool mark_once(std::set<std::string>& seen, const std::string& option, std::string& error) {
    if (!seen.insert(option).second) {
        error = "duplicate option: " + option;
        return false;
    }
    return true;
}

bool parse_debug_port(const std::string& text, int& value) {
    int parsed = 0;
    const char* begin = text.data();
    const char* end = begin + text.size();
    const auto result = std::from_chars(begin, end, parsed);
    if (result.ec != std::errc{} || result.ptr != end) {
        return false;
    }
    if (parsed < 6000 || parsed > 65535) {
        return false;
    }
    value = parsed;
    return true;
}

} // namespace

std::string native_cli_usage() {
    return
        "usage:\n"
        "  vphone-cli-win --help\n"
        "  vphone-cli-win --version\n"
        "  vphone-cli-win protocol-version\n"
        "  vphone-cli-win vm launch --config PATH [options] --dry-run\n"
        "\n"
        "options for vm launch:\n"
        "  --dfu\n"
        "  --headless\n"
        "  --api-listen HOST:PORT\n"
        "  --kernel-debug-port PORT\n"
        "  --vphoned-bin PATH\n"
        "  --install-ipa PATH\n"
        "  --dry-run                 emit Protocol v1 request; do not start a VM\n";
}

NativeCliParseResult parse_native_cli(const std::vector<std::string>& args) {
    NativeCliParseResult result;

    if (args.empty()) {
        result.error = "missing command";
        return result;
    }

    if (args.size() == 1 && (args[0] == "--help" || args[0] == "-h" || args[0] == "help")) {
        result.ok = true;
        result.show_help = true;
        return result;
    }

    if (args.size() == 1 && (args[0] == "--version" || args[0] == "version")) {
        result.ok = true;
        result.show_version = true;
        return result;
    }

    if (args.size() == 1 && args[0] == "protocol-version") {
        result.ok = true;
        return result;
    }

    if (args.size() < 2 || args[0] != "vm" || args[1] != "launch") {
        result.error = "unsupported command";
        return result;
    }

    BackendBootRequest boot;
    std::set<std::string> seen;

    for (std::size_t i = 2; i < args.size(); ++i) {
        const std::string& arg = args[i];

        if (arg == "--config") {
            if (!mark_once(seen, arg, result.error)) return result;
            if (!take_value(args, i, arg, boot.config, result.error)) return result;
            continue;
        }

        if (arg == "--dfu") {
            if (!mark_once(seen, arg, result.error)) return result;
            boot.dfu = true;
            continue;
        }

        if (arg == "--headless") {
            if (!mark_once(seen, arg, result.error)) return result;
            boot.headless = true;
            continue;
        }

        if (arg == "--api-listen") {
            if (!mark_once(seen, arg, result.error)) return result;
            std::string value;
            if (!take_value(args, i, arg, value, result.error)) return result;
            boot.api_listen = value;
            continue;
        }

        if (arg == "--kernel-debug-port") {
            if (!mark_once(seen, arg, result.error)) return result;
            std::string value;
            if (!take_value(args, i, arg, value, result.error)) return result;

            int port = 0;
            if (!parse_debug_port(value, port)) {
                result.error = "--kernel-debug-port must be an integer from 6000 through 65535";
                return result;
            }
            boot.kernel_debug_port = port;
            continue;
        }

        if (arg == "--vphoned-bin") {
            if (!mark_once(seen, arg, result.error)) return result;
            if (!take_value(args, i, arg, boot.vphoned_bin, result.error)) return result;
            continue;
        }

        if (arg == "--install-ipa") {
            if (!mark_once(seen, arg, result.error)) return result;
            std::string value;
            if (!take_value(args, i, arg, value, result.error)) return result;
            boot.install_ipa = value;
            continue;
        }

        if (arg == "--dry-run") {
            if (!mark_once(seen, arg, result.error)) return result;
            result.dry_run = true;
            continue;
        }

        result.error = "unknown option: " + arg;
        return result;
    }

    if (boot.config.empty()) {
        result.error = "--config is required";
        return result;
    }

    if (!result.dry_run) {
        result.error = "native backend execution is not enabled in Phase 3; use --dry-run";
        return result;
    }

    result.request.protocol_version = kBackendProtocolVersion;
    result.request.operation = "boot";
    result.request.boot = std::move(boot);

    if (!validate_backend_request(result.request, result.error)) {
        return result;
    }

    result.ok = true;
    return result;
}

} // namespace vphone
