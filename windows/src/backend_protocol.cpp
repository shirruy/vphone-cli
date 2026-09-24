#include "vphone/backend_protocol.hpp"

#include <cctype>
#include <sstream>
#include <string_view>

namespace vphone {
namespace {

void skip_ws(std::string_view text, std::size_t& pos) {
    while (pos < text.size() && std::isspace(static_cast<unsigned char>(text[pos]))) {
        ++pos;
    }
}

bool find_value(std::string_view text, std::string_view key, std::size_t& pos) {
    std::size_t cursor = 0;

    while (cursor < text.size()) {
        if (text[cursor] != '"') {
            ++cursor;
            continue;
        }

        ++cursor;
        std::string token;
        bool escaped = false;
        bool closed = false;

        while (cursor < text.size()) {
            const char ch = text[cursor++];

            if (escaped) {
                token.push_back(ch);
                escaped = false;
                continue;
            }

            if (ch == '\\') {
                escaped = true;
                continue;
            }

            if (ch == '"') {
                closed = true;
                break;
            }

            token.push_back(ch);
        }

        if (!closed) {
            return false;
        }

        std::size_t after = cursor;
        skip_ws(text, after);

        // A JSON key is a string token immediately followed by a colon.
        // This deliberately avoids matching string values such as
        // "operation": "boot" when searching for the separate "boot" key.
        if (after < text.size() && text[after] == ':' && token == key) {
            pos = after + 1;
            skip_ws(text, pos);
            return pos < text.size();
        }
    }

    return false;
}

bool parse_string_at(std::string_view text, std::size_t& pos, std::string& value) {
    skip_ws(text, pos);
    if (pos >= text.size() || text[pos] != '"') {
        return false;
    }

    ++pos;
    std::string out;

    while (pos < text.size()) {
        const char ch = text[pos++];

        if (ch == '"') {
            value = std::move(out);
            return true;
        }

        if (ch != '\\') {
            out.push_back(ch);
            continue;
        }

        if (pos >= text.size()) {
            return false;
        }

        const char escaped = text[pos++];
        switch (escaped) {
        case '"': out.push_back('"'); break;
        case '\\': out.push_back('\\'); break;
        case '/': out.push_back('/'); break;
        case 'b': out.push_back('\b'); break;
        case 'f': out.push_back('\f'); break;
        case 'n': out.push_back('\n'); break;
        case 'r': out.push_back('\r'); break;
        case 't': out.push_back('\t'); break;
        default:
            return false;
        }
    }

    return false;
}

bool parse_required_string(std::string_view text, std::string_view key, std::string& value) {
    std::size_t pos = 0;
    return find_value(text, key, pos) && parse_string_at(text, pos, value);
}

bool parse_optional_string(
    std::string_view text,
    std::string_view key,
    std::optional<std::string>& value
) {
    std::size_t pos = 0;
    if (!find_value(text, key, pos)) {
        value.reset();
        return true;
    }

    if (text.substr(pos, 4) == "null") {
        value.reset();
        return true;
    }

    std::string parsed;
    if (!parse_string_at(text, pos, parsed)) {
        return false;
    }

    value = std::move(parsed);
    return true;
}

bool parse_required_bool(std::string_view text, std::string_view key, bool& value) {
    std::size_t pos = 0;
    if (!find_value(text, key, pos)) {
        return false;
    }

    if (text.substr(pos, 4) == "true") {
        value = true;
        return true;
    }

    if (text.substr(pos, 5) == "false") {
        value = false;
        return true;
    }

    return false;
}

bool parse_required_int(std::string_view text, std::string_view key, int& value) {
    std::size_t pos = 0;
    if (!find_value(text, key, pos)) {
        return false;
    }

    bool negative = false;
    if (text[pos] == '-') {
        negative = true;
        ++pos;
    }

    if (pos >= text.size() || !std::isdigit(static_cast<unsigned char>(text[pos]))) {
        return false;
    }

    long long parsed = 0;
    while (pos < text.size() && std::isdigit(static_cast<unsigned char>(text[pos]))) {
        parsed = parsed * 10 + (text[pos] - '0');
        ++pos;
        if (parsed > 2147483647LL + (negative ? 1LL : 0LL)) {
            return false;
        }
    }

    value = static_cast<int>(negative ? -parsed : parsed);
    return true;
}

bool parse_optional_int(std::string_view text, std::string_view key, std::optional<int>& value) {
    std::size_t pos = 0;
    if (!find_value(text, key, pos)) {
        value.reset();
        return true;
    }

    if (text.substr(pos, 4) == "null") {
        value.reset();
        return true;
    }

    bool negative = false;
    if (text[pos] == '-') {
        negative = true;
        ++pos;
    }

    if (pos >= text.size() || !std::isdigit(static_cast<unsigned char>(text[pos]))) {
        return false;
    }

    long long parsed = 0;
    while (pos < text.size() && std::isdigit(static_cast<unsigned char>(text[pos]))) {
        parsed = parsed * 10 + (text[pos] - '0');
        ++pos;
        if (parsed > 2147483647LL + (negative ? 1LL : 0LL)) {
            return false;
        }
    }

    value = static_cast<int>(negative ? -parsed : parsed);
    return true;
}

bool extract_object(std::string_view text, std::string_view key, std::string_view& object) {
    std::size_t pos = 0;
    if (!find_value(text, key, pos)) {
        return false;
    }

    if (pos >= text.size() || text[pos] != '{') {
        return false;
    }

    const std::size_t start = pos;
    int depth = 0;
    bool in_string = false;
    bool escaped = false;

    for (; pos < text.size(); ++pos) {
        const char ch = text[pos];

        if (in_string) {
            if (escaped) {
                escaped = false;
            } else if (ch == '\\') {
                escaped = true;
            } else if (ch == '"') {
                in_string = false;
            }
            continue;
        }

        if (ch == '"') {
            in_string = true;
        } else if (ch == '{') {
            ++depth;
        } else if (ch == '}') {
            --depth;
            if (depth == 0) {
                object = text.substr(start, pos - start + 1);
                return true;
            }
        }
    }

    return false;
}

std::string escape_json(std::string_view input) {
    std::string out;
    out.reserve(input.size() + 8);

    for (const char ch : input) {
        switch (ch) {
        case '"': out += "\\\""; break;
        case '\\': out += "\\\\"; break;
        case '\b': out += "\\b"; break;
        case '\f': out += "\\f"; break;
        case '\n': out += "\\n"; break;
        case '\r': out += "\\r"; break;
        case '\t': out += "\\t"; break;
        default: out.push_back(ch); break;
        }
    }

    return out;
}

void append_nullable_string(std::ostringstream& out, const std::optional<std::string>& value) {
    if (value) {
        out << "\"" << escape_json(*value) << "\"";
    } else {
        out << "null";
    }
}

} // namespace

bool validate_backend_request(const BackendRequest& request, std::string& error) {
    if (request.protocol_version != kBackendProtocolVersion) {
        error = "unsupported backend protocol version: " + std::to_string(request.protocol_version);
        return false;
    }

    if (request.operation != "boot") {
        error = "unsupported operation: " + request.operation;
        return false;
    }

    if (!request.boot) {
        error = "boot operation requires a boot payload";
        return false;
    }

    const auto& boot = *request.boot;

    if (boot.config.empty()) {
        error = "boot.config must not be empty";
        return false;
    }

    if (boot.dfu && boot.api_listen) {
        error = "api_listen is unavailable in DFU mode";
        return false;
    }

    if (boot.dfu && boot.install_ipa) {
        error = "install_ipa is unavailable in DFU mode";
        return false;
    }

    return true;
}

bool parse_backend_request_json(
    const std::string& json,
    BackendRequest& request,
    std::string& error
) {
    BackendRequest parsed;

    if (!parse_required_int(json, "protocol_version", parsed.protocol_version)) {
        error = "missing or invalid protocol_version";
        return false;
    }

    if (!parse_required_string(json, "operation", parsed.operation)) {
        error = "missing or invalid operation";
        return false;
    }

    if (parsed.operation == "boot") {
        std::string_view boot_json;
        if (!extract_object(json, "boot", boot_json)) {
            error = "missing or invalid boot object";
            return false;
        }

        BackendBootRequest boot;

        if (!parse_required_string(boot_json, "config", boot.config)) {
            error = "missing or invalid boot.config";
            return false;
        }

        if (!parse_required_bool(boot_json, "dfu", boot.dfu)) {
            error = "missing or invalid boot.dfu";
            return false;
        }

        if (!parse_required_bool(boot_json, "headless", boot.headless)) {
            error = "missing or invalid boot.headless";
            return false;
        }

        if (!parse_optional_string(boot_json, "api_listen", boot.api_listen)) {
            error = "invalid boot.api_listen";
            return false;
        }

        if (!parse_optional_int(boot_json, "kernel_debug_port", boot.kernel_debug_port)) {
            error = "invalid boot.kernel_debug_port";
            return false;
        }

        std::string vphoned_bin;
        if (!parse_required_string(boot_json, "vphoned_bin", vphoned_bin)) {
            error = "missing or invalid boot.vphoned_bin";
            return false;
        }
        boot.vphoned_bin = std::move(vphoned_bin);

        if (!parse_optional_string(boot_json, "install_ipa", boot.install_ipa)) {
            error = "invalid boot.install_ipa";
            return false;
        }

        parsed.boot = std::move(boot);
    }

    if (!validate_backend_request(parsed, error)) {
        return false;
    }

    request = std::move(parsed);
    return true;
}

std::string canonical_backend_request_json(const BackendRequest& request) {
    std::ostringstream out;
    out << "{\n"
        << "  \"protocol_version\": " << request.protocol_version << ",\n"
        << "  \"operation\": \"" << escape_json(request.operation) << "\",\n";

    if (!request.boot) {
        out << "  \"boot\": null\n}\n";
        return out.str();
    }

    const auto& boot = *request.boot;
    out << "  \"boot\": {\n"
        << "    \"config\": \"" << escape_json(boot.config) << "\",\n"
        << "    \"dfu\": " << (boot.dfu ? "true" : "false") << ",\n"
        << "    \"headless\": " << (boot.headless ? "true" : "false") << ",\n"
        << "    \"api_listen\": ";
    append_nullable_string(out, boot.api_listen);
    out << ",\n"
        << "    \"kernel_debug_port\": ";
    if (boot.kernel_debug_port) {
        out << *boot.kernel_debug_port;
    } else {
        out << "null";
    }
    out << ",\n"
        << "    \"vphoned_bin\": \"" << escape_json(boot.vphoned_bin) << "\",\n"
        << "    \"install_ipa\": ";
    append_nullable_string(out, boot.install_ipa);
    out << "\n  }\n}\n";

    return out.str();
}

} // namespace vphone
