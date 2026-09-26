#include "vphone/runtime_foundation.hpp"

#define WIN32_LEAN_AND_MEAN
#include <Windows.h>

#include <sstream>
#include <string>

namespace vphone {
namespace {

std::string json_escape(const std::string& value) {
    std::string out;
    out.reserve(value.size() + 16);

    for (const char ch : value) {
        switch (ch) {
        case '\\':
            out += "\\\\";
            break;
        case '"':
            out += "\\\"";
            break;
        case '\n':
            out += "\\n";
            break;
        case '\r':
            out += "\\r";
            break;
        case '\t':
            out += "\\t";
            break;
        default:
            out.push_back(ch);
            break;
        }
    }

    return out;
}

std::string host_architecture() {
    SYSTEM_INFO info{};
    GetNativeSystemInfo(&info);

    switch (info.wProcessorArchitecture) {
    case PROCESSOR_ARCHITECTURE_ARM64:
        return "arm64";

    case PROCESSOR_ARCHITECTURE_AMD64:
        return "x64";

    case PROCESSOR_ARCHITECTURE_INTEL:
        return "x86";

    default:
        return "unknown";
    }
}

bool find_qemu_aarch64(std::string& path) {
    wchar_t buffer[32768]{};

    const DWORD result = SearchPathW(
        nullptr,
        L"qemu-system-aarch64.exe",
        nullptr,
        static_cast<DWORD>(_countof(buffer)),
        buffer,
        nullptr
    );

    if (
        result == 0 ||
        result >= static_cast<DWORD>(_countof(buffer))
    ) {
        return false;
    }

    const int required = WideCharToMultiByte(
        CP_UTF8,
        0,
        buffer,
        -1,
        nullptr,
        0,
        nullptr,
        nullptr
    );

    if (required <= 1) {
        return false;
    }

    std::string utf8(
        static_cast<std::size_t>(required),
        '\0'
    );

    const int written = WideCharToMultiByte(
        CP_UTF8,
        0,
        buffer,
        -1,
        utf8.data(),
        required,
        nullptr,
        nullptr
    );

    if (written <= 1) {
        return false;
    }

    if (!utf8.empty() && utf8.back() == '\0') {
        utf8.pop_back();
    }

    path = std::move(utf8);
    return true;
}

} // namespace

const char* to_string(RuntimeProvider provider) {
    switch (provider) {
    case RuntimeProvider::none:
        return "none";

    case RuntimeProvider::qemu_tcg_candidate:
        return "qemu-tcg-arm64-candidate";

    case RuntimeProvider::windows_arm64_candidate:
        return "windows-arm64-native-candidate";
    }

    return "unknown";
}

RuntimeFoundationStatus probe_runtime_foundation() {
    RuntimeFoundationStatus status;

    status.host_architecture = host_architecture();

    std::string qemuPath;

    status.qemu_system_aarch64_present =
        find_qemu_aarch64(qemuPath);

    if (status.host_architecture == "arm64") {
        status.provider =
            RuntimeProvider::windows_arm64_candidate;

        status.arm64_execution_provider_detected = true;

        status.reason =
            "ARM64 Windows host detected, but Apple machine model "
            "and guest boot runtime are not implemented.";

        return status;
    }

    if (status.qemu_system_aarch64_present) {
        status.provider =
            RuntimeProvider::qemu_tcg_candidate;

        status.provider_path = qemuPath;

        status.arm64_execution_provider_detected = true;

        status.reason =
            "QEMU ARM64 execution candidate detected, but Apple "
            "machine model and guest boot runtime are not implemented.";

        return status;
    }

    status.provider = RuntimeProvider::none;

    status.reason =
        "No ARM64 execution provider detected. "
        "Windows runtime remains fail-closed.";

    return status;
}

std::string runtime_foundation_json(
    const RuntimeFoundationStatus& status
) {
    std::ostringstream out;

    out
        << "{\n"
        << "  \"provider\": \""
        << json_escape(to_string(status.provider))
        << "\",\n"

        << "  \"host_architecture\": \""
        << json_escape(status.host_architecture)
        << "\",\n"

        << "  \"provider_path\": ";

    if (status.provider_path.empty()) {
        out << "null";
    }
    else {
        out
            << "\""
            << json_escape(status.provider_path)
            << "\"";
    }

    out
        << ",\n"

        << "  \"qemu_system_aarch64_present\": "
        << (
            status.qemu_system_aarch64_present
                ? "true"
                : "false"
        )
        << ",\n"

        << "  \"arm64_execution_provider_detected\": "
        << (
            status.arm64_execution_provider_detected
                ? "true"
                : "false"
        )
        << ",\n"

        << "  \"apple_machine_model_implemented\": "
        << (
            status.apple_machine_model_implemented
                ? "true"
                : "false"
        )
        << ",\n"

        << "  \"boot_ready\": "
        << (
            status.boot_ready
                ? "true"
                : "false"
        )
        << ",\n"

        << "  \"reason\": \""
        << json_escape(status.reason)
        << "\"\n"

        << "}\n";

    return out.str();
}

} // namespace vphone