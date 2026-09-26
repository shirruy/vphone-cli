#include "vphone/arm64_execution_provider.hpp"

#define WIN32_LEAN_AND_MEAN
#include <Windows.h>

#include <cstdio>
#include <filesystem>
#include <sstream>
#include <string>
#include <vector>

namespace vphone {
namespace {

std::string json_escape(
    const std::string& value
) {
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

std::string wide_to_utf8(
    const std::wstring& value
) {
    if (value.empty()) {
        return {};
    }

    const int required =
        WideCharToMultiByte(
            CP_UTF8,
            0,
            value.c_str(),
            -1,
            nullptr,
            0,
            nullptr,
            nullptr
        );

    if (required <= 1) {
        return {};
    }

    std::string out(
        static_cast<std::size_t>(required),
        '\0'
    );

    const int written =
        WideCharToMultiByte(
            CP_UTF8,
            0,
            value.c_str(),
            -1,
            out.data(),
            required,
            nullptr,
            nullptr
        );

    if (written <= 1) {
        return {};
    }

    if (
        !out.empty() &&
        out.back() == '\0'
    ) {
        out.pop_back();
    }

    return out;
}

std::string host_architecture() {
    SYSTEM_INFO info{};
    GetNativeSystemInfo(&info);

    switch (
        info.wProcessorArchitecture
    ) {
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

bool find_qemu(
    std::string& path
) {
    wchar_t buffer[32768]{};

    const DWORD found =
        SearchPathW(
            nullptr,
            L"qemu-system-aarch64.exe",
            nullptr,
            static_cast<DWORD>(
                _countof(buffer)
            ),
            buffer,
            nullptr
        );

    if (
        found > 0 &&
        found <
            static_cast<DWORD>(
                _countof(buffer)
            )
    ) {
        path = wide_to_utf8(buffer);

        if (!path.empty()) {
            return true;
        }
    }

    wchar_t programFiles[32768]{};

    const DWORD pfLength =
        GetEnvironmentVariableW(
            L"ProgramFiles",
            programFiles,
            static_cast<DWORD>(
                _countof(programFiles)
            )
        );

    if (
        pfLength > 0 &&
        pfLength <
            static_cast<DWORD>(
                _countof(programFiles)
            )
    ) {
        const std::filesystem::path candidate =
            std::filesystem::path(
                programFiles
            ) /
            L"qemu" /
            L"qemu-system-aarch64.exe";

        std::error_code ec;

        if (
            std::filesystem::is_regular_file(
                candidate,
                ec
            ) &&
            !ec
        ) {
            path =
                wide_to_utf8(
                    candidate.wstring()
                );

            return !path.empty();
        }
    }

    return false;
}

std::string run_capture(
    const std::string& executable,
    const std::string& arguments
) {
    const std::string command =
        "\"" +
        executable +
        "\" " +
        arguments +
        " 2>&1";

    FILE* pipe =
        _popen(
            command.c_str(),
            "r"
        );

    if (!pipe) {
        return {};
    }

    std::string output;
    char buffer[4096]{};

    while (
        std::fgets(
            buffer,
            static_cast<int>(
                sizeof(buffer)
            ),
            pipe
        )
    ) {
        output += buffer;
    }

    const int result =
        _pclose(pipe);

    if (result != 0) {
        return {};
    }

    return output;
}

bool contains_line_token(
    const std::string& text,
    const std::string& token
) {
    std::istringstream stream(text);
    std::string line;

    while (
        std::getline(
            stream,
            line
        )
    ) {
        const auto first =
            line.find_first_not_of(
                " \t\r\n"
            );

        if (
            first ==
            std::string::npos
        ) {
            continue;
        }

        if (
            line.compare(
                first,
                token.size(),
                token
            ) == 0
        ) {
            const auto end =
                first +
                token.size();

            if (
                end >= line.size() ||
                line[end] == ' ' ||
                line[end] == '\t'
            ) {
                return true;
            }
        }
    }

    return false;
}

} // namespace

const char* to_string(
    Arm64ExecutionProviderKind kind
) {
    switch (kind) {
    case Arm64ExecutionProviderKind::none:
        return "none";

    case Arm64ExecutionProviderKind::qemu_tcg:
        return "qemu-tcg";

    case Arm64ExecutionProviderKind::windows_arm64_native:
        return "windows-arm64-native";
    }

    return "unknown";
}

Arm64ExecutionProviderStatus
probe_arm64_execution_provider() {

    Arm64ExecutionProviderStatus status;

    status.host_architecture =
        host_architecture();

    std::string qemuPath;

    status.qemu_present =
        find_qemu(qemuPath);

    if (status.qemu_present) {

        status.executable_path =
            qemuPath;

        const auto version =
            run_capture(
                qemuPath,
                "--version"
            );

        const auto machines =
            run_capture(
                qemuPath,
                "-machine help"
            );

        const auto accelerators =
            run_capture(
                qemuPath,
                "-accel help"
            );

        status.version =
            version;

        status.qemu_virt_machine =
            contains_line_token(
                machines,
                "virt"
            );

        status.qemu_tcg_accelerator =
            contains_line_token(
                accelerators,
                "tcg"
            );

        if (
            status.qemu_virt_machine &&
            status.qemu_tcg_accelerator
        ) {
            status.kind =
                Arm64ExecutionProviderKind::
                    qemu_tcg;

            status.available = true;

            status.reason =
                "QEMU ARM64 system emulation "
                "with the virt machine and TCG "
                "accelerator is available. "
                "Apple machine modeling and "
                "Windows-hosted iPhone guest "
                "boot remain unimplemented.";

            return status;
        }

        status.reason =
            "qemu-system-aarch64.exe was found, "
            "but the required virt machine or "
            "TCG accelerator was unavailable.";

        return status;
    }

    if (
        status.host_architecture ==
        "arm64"
    ) {
        status.kind =
            Arm64ExecutionProviderKind::
                windows_arm64_native;

        status.available = true;

        status.reason =
            "Native ARM64 Windows execution "
            "substrate detected. Apple machine "
            "modeling and guest boot remain "
            "unimplemented.";

        return status;
    }

    status.reason =
        "No usable ARM64 execution provider "
        "was detected.";

    return status;
}

std::string arm64_execution_provider_json(
    const Arm64ExecutionProviderStatus& status
) {
    std::ostringstream out;

    out
        << "{\n"
        << "  \"provider\": \""
        << json_escape(
            to_string(status.kind)
        )
        << "\",\n"

        << "  \"host_architecture\": \""
        << json_escape(
            status.host_architecture
        )
        << "\",\n"

        << "  \"available\": "
        << (
            status.available
                ? "true"
                : "false"
        )
        << ",\n"

        << "  \"qemu_present\": "
        << (
            status.qemu_present
                ? "true"
                : "false"
        )
        << ",\n"

        << "  \"qemu_virt_machine\": "
        << (
            status.qemu_virt_machine
                ? "true"
                : "false"
        )
        << ",\n"

        << "  \"qemu_tcg_accelerator\": "
        << (
            status.qemu_tcg_accelerator
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

        << "  \"windows_guest_boot_ready\": "
        << (
            status.windows_guest_boot_ready
                ? "true"
                : "false"
        )
        << ",\n"

        << "  \"executable_path\": ";

    if (
        status.executable_path.empty()
    ) {
        out << "null";
    }
    else {
        out
            << "\""
            << json_escape(
                status.executable_path
            )
            << "\"";
    }

    out
        << ",\n"
        << "  \"reason\": \""
        << json_escape(
            status.reason
        )
        << "\"\n"
        << "}\n";

    return out.str();
}

} // namespace vphone