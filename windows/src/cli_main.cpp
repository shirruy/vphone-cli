#include "vphone/cli_core.hpp"

#include <iostream>
#include <string>
#include <vector>

int main(int argc, char** argv) {
    std::vector<std::string> args;
    args.reserve(argc > 1 ? static_cast<std::size_t>(argc - 1) : 0);

    for (int i = 1; i < argc; ++i) {
        args.emplace_back(argv[i]);
    }

    const auto parsed = vphone::parse_native_cli(args);

    if (!parsed.ok) {
        std::cerr << "ERROR: " << parsed.error << "\n";
        std::cerr << vphone::native_cli_usage();
        return 64;
    }

    if (parsed.show_help) {
        std::cout << vphone::native_cli_usage();
        return 0;
    }

    if (parsed.show_version) {
        std::cout << "vphone-cli-win phase3 protocol/" << vphone::kBackendProtocolVersion << "\n";
        return 0;
    }

    if (args.size() == 1 && args[0] == "protocol-version") {
        std::cout << vphone::kBackendProtocolVersion << "\n";
        return 0;
    }

    if (parsed.show_firmware_capabilities) {
        std::cout
            << "{\n"
            << "  \"ftab\": \"supported\",\n"
            << "  \"mbn\": \"supported\",\n"
            << "  \"aea_decrypt_encrypt\": \"supported\",\n"
            << "  \"disk_image_udrw_raw_convert\": \"supported\",\n"
            << "  \"disk_image_udif_zlib_decode\": \"supported\",\n"
            << "  \"disk_image_udif_lzfse_decode\": \"supported\",\n"
            << "  \"disk_image_udif_bzip2_decode\": \"supported\",\n"
            << "  \"disk_image_udif_adc_decode\": \"supported\",\n"
            << "  \"disk_image_fixed_vhd_convert\": \"supported\",\n"
            << "  \"disk_image_fixed_vhd_attach_readonly\": \"supported\",\n"
            << "  \"disk_image_attach_convert\": \"unsupported\",\n"
            << "  \"apfs_seal\": \"unsupported\",\n"
            << "  \"canonical_metadata_archive\": \"unsupported\"\n"
            << "}\n";
        return 0;
    }

    if (parsed.show_archive_capabilities) {
        std::cout
            << "{\n"
            << "  \"gnutar_uncompressed\": \"supported\",\n"
            << "  \"member_read\": \"supported\",\n"
            << "  \"bundle_manifest_validation\": \"supported\",\n"
            << "  \"windows_hardlink_identity\": \"supported\",\n"
            << "  \"symlink_import\": \"unsupported\",\n"
            << "  \"zstd\": \"supported\",\n"
            << "  \"xz\": \"supported\",\n"
            << "  \"gzip\": \"supported\",\n"
            << "  \"darwin_xattrs_acl\": \"unsupported\"\n"
            << "}\n";
        return 0;
    }

    if (parsed.show_restore_capabilities) {
        std::cout
            << "{\n"
            << "  \"apfs_snapshot_rename\": \"supported\",\n"
            << "  \"aea_profile1_symmetric_core\": \"supported\",\n"
            << "  \"aea_profile1_file_backend\": \"supported\",\n"
            << "  \"aea_independent_interop\": \"supported\",\n"
            << "  \"aea_profile1_bounded_streaming\": \"supported\",\n"
            << "  \"aea_decrypt_encrypt\": \"supported\",\n"
            << "  \"disk_image_udrw_raw_convert\": \"supported\",\n"
            << "  \"disk_image_udif_zlib_decode\": \"supported\",\n"
            << "  \"disk_image_udif_lzfse_decode\": \"supported\",\n"
            << "  \"disk_image_udif_bzip2_decode\": \"supported\",\n"
            << "  \"disk_image_udif_adc_decode\": \"supported\",\n"
            << "  \"disk_image_fixed_vhd_convert\": \"supported\",\n"
            << "  \"disk_image_fixed_vhd_attach_readonly\": \"supported\",\n"
            << "  \"disk_image_attach_convert\": \"unsupported\",\n"
            << "  \"apfs_seal\": \"unsupported\",\n"
            << "  \"canonical_metadata_archive\": \"unsupported\"\n"
            << "}\n";
        return 0;
    }

    if (parsed.dry_run) {
        std::cout << vphone::canonical_backend_request_json(parsed.request);
        return 0;
    }

    std::cerr << "ERROR: unreachable native CLI state\n";
    return 70;
}

