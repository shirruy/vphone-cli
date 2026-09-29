#include "vphone/apfs_reader.hpp"

#include <iostream>
#include <string>
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <wincrypt.h>

namespace {
std::string sha256_hex(const std::vector<std::uint8_t>& data) {
    HCRYPTPROV prov = 0;
    HCRYPTHASH hash = 0;
    std::string out;

    if (!CryptAcquireContextW(
            &prov, nullptr, nullptr, PROV_RSA_AES,
            CRYPT_VERIFYCONTEXT)) {
        return "";
    }
    if (CryptCreateHash(prov, CALG_SHA_256, 0, 0, &hash)) {
        if (CryptHashData(
                hash,
                const_cast<BYTE*>(data.data()),
                static_cast<DWORD>(data.size()),
                0)) {
            BYTE buf[32];
            DWORD len = 32;
            if (CryptGetHashParam(
                    hash, HP_HASHVAL, buf, &len, 0) && len == 32) {
                char hex[65];
                for (DWORD i = 0; i < 32; ++i) {
                    std::snprintf(
                        hex + i * 2, 3, "%02x", buf[i]
                    );
                }
                hex[64] = '\0';
                out = hex;
            }
        }
        CryptDestroyHash(hash);
    }
    CryptReleaseContext(prov, 0);
    return out;
}
} // namespace

int main(int argc, char** argv) {
    std::string dump_path;
    std::string resolve_path;
    std::string resolve_inode;
    if (argc == 4 && std::string(argv[1]) == "--dump-plist") {
        dump_path = argv[2];
    } else if (argc == 4 && std::string(argv[1]) == "--resolve-path") {
        resolve_path = argv[2];
    } else if (argc == 4 && std::string(argv[1]) == "--resolve-inode") {
        resolve_inode = argv[2];
    } else if (argc != 2) {
        std::cerr
            << "usage: vphone-apfs-reader-win <raw-apfs-image>\n"
            << "       vphone-apfs-reader-win --dump-plist <path> <raw-apfs-image>\n"
            << "       vphone-apfs-reader-win --resolve-path <path> <raw-apfs-image>\n"
            << "       vphone-apfs-reader-win --resolve-inode <cnid> <raw-apfs-image>\n";
        return 64;
    }

    const char* image_path =
        argc == 4 ? argv[3] : argv[1];

    if (!resolve_path.empty()) {
        vphone::ApfsPathResolution resolution;
        std::string error;
        if (!vphone::apfs_resolve_path(
                image_path, resolve_path, resolution, error)) {
            std::cerr << "ERROR: " << error << "\n";
            return 1;
        }
        std::cout << "{\n";
        std::cout << "  \"path\": \"" << resolve_path << "\",\n";
        std::cout << "  \"status\": \"" << resolution.status << "\",\n";
        std::cout << "  \"resolved\": "
                  << (resolution.resolved ? "true" : "false") << ",\n";
        std::cout << "  \"final_cnid\": "
                  << resolution.final_cnid << ",\n";
        std::cout << "  \"parent_cnid\": "
                  << resolution.parent_cnid << ",\n";
        std::cout << "  \"drec_type\": "
                  << resolution.drec_type << ",\n";
        std::cout << "  \"name\": \"" << resolution.name << "\"\n";
        std::cout << "}\n";
        return 0;
    }

    if (!resolve_inode.empty()) {
        const std::uint64_t cnid =
            static_cast<std::uint64_t>(
                std::strtoull(resolve_inode.c_str(), nullptr, 10));
        vphone::ApfsInodeResolution resolution;
        std::string error;
        if (!vphone::apfs_resolve_inode(
                image_path, cnid, resolution, error)) {
            std::cerr << "ERROR: " << error << "\n";
            return 1;
        }
        std::cout << "{\n";
        std::cout << "  \"cnid\": " << resolution.cnid << ",\n";
        std::cout << "  \"status\": \"" << resolution.status << "\",\n";
        std::cout << "  \"inode_found\": "
                  << (resolution.inode_found ? "true" : "false") << ",\n";
        std::cout << "  \"private_id\": "
                  << resolution.private_id << ",\n";
        std::cout << "  \"parent_id\": "
                  << resolution.parent_id << ",\n";
        std::cout << "  \"mode\": " << resolution.mode << ",\n";
        std::cout << "  \"bsd_flags\": "
                  << resolution.bsd_flags << ",\n";
        std::cout << "  \"compressed\": "
                  << (resolution.compressed ? "true" : "false") << ",\n";
        std::cout << "  \"has_dstream\": "
                  << (resolution.has_dstream ? "true" : "false") << ",\n";
        std::cout << "  \"dstream_size\": "
                  << resolution.dstream_size << ",\n";
        std::cout << "  \"extent_count\": "
                  << resolution.extent_count << ",\n";
        std::cout << "  \"bytes_reconstructed\": "
                  << (resolution.bytes_reconstructed ? "true" : "false")
                  << ",\n";
        std::cout << "  \"sha256\": \"" << resolution.sha256 << "\"\n";
        std::cout << "}\n";
        return 0;
    }

    vphone::ApfsReaderReport report;
    std::string error;
    if (!vphone::apfs_read_container(image_path, report, error)) {
        std::cerr << "ERROR: " << error << "\n";
        return 1;
    }

    if (!dump_path.empty() &&
        report.plist_file.status == "READ_OK" &&
        !report.plist_file.bytes.empty()) {
        HANDLE f = CreateFileA(
            dump_path.c_str(),
            GENERIC_WRITE,
            0,
            nullptr,
            CREATE_ALWAYS,
            FILE_ATTRIBUTE_NORMAL,
            nullptr
        );
        if (f != INVALID_HANDLE_VALUE) {
            DWORD written = 0;
            WriteFile(
                f,
                report.plist_file.bytes.data(),
                static_cast<DWORD>(
                    report.plist_file.bytes.size()),
                &written,
                nullptr
            );
            CloseHandle(f);
        }
    }

    std::cout << "{\n";
    std::cout << "  \"block_size\": " << report.container.block_size << ",\n";
    std::cout << "  \"block_count\": " << report.container.block_count << ",\n";
    std::cout << "  \"volumes\": [\n";
    for (std::size_t i = 0; i < report.volumes.size(); ++i) {
        const auto& v = report.volumes[i];
        std::cout << "    {\n";
        std::cout << "      \"apsb_block\": " << v.apsb_block << ",\n";
        std::cout << "      \"apsb_oid\": " << v.apsb_oid << ",\n";
        std::cout << "      \"xid\": " << v.xid << ",\n";
        std::cout << "      \"omap_block\": " << v.omap_block << ",\n";
        std::cout << "      \"root_tree_oid\": " << v.root_tree_oid << ",\n";
        std::cout << "      \"extentref_tree_oid\": " << v.extentref_tree_oid << ",\n";
        std::cout << "      \"root_tree_block\": " << v.root_tree_block << ",\n";
        std::cout << "      \"root_tree\": {\n";
        std::cout << "        \"flags\": " << v.root_tree_info.flags << ",\n";
        std::cout << "        \"level\": " << v.root_tree_info.level << ",\n";
        std::cout << "        \"nkeys\": " << v.root_tree_info.nkeys << ",\n";
        std::cout << "        \"has_footer\": " << (v.root_tree_info.has_footer ? "true" : "false") << ",\n";
        std::cout << "        \"bt_flags\": " << v.root_tree_info.bt_flags << ",\n";
        std::cout << "        \"node_size\": " << v.root_tree_info.node_size << ",\n";
        std::cout << "        \"key_size\": " << v.root_tree_info.key_size << ",\n";
        std::cout << "        \"val_size\": " << v.root_tree_info.val_size << "\n";
        std::cout << "      },\n";
        std::cout << "      \"volume_name\": \"" << v.volume_name << "\"\n";
        std::cout << "    }";
        if (i + 1 < report.volumes.size()) {
            std::cout << ",";
        }
        std::cout << "\n";
    }
    std::cout << "  ]\n";
    std::cout << "  ,";
    std::cout << "  \"launchdaemons\": {\n";
    std::cout << "    \"status\": \"" << report.launchdaemons_status << "\",\n";
    std::cout << "    \"cnid\": " << report.launchdaemons_cnid << "\n";
    std::cout << "  }\n";
    std::cout << "  ,";
    std::cout << "  \"plist_file\": {\n";
    std::cout << "    \"status\": \"" << report.plist_file.status << "\",\n";
    std::cout << "    \"name\": \"" << report.plist_file.name << "\",\n";
    std::cout << "    \"drec_cnid\": " << report.plist_file.drec_cnid << ",\n";
    std::cout << "    \"inode_cnid\": " << report.plist_file.inode_cnid << ",\n";
    std::cout << "    \"private_id\": " << report.plist_file.private_id << ",\n";
    std::cout << "    \"file_size\": " << report.plist_file.file_size << ",\n";
    std::cout << "    \"extent_count\": " << report.plist_file.extent_count << ",\n";
    std::cout << "    \"sha256\": \"" << sha256_hex(report.plist_file.bytes) << "\",\n";
    std::cout << "    \"format\": \"" << report.plist_file.format << "\"\n";
    if (!report.plist_file.error.empty()) {
        std::cout << "    ,\"error\": \"" << report.plist_file.error << "\"\n";
    }
    std::cout << "    ,\"decmpfs\": {\n";
    std::cout << "      \"found\": " << (report.plist_file.decmpfs_found ? "true" : "false") << "\n";
    std::cout << "      ,\"xattr_flags\": " << report.plist_file.xattr_flags << "\n";
    std::cout << "      ,\"signature\": " << report.plist_file.decmpfs_signature << "\n";
    std::cout << "      ,\"algo\": " << report.plist_file.decmpfs_algo << "\n";
    std::cout << "      ,\"logical_size\": " << report.plist_file.decmpfs_logical_size << "\n";
    std::cout << "      ,\"embedded\": " << (report.plist_file.xattr_embedded ? "true" : "false") << "\n";
    std::cout << "      ,\"needs_resource_fork\": " << (report.plist_file.needs_resource_fork ? "true" : "false") << "\n";
    std::cout << "    }\n";
    std::cout << "  }\n";
    std::cout << "}\n";
    return 0;
}
