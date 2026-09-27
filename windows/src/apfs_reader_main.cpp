#include "vphone/apfs_reader.hpp"

#include <iostream>
#include <string>

int main(int argc, char** argv) {
    if (argc != 2) {
        std::cerr << "usage: vphone-apfs-reader-win <raw-apfs-image>\n";
        return 64;
    }

    vphone::ApfsReaderReport report;
    std::string error;
    if (!vphone::apfs_read_container(argv[1], report, error)) {
        std::cerr << "ERROR: " << error << "\n";
        return 1;
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
    std::cout << "  \"launchdaemons\": {\n";
    std::cout << "    \"status\": \"" << report.launchdaemons_status << "\",\n";
    std::cout << "    \"cnid\": " << report.launchdaemons_cnid << "\n";
    std::cout << "  }\n";
    std::cout << "}\n";
    return 0;
}
