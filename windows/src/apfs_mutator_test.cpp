#include "vphone/apfs_reader.hpp"
#include <cstdio>
#include <string>

int main(int argc, char** argv) {
    if (argc < 2) {
        std::fprintf(stderr, "usage: vphone-apfs-mutator-test <image-copy>\n");
        return 64;
    }
    vphone::ApfsMutationResult result;
    std::string error;
    const bool ok = vphone::apfs_mutate_plist_byte(
        argv[1],
        "a5ff5c5e0b656c51befcae503d0ba878ff41a348b3b19dcfd01877a09e41b2eb",
        639, 100, 0x69, 0x68,
        result, error
    );
    std::printf("{\n");
    std::printf("  \"success\": %s,\n", ok ? "true" : "false");
    std::printf("  \"error\": \"%s\",\n", error.c_str());
    std::printf("  \"apsb_block\": %llu,\n", (unsigned long long)result.apsb_block);
    std::printf("  \"volume_xid\": %llu,\n", (unsigned long long)result.volume_xid);
    std::printf("  \"target_leaf_block\": %llu,\n", (unsigned long long)result.target_leaf_block);
    std::printf("  \"data_offset_in_block\": %llu,\n", (unsigned long long)result.data_offset_in_block);
    std::printf("  \"old_byte\": %u,\n", (unsigned)result.old_byte);
    std::printf("  \"new_byte\": %u,\n", (unsigned)result.new_byte);
    std::printf("  \"old_plist_sha256\": \"%s\",\n", result.old_plist_sha256.c_str());
    std::printf("  \"new_plist_sha256\": \"%s\",\n", result.new_plist_sha256.c_str());
    std::printf("  \"old_block_checksum\": \"%s\",\n", result.old_block_checksum.c_str());
    std::printf("  \"new_block_checksum\": \"%s\"\n", result.new_block_checksum.c_str());
    std::printf("}\n");
    return ok ? 0 : 1;
}
