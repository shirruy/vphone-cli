#include "vphone/archive_portable.h"
#include "vphone/bundle_portable.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CHECK(expr) \
    do { \
        if (!(expr)) { \
            fprintf(stderr, "CHECK FAILED at %s:%d: %s\n", __FILE__, __LINE__, #expr); \
            return 1; \
        } \
    } while (0)

static int write_bundle(const char* path, const vphone_archive_member* members, size_t count)
{
    char error[512] = {0};
    remove(path);
    const int rc = vphone_archive_create_gnutar(path, members, count, error, sizeof(error));
    if (rc != 0) {
        fprintf(stderr, "archive create failed: %s\n", error);
    }
    return rc;
}

int main(int argc, char** argv)
{
    CHECK(argc == 2);

    const char* path = argv[1];
    char error[512] = {0};
    size_t member_count = 0;
    size_t hardlink_count = 0;

    static const unsigned char config[] =
        "<?xml version=\"1.0\"?><plist><dict><key>Name</key><string>Bundle</string></dict></plist>";
    static const unsigned char disk[] = {0x10, 0x20, 0x30, 0x40};
    static const unsigned char meta[] = "metadata";

    const vphone_archive_member valid[] = {
        {"config.plist", config, sizeof(config) - 1, NULL},
        {"vm/disk.img", disk, sizeof(disk), NULL},
        {"vm/disk-copy.img", NULL, 0, "vm/disk.img"},
        {"meta/info.txt", meta, sizeof(meta) - 1, NULL}
    };

    CHECK(write_bundle(path, valid, sizeof(valid) / sizeof(valid[0])) == 0);
    CHECK(vphone_bundle_validate_gnutar(
        path, &member_count, &hardlink_count, error, sizeof(error)
    ) == 0);
    CHECK(member_count == 4);
    CHECK(hardlink_count == 1);

    const vphone_archive_member missing_config[] = {
        {"vm/disk.img", disk, sizeof(disk), NULL}
    };
    CHECK(write_bundle(path, missing_config, 1) == 0);
    memset(error, 0, sizeof(error));
    CHECK(vphone_bundle_validate_gnutar(
        path, &member_count, &hardlink_count, error, sizeof(error)
    ) != 0);
    CHECK(strstr(error, "config.plist") != NULL);

    const vphone_archive_member traversal[] = {
        {"config.plist", config, sizeof(config) - 1, NULL},
        {"../escape.txt", meta, sizeof(meta) - 1, NULL}
    };
    CHECK(write_bundle(path, traversal, 2) == 0);
    memset(error, 0, sizeof(error));
    CHECK(vphone_bundle_validate_gnutar(
        path, &member_count, &hardlink_count, error, sizeof(error)
    ) != 0);
    CHECK(strstr(error, "unsafe bundle member path") != NULL);

    const vphone_archive_member ads_path[] = {
        {"config.plist", config, sizeof(config) - 1, NULL},
        {"vm/file.txt:stream", meta, sizeof(meta) - 1, NULL}
    };
    CHECK(write_bundle(path, ads_path, 2) == 0);
    memset(error, 0, sizeof(error));
    CHECK(vphone_bundle_validate_gnutar(
        path, &member_count, &hardlink_count, error, sizeof(error)
    ) != 0);
    CHECK(strstr(error, "unsafe bundle member path") != NULL);

    const vphone_archive_member bad_hardlink[] = {
        {"config.plist", config, sizeof(config) - 1, NULL},
        {"vm/link.img", NULL, 0, "../outside.img"}
    };
    CHECK(write_bundle(path, bad_hardlink, 2) == 0);
    memset(error, 0, sizeof(error));
    CHECK(vphone_bundle_validate_gnutar(
        path, &member_count, &hardlink_count, error, sizeof(error)
    ) != 0);
    CHECK(strstr(error, "unsafe bundle hardlink target") != NULL);

    remove(path);
    return 0;
}
