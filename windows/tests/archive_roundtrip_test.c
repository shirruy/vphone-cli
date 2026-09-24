#include "vphone/archive_portable.h"

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

int main(int argc, char** argv)
{
    CHECK(argc == 2);

    static const unsigned char payload[] =
        "<?xml version=\"1.0\"?><plist><dict><key>ProductVersion</key><string>26.0</string></dict></plist>";

    char error[512] = {0};

    remove(argv[1]);

    CHECK(vphone_archive_create_single_gnutar(
        argv[1],
        "vm/config.plist",
        payload,
        sizeof(payload) - 1,
        error,
        sizeof(error)
    ) == 0);

    unsigned char* readback = NULL;
    size_t readback_size = 0;

    CHECK(vphone_archive_read_member(
        argv[1],
        "vm/config.plist",
        &readback,
        &readback_size,
        error,
        sizeof(error)
    ) == 0);

    CHECK(readback != NULL);
    CHECK(readback_size == sizeof(payload) - 1);
    CHECK(memcmp(readback, payload, readback_size) == 0);

    vphone_archive_free(readback);

    readback = NULL;
    readback_size = 0;
    CHECK(vphone_archive_read_member(
        argv[1],
        "vm/missing.plist",
        &readback,
        &readback_size,
        error,
        sizeof(error)
    ) != 0);
    CHECK(strstr(error, "not found") != NULL);

    remove(argv[1]);
    return 0;
}
