#include "vphone/archive_portable.h"
#include "vphone/bundle_portable.h"
#include "vphone/compression_portable.h"

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

static int read_file(const char* path, unsigned char** data, size_t* size)
{
    FILE* fp = fopen(path, "rb");
    if (!fp) {
        return -1;
    }

    if (fseek(fp, 0, SEEK_END) != 0) {
        fclose(fp);
        return -1;
    }

    const long length = ftell(fp);
    if (length <= 0) {
        fclose(fp);
        return -1;
    }

    if (fseek(fp, 0, SEEK_SET) != 0) {
        fclose(fp);
        return -1;
    }

    unsigned char* buffer = (unsigned char*)malloc((size_t)length);
    if (!buffer) {
        fclose(fp);
        return -1;
    }

    if (fread(buffer, 1, (size_t)length, fp) != (size_t)length) {
        free(buffer);
        fclose(fp);
        return -1;
    }

    fclose(fp);
    *data = buffer;
    *size = (size_t)length;
    return 0;
}

static int write_file(const char* path, const void* data, size_t size)
{
    FILE* fp = fopen(path, "wb");
    if (!fp) {
        return -1;
    }

    const size_t written = fwrite(data, 1, size, fp);
    fclose(fp);
    return written == size ? 0 : -1;
}

static int roundtrip(
    vphone_compression_kind kind,
    const unsigned char* source,
    size_t source_size,
    const char* restored_tar
)
{
    char error[512] = {0};

    unsigned char* compressed = NULL;
    size_t compressed_size = 0;

    if (vphone_compress_buffer(
            kind,
            source,
            source_size,
            &compressed,
            &compressed_size,
            error,
            sizeof(error)
        ) != 0) {
        fprintf(stderr, "compress failed: %s\n", error);
        return -1;
    }

    if (!compressed || compressed_size == 0) {
        vphone_compression_free(compressed);
        return -1;
    }

    unsigned char* restored = NULL;
    size_t restored_size = 0;

    if (vphone_decompress_buffer(
            kind,
            compressed,
            compressed_size,
            source_size,
            &restored,
            &restored_size,
            error,
            sizeof(error)
        ) != 0) {
        fprintf(stderr, "decompress failed: %s\n", error);
        vphone_compression_free(compressed);
        return -1;
    }

    int result = 0;

    if (restored_size != source_size ||
        memcmp(restored, source, source_size) != 0) {
        fprintf(stderr, "byte parity mismatch\n");
        result = -1;
    } else if (write_file(restored_tar, restored, restored_size) != 0) {
        fprintf(stderr, "failed to write restored tar\n");
        result = -1;
    } else {
        size_t members = 0;
        size_t hardlinks = 0;
        memset(error, 0, sizeof(error));

        if (vphone_bundle_validate_gnutar(
                restored_tar,
                &members,
                &hardlinks,
                error,
                sizeof(error)
            ) != 0) {
            fprintf(stderr, "restored bundle validation failed: %s\n", error);
            result = -1;
        } else if (members != 3 || hardlinks != 1) {
            fprintf(stderr, "restored bundle semantic counts drifted\n");
            result = -1;
        }
    }

    vphone_compression_free(restored);
    vphone_compression_free(compressed);
    return result;
}

int main(int argc, char** argv)
{
    CHECK(argc == 3);

    const char* source_tar = argv[1];
    const char* restored_tar = argv[2];

    static const unsigned char config[] =
        "<?xml version=\"1.0\"?><plist><dict><key>Name</key><string>Compression</string></dict></plist>";
    static const unsigned char disk[] = {
        0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80
    };

    const vphone_archive_member members[] = {
        {"config.plist", config, sizeof(config) - 1, NULL},
        {"vm/disk.img", disk, sizeof(disk), NULL},
        {"vm/disk-copy.img", NULL, 0, "vm/disk.img"}
    };

    char error[512] = {0};

    remove(source_tar);
    remove(restored_tar);

    CHECK(vphone_archive_create_gnutar(
        source_tar,
        members,
        sizeof(members) / sizeof(members[0]),
        error,
        sizeof(error)
    ) == 0);

    unsigned char* source = NULL;
    size_t source_size = 0;

    CHECK(read_file(source_tar, &source, &source_size) == 0);
    CHECK(source != NULL);
    CHECK(source_size > 0);

    CHECK(roundtrip(VPHONE_COMPRESSION_GZIP, source, source_size, restored_tar) == 0);
    CHECK(roundtrip(VPHONE_COMPRESSION_XZ, source, source_size, restored_tar) == 0);
    CHECK(roundtrip(VPHONE_COMPRESSION_ZSTD, source, source_size, restored_tar) == 0);

    free(source);

    remove(restored_tar);
    remove(source_tar);

    return 0;
}
