#include "vphone/archive_portable.h"

#include <archive.h>
#include <archive_entry.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void set_error(char* error, size_t error_size, const char* message)
{
    if (!error || error_size == 0) {
        return;
    }
#if defined(_MSC_VER)
    snprintf(error, error_size, "%s", message ? message : "unknown archive error");
#else
    snprintf(error, error_size, "%s", message ? message : "unknown archive error");
#endif
}

int vphone_archive_create_single_gnutar(
    const char* archive_path,
    const char* stored_path,
    const void* data,
    size_t size,
    char* error,
    size_t error_size
)
{
    if (!archive_path || !stored_path || !data || size == 0) {
        set_error(error, error_size, "invalid create arguments");
        return -1;
    }

    struct archive* writer = archive_write_new();
    if (!writer) {
        set_error(error, error_size, "archive_write_new failed");
        return -1;
    }

    int result = -1;
    struct archive_entry* entry = NULL;

    if (archive_write_set_format_gnutar(writer) != ARCHIVE_OK) {
        set_error(error, error_size, archive_error_string(writer));
        goto cleanup;
    }

    if (archive_write_open_filename(writer, archive_path) != ARCHIVE_OK) {
        set_error(error, error_size, archive_error_string(writer));
        goto cleanup;
    }

    entry = archive_entry_new();
    if (!entry) {
        set_error(error, error_size, "archive_entry_new failed");
        goto cleanup_open;
    }

    archive_entry_set_pathname(entry, stored_path);
    archive_entry_set_filetype(entry, AE_IFREG);
    archive_entry_set_perm(entry, 0644);
    archive_entry_set_size(entry, (la_int64_t)size);

    if (archive_write_header(writer, entry) != ARCHIVE_OK) {
        set_error(error, error_size, archive_error_string(writer));
        goto cleanup_entry;
    }

    const la_ssize_t written = archive_write_data(writer, data, size);
    if (written < 0 || (size_t)written != size) {
        set_error(error, error_size, archive_error_string(writer));
        goto cleanup_entry;
    }

    result = 0;

cleanup_entry:
    archive_entry_free(entry);
cleanup_open:
    if (archive_write_close(writer) != ARCHIVE_OK && result == 0) {
        set_error(error, error_size, archive_error_string(writer));
        result = -1;
    }
cleanup:
    archive_write_free(writer);
    return result;
}

int vphone_archive_read_member(
    const char* archive_path,
    const char* member_path,
    unsigned char** data,
    size_t* size,
    char* error,
    size_t error_size
)
{
    if (!archive_path || !member_path || !data || !size) {
        set_error(error, error_size, "invalid read arguments");
        return -1;
    }

    *data = NULL;
    *size = 0;

    struct archive* reader = archive_read_new();
    if (!reader) {
        set_error(error, error_size, "archive_read_new failed");
        return -1;
    }

    archive_read_support_format_tar(reader);

    int result = -1;

    if (archive_read_open_filename(reader, archive_path, 10240) != ARCHIVE_OK) {
        set_error(error, error_size, archive_error_string(reader));
        goto cleanup;
    }

    struct archive_entry* entry = NULL;
    while (archive_read_next_header(reader, &entry) == ARCHIVE_OK) {
        const char* path = archive_entry_pathname(entry);
        if (!path || strcmp(path, member_path) != 0) {
            archive_read_data_skip(reader);
            continue;
        }

        const la_int64_t declared = archive_entry_size(entry);
        if (declared < 0 || (unsigned long long)declared > (unsigned long long)SIZE_MAX) {
            set_error(error, error_size, "invalid archive member size");
            goto cleanup_open;
        }

        const size_t capacity = (size_t)declared;
        unsigned char* buffer = (unsigned char*)malloc(capacity ? capacity : 1);
        if (!buffer) {
            set_error(error, error_size, "out of memory");
            goto cleanup_open;
        }

        size_t total = 0;
        while (total < capacity) {
            const la_ssize_t read = archive_read_data(reader, buffer + total, capacity - total);
            if (read < 0) {
                set_error(error, error_size, archive_error_string(reader));
                free(buffer);
                goto cleanup_open;
            }
            if (read == 0) {
                break;
            }
            total += (size_t)read;
        }

        if (total != capacity) {
            set_error(error, error_size, "archive member ended before declared size");
            free(buffer);
            goto cleanup_open;
        }

        *data = buffer;
        *size = total;
        result = 0;
        goto cleanup_open;
    }

    set_error(error, error_size, "archive member not found");

cleanup_open:
    archive_read_close(reader);
cleanup:
    archive_read_free(reader);
    return result;
}

void vphone_archive_free(void* data)
{
    free(data);
}
