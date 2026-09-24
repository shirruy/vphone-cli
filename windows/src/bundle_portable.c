#include "vphone/bundle_portable.h"

#include <archive.h>
#include <archive_entry.h>

#include <ctype.h>
#include <stdio.h>
#include <string.h>

static void set_error(char* error, size_t error_size, const char* message)
{
    if (!error || error_size == 0) {
        return;
    }
    snprintf(error, error_size, "%s", message ? message : "bundle validation failed");
}

static int is_safe_bundle_path(const char* path)
{
    if (!path || path[0] == '\0') {
        return 0;
    }

    if (path[0] == '/' || path[0] == '\\') {
        return 0;
    }

    if (isalpha((unsigned char)path[0]) && path[1] == ':') {
        return 0;
    }

    if (strchr(path, '\\') != NULL || strchr(path, ':') != NULL) {
        return 0;
    }

    const char* component = path;

    for (const char* p = path;; ++p) {
        if (*p == '/' || *p == '\0') {
            const size_t length = (size_t)(p - component);

            if (length == 0) {
                return 0;
            }

            if ((length == 1 && component[0] == '.') ||
                (length == 2 && component[0] == '.' && component[1] == '.')) {
                return 0;
            }

            if (*p == '\0') {
                break;
            }

            component = p + 1;
        }
    }

    return 1;
}

int vphone_bundle_validate_gnutar(
    const char* archive_path,
    size_t* member_count,
    size_t* hardlink_count,
    char* error,
    size_t error_size
)
{
    if (!archive_path || !member_count || !hardlink_count) {
        set_error(error, error_size, "invalid bundle validation arguments");
        return -1;
    }

    *member_count = 0;
    *hardlink_count = 0;

    struct archive* reader = archive_read_new();
    if (!reader) {
        set_error(error, error_size, "archive_read_new failed");
        return -1;
    }

    archive_read_support_format_tar(reader);

    int result = -1;
    size_t config_count = 0;

    if (archive_read_open_filename(reader, archive_path, 10240) != ARCHIVE_OK) {
        set_error(error, error_size, archive_error_string(reader));
        goto cleanup;
    }

    struct archive_entry* entry = NULL;

    while (archive_read_next_header(reader, &entry) == ARCHIVE_OK) {
        const char* path = archive_entry_pathname(entry);

        if (!is_safe_bundle_path(path)) {
            set_error(error, error_size, "unsafe bundle member path");
            goto cleanup_open;
        }

        if (archive_entry_symlink(entry) != NULL) {
            set_error(error, error_size, "symlink entries are not supported on Windows");
            goto cleanup_open;
        }

        const char* hardlink = archive_entry_hardlink(entry);
        if (hardlink) {
            if (!is_safe_bundle_path(hardlink)) {
                set_error(error, error_size, "unsafe bundle hardlink target");
                goto cleanup_open;
            }
            ++(*hardlink_count);
        }

        if (strcmp(path, "config.plist") == 0) {
            if (archive_entry_filetype(entry) != AE_IFREG || archive_entry_size(entry) <= 0) {
                set_error(error, error_size, "config.plist must be a non-empty regular file");
                goto cleanup_open;
            }
            ++config_count;
        }

        ++(*member_count);
        archive_read_data_skip(reader);
    }

    if (config_count != 1) {
        set_error(error, error_size, "bundle must contain exactly one top-level config.plist");
        goto cleanup_open;
    }

    result = 0;

cleanup_open:
    archive_read_close(reader);
cleanup:
    archive_read_free(reader);
    return result;
}
