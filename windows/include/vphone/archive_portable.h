#pragma once

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

int vphone_archive_create_single_gnutar(
    const char* archive_path,
    const char* stored_path,
    const void* data,
    size_t size,
    char* error,
    size_t error_size
);

int vphone_archive_read_member(
    const char* archive_path,
    const char* member_path,
    unsigned char** data,
    size_t* size,
    char* error,
    size_t error_size
);

void vphone_archive_free(void* data);

#ifdef __cplusplus
}
#endif
