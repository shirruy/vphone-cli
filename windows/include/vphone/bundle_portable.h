#pragma once

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

int vphone_bundle_validate_gnutar(
    const char* archive_path,
    size_t* member_count,
    size_t* hardlink_count,
    char* error,
    size_t error_size
);

#ifdef __cplusplus
}
#endif
