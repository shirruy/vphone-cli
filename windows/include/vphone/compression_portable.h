#pragma once

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum vphone_compression_kind {
    VPHONE_COMPRESSION_GZIP = 1,
    VPHONE_COMPRESSION_XZ = 2,
    VPHONE_COMPRESSION_ZSTD = 3
} vphone_compression_kind;

int vphone_compress_buffer(
    vphone_compression_kind kind,
    const void* input,
    size_t input_size,
    unsigned char** output,
    size_t* output_size,
    char* error,
    size_t error_size
);

int vphone_decompress_buffer(
    vphone_compression_kind kind,
    const void* input,
    size_t input_size,
    size_t expected_size,
    unsigned char** output,
    size_t* output_size,
    char* error,
    size_t error_size
);

void vphone_compression_free(void* data);

#ifdef __cplusplus
}
#endif
