#include "vphone/compression_portable.h"

#include <lzma.h>
#include <zlib.h>
#include <zstd.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void set_error(char* error, size_t error_size, const char* message)
{
    if (!error || error_size == 0) {
        return;
    }
    snprintf(error, error_size, "%s", message ? message : "compression error");
}

static int gzip_compress(
    const unsigned char* input,
    size_t input_size,
    unsigned char** output,
    size_t* output_size,
    char* error,
    size_t error_size
)
{
    z_stream stream;
    memset(&stream, 0, sizeof(stream));

    if (deflateInit2(
            &stream,
            Z_DEFAULT_COMPRESSION,
            Z_DEFLATED,
            MAX_WBITS + 16,
            8,
            Z_DEFAULT_STRATEGY
        ) != Z_OK) {
        set_error(error, error_size, "gzip deflateInit2 failed");
        return -1;
    }

    const uLong bound = compressBound((uLong)input_size);
    const size_t capacity = (size_t)bound + 64;

    unsigned char* buffer = (unsigned char*)malloc(capacity);
    if (!buffer) {
        deflateEnd(&stream);
        set_error(error, error_size, "out of memory");
        return -1;
    }

    stream.next_in = (Bytef*)input;
    stream.avail_in = (uInt)input_size;
    stream.next_out = buffer;
    stream.avail_out = (uInt)capacity;

    const int rc = deflate(&stream, Z_FINISH);
    if (rc != Z_STREAM_END) {
        free(buffer);
        deflateEnd(&stream);
        set_error(error, error_size, "gzip deflate failed");
        return -1;
    }

    *output_size = (size_t)stream.total_out;
    *output = buffer;

    deflateEnd(&stream);
    return 0;
}

static int gzip_decompress(
    const unsigned char* input,
    size_t input_size,
    size_t expected_size,
    unsigned char** output,
    size_t* output_size,
    char* error,
    size_t error_size
)
{
    z_stream stream;
    memset(&stream, 0, sizeof(stream));

    if (inflateInit2(&stream, MAX_WBITS + 16) != Z_OK) {
        set_error(error, error_size, "gzip inflateInit2 failed");
        return -1;
    }

    unsigned char* buffer = (unsigned char*)malloc(expected_size ? expected_size : 1);
    if (!buffer) {
        inflateEnd(&stream);
        set_error(error, error_size, "out of memory");
        return -1;
    }

    stream.next_in = (Bytef*)input;
    stream.avail_in = (uInt)input_size;
    stream.next_out = buffer;
    stream.avail_out = (uInt)expected_size;

    const int rc = inflate(&stream, Z_FINISH);
    if (rc != Z_STREAM_END || (size_t)stream.total_out != expected_size) {
        free(buffer);
        inflateEnd(&stream);
        set_error(error, error_size, "gzip inflate size/parity failure");
        return -1;
    }

    *output = buffer;
    *output_size = (size_t)stream.total_out;

    inflateEnd(&stream);
    return 0;
}

static int xz_compress(
    const unsigned char* input,
    size_t input_size,
    unsigned char** output,
    size_t* output_size,
    char* error,
    size_t error_size
)
{
    const size_t capacity = lzma_stream_buffer_bound(input_size);
    unsigned char* buffer = (unsigned char*)malloc(capacity ? capacity : 1);
    if (!buffer) {
        set_error(error, error_size, "out of memory");
        return -1;
    }

    size_t out_pos = 0;
    const lzma_ret rc = lzma_easy_buffer_encode(
        6,
        LZMA_CHECK_CRC64,
        NULL,
        input,
        input_size,
        buffer,
        &out_pos,
        capacity
    );

    if (rc != LZMA_OK) {
        free(buffer);
        set_error(error, error_size, "xz encode failed");
        return -1;
    }

    *output = buffer;
    *output_size = out_pos;
    return 0;
}

static int xz_decompress(
    const unsigned char* input,
    size_t input_size,
    size_t expected_size,
    unsigned char** output,
    size_t* output_size,
    char* error,
    size_t error_size
)
{
    unsigned char* buffer = (unsigned char*)malloc(expected_size ? expected_size : 1);
    if (!buffer) {
        set_error(error, error_size, "out of memory");
        return -1;
    }

    uint64_t memlimit = UINT64_MAX;
    size_t in_pos = 0;
    size_t out_pos = 0;

    const lzma_ret rc = lzma_stream_buffer_decode(
        &memlimit,
        0,
        NULL,
        input,
        &in_pos,
        input_size,
        buffer,
        &out_pos,
        expected_size
    );

    if (rc != LZMA_OK || in_pos != input_size || out_pos != expected_size) {
        free(buffer);
        set_error(error, error_size, "xz decode size/parity failure");
        return -1;
    }

    *output = buffer;
    *output_size = out_pos;
    return 0;
}

static int zstd_compress(
    const unsigned char* input,
    size_t input_size,
    unsigned char** output,
    size_t* output_size,
    char* error,
    size_t error_size
)
{
    const size_t capacity = ZSTD_compressBound(input_size);
    unsigned char* buffer = (unsigned char*)malloc(capacity ? capacity : 1);
    if (!buffer) {
        set_error(error, error_size, "out of memory");
        return -1;
    }

    const size_t written = ZSTD_compress(
        buffer,
        capacity,
        input,
        input_size,
        3
    );

    if (ZSTD_isError(written)) {
        set_error(error, error_size, ZSTD_getErrorName(written));
        free(buffer);
        return -1;
    }

    *output = buffer;
    *output_size = written;
    return 0;
}

static int zstd_decompress(
    const unsigned char* input,
    size_t input_size,
    size_t expected_size,
    unsigned char** output,
    size_t* output_size,
    char* error,
    size_t error_size
)
{
    const unsigned long long frame_size = ZSTD_getFrameContentSize(input, input_size);
    if (frame_size == ZSTD_CONTENTSIZE_ERROR ||
        frame_size == ZSTD_CONTENTSIZE_UNKNOWN ||
        frame_size != (unsigned long long)expected_size) {
        set_error(error, error_size, "zstd frame content-size mismatch");
        return -1;
    }

    unsigned char* buffer = (unsigned char*)malloc(expected_size ? expected_size : 1);
    if (!buffer) {
        set_error(error, error_size, "out of memory");
        return -1;
    }

    const size_t written = ZSTD_decompress(
        buffer,
        expected_size,
        input,
        input_size
    );

    if (ZSTD_isError(written) || written != expected_size) {
        if (ZSTD_isError(written)) {
            set_error(error, error_size, ZSTD_getErrorName(written));
        } else {
            set_error(error, error_size, "zstd decompressed size mismatch");
        }
        free(buffer);
        return -1;
    }

    *output = buffer;
    *output_size = written;
    return 0;
}

int vphone_compress_buffer(
    vphone_compression_kind kind,
    const void* input,
    size_t input_size,
    unsigned char** output,
    size_t* output_size,
    char* error,
    size_t error_size
)
{
    if (!input || input_size == 0 || !output || !output_size) {
        set_error(error, error_size, "invalid compression arguments");
        return -1;
    }

    *output = NULL;
    *output_size = 0;

    switch (kind) {
    case VPHONE_COMPRESSION_GZIP:
        return gzip_compress((const unsigned char*)input, input_size, output, output_size, error, error_size);
    case VPHONE_COMPRESSION_XZ:
        return xz_compress((const unsigned char*)input, input_size, output, output_size, error, error_size);
    case VPHONE_COMPRESSION_ZSTD:
        return zstd_compress((const unsigned char*)input, input_size, output, output_size, error, error_size);
    default:
        set_error(error, error_size, "unsupported compression kind");
        return -1;
    }
}

int vphone_decompress_buffer(
    vphone_compression_kind kind,
    const void* input,
    size_t input_size,
    size_t expected_size,
    unsigned char** output,
    size_t* output_size,
    char* error,
    size_t error_size
)
{
    if (!input || input_size == 0 || expected_size == 0 || !output || !output_size) {
        set_error(error, error_size, "invalid decompression arguments");
        return -1;
    }

    *output = NULL;
    *output_size = 0;

    switch (kind) {
    case VPHONE_COMPRESSION_GZIP:
        return gzip_decompress((const unsigned char*)input, input_size, expected_size, output, output_size, error, error_size);
    case VPHONE_COMPRESSION_XZ:
        return xz_decompress((const unsigned char*)input, input_size, expected_size, output, output_size, error, error_size);
    case VPHONE_COMPRESSION_ZSTD:
        return zstd_decompress((const unsigned char*)input, input_size, expected_size, output, output_size, error, error_size);
    default:
        set_error(error, error_size, "unsupported compression kind");
        return -1;
    }
}

void vphone_compression_free(void* data)
{
    free(data);
}
