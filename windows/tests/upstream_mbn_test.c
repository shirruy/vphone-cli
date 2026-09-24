#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "mbn.h"

#define CHECK(expr) \
    do { \
        if (!(expr)) { \
            fprintf(stderr, "CHECK FAILED at %s:%d: %s\n", __FILE__, __LINE__, #expr); \
            return 1; \
        } \
    } while (0)

static void write_u32_le(unsigned char* p, uint32_t value)
{
    p[0] = (unsigned char)(value & 0xFF);
    p[1] = (unsigned char)((value >> 8) & 0xFF);
    p[2] = (unsigned char)((value >> 16) & 0xFF);
    p[3] = (unsigned char)((value >> 24) & 0xFF);
}

int main(void)
{
    enum { HEADER_SIZE = 40, TOTAL_SIZE = 64 };
    unsigned char image[TOTAL_SIZE];

    for (size_t i = 0; i < sizeof(image); ++i) {
        image[i] = (unsigned char)i;
    }

    write_u32_le(&image[0], 0x0000000A);
    write_u32_le(&image[16], TOTAL_SIZE - HEADER_SIZE);

    static const unsigned char signature[] = {0xDE, 0xAD, 0xBE, 0xEF};

    unsigned char expected[TOTAL_SIZE];
    memcpy(expected, image, sizeof(expected));
    memcpy(expected + TOTAL_SIZE - sizeof(signature), signature, sizeof(signature));

    void* stitched = mbn_stitch(image, sizeof(image), signature, sizeof(signature));
    CHECK(stitched != NULL);
    CHECK(memcmp(stitched, expected, sizeof(expected)) == 0);

    free(stitched);

    CHECK(mbn_stitch(NULL, sizeof(image), signature, sizeof(signature)) == NULL);
    CHECK(mbn_stitch(image, sizeof(image), NULL, sizeof(signature)) == NULL);
    CHECK(mbn_stitch(image, sizeof(image), signature, 0) == NULL);

    return 0;
}
