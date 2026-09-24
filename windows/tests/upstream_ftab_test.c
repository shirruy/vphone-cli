#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "ftab.h"

int main(void)
{
    static const unsigned char payload[] = {0x10, 0x20, 0x30, 0x40, 0x50};

    ftab_t source = (ftab_t)calloc(1, sizeof(struct ftab_fmt));
    assert(source != NULL);

    source->header.always_01 = 1;
    source->header.always_ff = 0xFFFFFFFFu;
    source->header.tag = 'rkos';
    source->header.magic = 'ftab';

    assert(ftab_add_entry(source, 'TEST', payload, sizeof(payload)) == 0);

    void *encoded = NULL;
    size_t encoded_size = 0;
    assert(ftab_write(source, &encoded, &encoded_size) == 0);
    assert(encoded != NULL);
    assert(encoded_size > sizeof(struct ftab_header));

    assert(ftab_free(source) == 0);

    ftab_t parsed = NULL;
    uint32_t parsed_tag = 0;
    assert(ftab_parse(encoded, encoded_size, &parsed, &parsed_tag) == 0);
    assert(parsed != NULL);
    assert(parsed_tag == 'rkos');

    void *roundtrip_payload = NULL;
    size_t roundtrip_size = 0;
    assert(ftab_get_entry_ptr(parsed, 'TEST', &roundtrip_payload, &roundtrip_size) == 0);
    assert(roundtrip_size == sizeof(payload));
    assert(memcmp(roundtrip_payload, payload, sizeof(payload)) == 0);

    assert(ftab_free(parsed) == 0);
    free(encoded);

    return 0;
}
