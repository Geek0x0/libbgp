#ifndef LIBBGP_CAPABILITY_H
#define LIBBGP_CAPABILITY_H

#include <stddef.h>
#include <stdint.h>

#include "libbgp/types.h"

typedef enum libbgp_cap_type {
    LIBBGP_CAP_4B_ASN,
    LIBBGP_CAP_MP_BGP,
    LIBBGP_CAP_UNKNOWN
} libbgp_cap_type_t;

struct libbgp_capability {
    uint32_t refcount;
    uint8_t code;
    libbgp_cap_type_t type;
    union {
        struct { uint32_t asn; } asn_4b;
        struct { uint16_t afi; uint8_t safi; } mp_bgp;
        struct { uint8_t *value; size_t len; } unknown;
    } data;
};

LIBBGP_API libbgp_capability_t *libbgp_capability_new(libbgp_cap_type_t type);
LIBBGP_API libbgp_capability_t *libbgp_capability_ref(libbgp_capability_t *cap);
LIBBGP_API void libbgp_capability_unref(libbgp_capability_t *cap);

LIBBGP_API libbgp_err_t libbgp_capability_parse(
    libbgp_capability_t *cap,
    const uint8_t *buf,
    size_t len,
    size_t *consumed);

LIBBGP_API libbgp_err_t libbgp_capability_write(
    const libbgp_capability_t *cap,
    uint8_t *buf,
    size_t buf_len,
    size_t *out_len);

#endif
