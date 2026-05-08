#ifndef LIBBGP_PREFIX6_H
#define LIBBGP_PREFIX6_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "libbgp/types.h"

struct libbgp_prefix6 {
    uint8_t addr[16];
    uint8_t len;
};

LIBBGP_API libbgp_err_t libbgp_prefix6_parse(
    libbgp_prefix6_t *p,
    const uint8_t *buf,
    size_t len,
    size_t *consumed);

LIBBGP_API libbgp_err_t libbgp_prefix6_write(
    const libbgp_prefix6_t *p,
    uint8_t *buf,
    size_t len,
    size_t *out_len);

LIBBGP_API bool libbgp_prefix6_eq(
    const libbgp_prefix6_t *a,
    const libbgp_prefix6_t *b);

LIBBGP_API bool libbgp_prefix6_includes(
    const libbgp_prefix6_t *outer,
    const libbgp_prefix6_t *inner);

LIBBGP_API int libbgp_prefix6_cmp(
    const libbgp_prefix6_t *a,
    const libbgp_prefix6_t *b);

LIBBGP_API void libbgp_cidr6_to_mask(uint8_t cidr, uint8_t out[16]);

#endif
