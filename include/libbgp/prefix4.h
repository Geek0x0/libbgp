#ifndef LIBBGP_PREFIX4_H
#define LIBBGP_PREFIX4_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "libbgp/types.h"

struct libbgp_prefix4 {
    uint32_t addr;
    uint8_t len;
};

LIBBGP_API libbgp_err_t libbgp_prefix4_parse(
    libbgp_prefix4_t *p,
    const uint8_t *buf,
    size_t len,
    size_t *consumed);

LIBBGP_API libbgp_err_t libbgp_prefix4_write(
    const libbgp_prefix4_t *p,
    uint8_t *buf,
    size_t len,
    size_t *out_len);

LIBBGP_API bool libbgp_prefix4_eq(
    const libbgp_prefix4_t *a,
    const libbgp_prefix4_t *b);

LIBBGP_API bool libbgp_prefix4_includes(
    const libbgp_prefix4_t *outer,
    const libbgp_prefix4_t *inner);

LIBBGP_API int libbgp_prefix4_cmp(
    const libbgp_prefix4_t *a,
    const libbgp_prefix4_t *b);

LIBBGP_API uint32_t libbgp_cidr_to_mask(uint8_t cidr);

#endif
