#ifndef LIBBGP_KEEPALIVE_H
#define LIBBGP_KEEPALIVE_H

#include <stddef.h>
#include <stdint.h>

#include "libbgp/types.h"

LIBBGP_API libbgp_err_t libbgp_keepalive_parse(
    const uint8_t *buf,
    size_t len,
    size_t *consumed);

LIBBGP_API libbgp_err_t libbgp_keepalive_write(
    uint8_t *buf,
    size_t buf_len,
    size_t *out_len);

#endif
