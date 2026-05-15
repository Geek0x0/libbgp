/**
 * @file keepalive.c
 * @brief BGP KEEPALIVE parse and write helpers.
 */
#include "libbgp/keepalive.h"

#include "internal.h"

libbgp_err_t libbgp_keepalive_parse(
    const uint8_t *buf,
    size_t len,
    size_t *consumed)
{
    BGP_UNUSED(buf);

    if (len != 0u) {
        return LIBBGP_ERR_BAD_LEN;
    }
    if (consumed != NULL) {
        *consumed = 0u;
    }
    return LIBBGP_OK;
}

libbgp_err_t libbgp_keepalive_write(
    uint8_t *buf,
    size_t buf_len,
    size_t *out_len)
{
    BGP_UNUSED(buf);
    BGP_UNUSED(buf_len);

    if (out_len != NULL) {
        *out_len = 0u;
    }
    return LIBBGP_OK;
}
