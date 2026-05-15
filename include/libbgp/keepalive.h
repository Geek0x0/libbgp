/**
 * @file keepalive.h
 * @brief BGP KEEPALIVE message parse and write helpers.
 * @ingroup libbgp_messages
 */

#ifndef LIBBGP_KEEPALIVE_H
#define LIBBGP_KEEPALIVE_H


/**
 * @file keepalive.h
 * @brief BGP KEEPALIVE message parse and write helpers.
 * @ingroup libbgp_messages
 */
#include <stddef.h>
#include <stdint.h>

#include "libbgp/types.h"

/**
 * @brief Parse a BGP KEEPALIVE message from a buffer.
 * @param buf Input buffer containing the KEEPALIVE message body.
 * @param len Length of buf in bytes.
 * @param consumed Out parameter set to number of bytes consumed from buf.
 * @return LIBBGP_OK on success, or an error code on failure.
 */
LIBBGP_API libbgp_err_t libbgp_keepalive_parse(
    const uint8_t *buf,
    size_t len,
    size_t *consumed);

/**
 * @brief Serialize a BGP KEEPALIVE message into a buffer.
 * @param buf Output buffer to write into.
 * @param buf_len Size of output buffer in bytes.
 * @param out_len Out parameter set to number of bytes written.
 * @return LIBBGP_OK on success, or an error code on failure.
 */
LIBBGP_API libbgp_err_t libbgp_keepalive_write(
    uint8_t *buf,
    size_t buf_len,
    size_t *out_len);

#endif
