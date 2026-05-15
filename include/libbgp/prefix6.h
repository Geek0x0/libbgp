#ifndef LIBBGP_PREFIX6_H
#define LIBBGP_PREFIX6_H

/**
 * @file prefix6.h
 * @brief IPv6 prefix parsing, serialization, comparison, and containment helpers.
 * @ingroup libbgp_prefix
 */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "libbgp/types.h"

/**
 * @brief IPv6 network prefix.
 */
struct libbgp_prefix6 {
    uint8_t addr[16]; ///< Network byte order IPv6 address with host bits ignored according to `len`.
    uint8_t len;      ///< Prefix length in bits, from 0 through 128.
};

/**
 * @brief Parse an IPv6 prefix from NLRI bytes.
 * @param[out] p Parsed prefix.
 * @param buf Input buffer containing NLRI bytes.
 * @param len Buffer length in bytes.
 * @param[out] consumed Number of NLRI bytes consumed.
 * @return `LIBBGP_OK` on success, `LIBBGP_ERR_BUFFER` for incomplete buffers,
 *         or `LIBBGP_ERR_INVALID` for invalid prefix lengths.
 */
LIBBGP_API libbgp_err_t libbgp_prefix6_parse(
    libbgp_prefix6_t *p,
    const uint8_t *buf,
    size_t len,
    size_t *consumed);

/**
 * @brief Serialize an IPv6 prefix to NLRI bytes.
 * @param p Prefix to write.
 * @param buf Output buffer.
 * @param len Output buffer length in bytes.
 * @param[out] out_len Number of NLRI bytes written.
 * @return `LIBBGP_OK` on success, `LIBBGP_ERR_BUFFER` for incomplete buffers,
 *         or `LIBBGP_ERR_INVALID` for invalid prefix lengths.
 */
LIBBGP_API libbgp_err_t libbgp_prefix6_write(
    const libbgp_prefix6_t *p,
    uint8_t *buf,
    size_t len,
    size_t *out_len);

/**
 * @brief Compare two IPv6 prefixes for equality.
 * @param a First prefix.
 * @param b Second prefix.
 * @return `true` when the prefixes are identical, otherwise `false`.
 */
LIBBGP_API bool libbgp_prefix6_eq(
    const libbgp_prefix6_t *a,
    const libbgp_prefix6_t *b);

/**
 * @brief Check whether one IPv6 prefix contains another.
 * @param outer Covering prefix.
 * @param inner Covered prefix.
 * @return `true` when `parent` covers every address in `child`, otherwise `false`.
 */
LIBBGP_API bool libbgp_prefix6_includes(
    const libbgp_prefix6_t *outer,
    const libbgp_prefix6_t *inner);

/**
 * @brief Compare two IPv6 prefixes.
 * @param a First prefix.
 * @param b Second prefix.
 * @return Negative, zero, or positive using address order first and prefix length second.
 */
LIBBGP_API int libbgp_prefix6_cmp(
    const libbgp_prefix6_t *a,
    const libbgp_prefix6_t *b);

/**
 * @brief Convert a CIDR prefix length to an IPv6 mask.
 * @param cidr Prefix length in bits.
 * @param[out] out Output mask bytes.
 */
LIBBGP_API void libbgp_cidr6_to_mask(uint8_t cidr, uint8_t out[16]);

#endif
