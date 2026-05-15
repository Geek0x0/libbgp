#ifndef LIBBGP_PREFIX4_H
#define LIBBGP_PREFIX4_H

/**
 * @file prefix4.h
 * @brief IPv4 prefix parsing, serialization, comparison, and containment helpers.
 * @ingroup libbgp_prefix
 */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "libbgp/types.h"

/**
 * @brief IPv4 network prefix.
 */
struct libbgp_prefix4 {
    uint32_t addr; ///< Network byte order IPv4 address with host bits ignored according to `len`.
    uint8_t len;   ///< Prefix length in bits, from 0 through 32.
};

/**
 * @brief Parse an IPv4 prefix from NLRI bytes.
 * @param[out] p Parsed prefix.
 * @param buf Input buffer containing NLRI bytes.
 * @param len Buffer length in bytes.
 * @param[out] consumed Number of NLRI bytes consumed.
 * @return `LIBBGP_OK` on success, `LIBBGP_ERR_BUFFER` for incomplete buffers,
 *         or `LIBBGP_ERR_INVALID` for invalid prefix lengths.
 */
LIBBGP_API libbgp_err_t libbgp_prefix4_parse(
    libbgp_prefix4_t *p,
    const uint8_t *buf,
    size_t len,
    size_t *consumed);

/**
 * @brief Serialize an IPv4 prefix to NLRI bytes.
 * @param p Prefix to write.
 * @param buf Output buffer.
 * @param len Output buffer length in bytes.
 * @param[out] out_len Number of NLRI bytes written.
 * @return `LIBBGP_OK` on success, `LIBBGP_ERR_BUFFER` for incomplete buffers,
 *         or `LIBBGP_ERR_INVALID` for invalid prefix lengths.
 */
LIBBGP_API libbgp_err_t libbgp_prefix4_write(
    const libbgp_prefix4_t *p,
    uint8_t *buf,
    size_t len,
    size_t *out_len);

/**
 * @brief Compare two IPv4 prefixes for equality.
 * @param a First prefix.
 * @param b Second prefix.
 * @return `true` when the prefixes are identical, otherwise `false`.
 */
LIBBGP_API bool libbgp_prefix4_eq(
    const libbgp_prefix4_t *a,
    const libbgp_prefix4_t *b);

/**
 * @brief Check whether one IPv4 prefix contains another.
 * @param outer Covering prefix.
 * @param inner Covered prefix.
 * @return `true` when `parent` covers every address in `child`, otherwise `false`.
 */
LIBBGP_API bool libbgp_prefix4_includes(
    const libbgp_prefix4_t *outer,
    const libbgp_prefix4_t *inner);

/**
 * @brief Compare two IPv4 prefixes.
 * @param a First prefix.
 * @param b Second prefix.
 * @return Negative, zero, or positive using address order first and prefix length second.
 */
LIBBGP_API int libbgp_prefix4_cmp(
    const libbgp_prefix4_t *a,
    const libbgp_prefix4_t *b);

/**
 * @brief Convert a CIDR prefix length to an IPv4 mask.
 * @param cidr Prefix length in bits.
 * @return Network byte order IPv4 mask for the requested prefix length.
 */
LIBBGP_API uint32_t libbgp_cidr_to_mask(uint8_t cidr);

#endif
