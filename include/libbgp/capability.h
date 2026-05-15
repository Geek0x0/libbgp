#ifndef LIBBGP_CAPABILITY_H
#define LIBBGP_CAPABILITY_H


/**
 * @file capability.h
 * @brief BGP OPEN capability object parsing, serialization, and reference counting.
 * @ingroup libbgp_packet
 */
/**
 * @file capability.h
 * @brief BGP OPEN capability object parsing, serialization, and reference counting.
 * @ingroup libbgp_packet
 */

#include <stddef.h>
#include <stdint.h>

#include "libbgp/types.h"

typedef enum libbgp_cap_type {
    LIBBGP_CAP_4B_ASN,   ///< 4-octet AS number capability
    LIBBGP_CAP_MP_BGP,   ///< Multiprotocol extensions (AFI/SAFI)
    LIBBGP_CAP_UNKNOWN   ///< Unknown capability type
} libbgp_cap_type_t;

/**
 * @brief BGP capability object.
 *
 * Objects are reference-counted. `*_new()` returns one reference, `*_ref()`
 * adds a reference, and `*_unref()` releases one reference and destroys the
 * object when the count reaches zero.
 */
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

/**
 * @brief Allocate a new capability object of the given type.
 * @param type Capability type to create.
 * @return Newly allocated reference-counted object or NULL on allocation failure.
 */
LIBBGP_API libbgp_capability_t *libbgp_capability_new(libbgp_cap_type_t type);

/**
 * @brief Increment the reference count of a capability object.
 * @param cap Object to add a reference to.
 * @return The same object pointer (or NULL if `cap` is NULL).
 */
LIBBGP_API libbgp_capability_t *libbgp_capability_ref(libbgp_capability_t *cap);

/**
 * @brief Release a reference to a capability object; free when count reaches zero.
 * @param cap Object to unreference.
 */
LIBBGP_API void libbgp_capability_unref(libbgp_capability_t *cap);

/**
 * @brief Parse a capability from a wire buffer into |cap|.
 * @param cap Receives a newly allocated reference-counted object on success.
 * @param buf Source buffer containing the capability TLV (code, length, value).
 * @param len Length of |buf| in bytes.
 * @param consumed Receives the number of bytes consumed from |buf|; may be NULL.
 * @return `LIBBGP_OK` on success, `LIBBGP_ERR_PARSE` for malformed input,
 *         `LIBBGP_ERR_BUFFER` for incomplete input, or `LIBBGP_ERR_NOMEM`.
 */
LIBBGP_API libbgp_err_t libbgp_capability_parse(
    libbgp_capability_t *cap,
    const uint8_t *buf,
    size_t len,
    size_t *consumed);

/**
 * @brief Serialize a capability object to wire format.
 * @param cap Capability object to serialize.
 * @param buf Destination buffer to write into.
 * @param buf_len Size of |buf| in bytes.
 * @param out_len Receives the number of bytes written; may be NULL.
 * @return `LIBBGP_OK` on success, `LIBBGP_ERR_BUFFER` if |buf_len| is too small,
 *         or `LIBBGP_ERR_INVALID` if the object cannot be serialized.
 */
LIBBGP_API libbgp_err_t libbgp_capability_write(
    const libbgp_capability_t *cap,
    uint8_t *buf,
    size_t buf_len,
    size_t *out_len);

#endif
