/**
 * @file open.h
 * @brief BGP OPEN message construction, parsing, serialization, and capability helpers.
 * @ingroup libbgp_messages
 */

#ifndef LIBBGP_OPEN_H
#define LIBBGP_OPEN_H


/**
 * @file open.h
 * @brief BGP OPEN message construction, parsing, serialization, and capability helpers.
 * @ingroup libbgp_messages
 */
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "libbgp/capability.h"
#include "libbgp/types.h"

/**
 * @brief BGP OPEN message representation.
 *
 * Call `libbgp_open_init()` before first use and `libbgp_open_destroy()` when
 * done. Capability objects added to the message are retained by reference by
 * this message (the message does not make deep copies).
 */
struct libbgp_open_msg {
    uint8_t version;
    uint16_t my_asn;
    uint16_t hold_time;
    uint32_t bgp_id;
    libbgp_capability_t **capabilities;
    size_t capability_count;
};

/**
 * @brief Initialize an OPEN message object.
 * @param msg Message object to initialize.
 */
LIBBGP_API void libbgp_open_init(libbgp_open_msg_t *msg);

/**
 * @brief Destroy an OPEN message object and release owned memory.
 * @param msg Message object previously initialized with libbgp_open_init().
 */
LIBBGP_API void libbgp_open_destroy(libbgp_open_msg_t *msg);

/**
 * @brief Add a capability to an OPEN message.
 * @param msg Initialized OPEN message to modify.
 * @param cap Capability object to add (retained by reference).
 * @return LIBBGP_OK on success, or an error code on failure.
 */
LIBBGP_API libbgp_err_t libbgp_open_add_capability(libbgp_open_msg_t *msg, libbgp_capability_t *cap);

/**
 * @brief Check if OPEN message contains 4-byte ASN capability.
 * @param msg Initialized OPEN message to query.
 * @return true if 4-byte ASN capability is present, false otherwise.
 */
LIBBGP_API bool libbgp_open_has_4b_asn(const libbgp_open_msg_t *msg);

/**
 * @brief Retrieve the 4-byte ASN value from the OPEN message, if present.
 * @param msg Initialized OPEN message to query.
 * @return 4-byte ASN value when capability present, otherwise 0.
 */
LIBBGP_API uint32_t libbgp_open_get_4b_asn(const libbgp_open_msg_t *msg);

/**
 * @brief Check if OPEN message advertises MP-BGP for a specific AFI/SAFI.
 * @param msg Initialized OPEN message to query.
 * @param afi Address Family Identifier to check.
 * @param safi Subsequent Address Family Identifier to check.
 * @return true if MP-BGP for the given AFI/SAFI is advertised, false otherwise.
 */
LIBBGP_API bool libbgp_open_has_mpbgp(const libbgp_open_msg_t *msg, uint16_t afi, uint8_t safi);

/**
 * @brief Parse a BGP OPEN message from a buffer.
 * @param msg Initialized OPEN message to populate.
 * @param buf Input buffer containing the OPEN message body.
 * @param len Length of buf in bytes.
 * @param consumed Out parameter set to number of bytes consumed from buf.
 * @return LIBBGP_OK on success, or an error code on failure.
 */
LIBBGP_API libbgp_err_t libbgp_open_parse(
    libbgp_open_msg_t *msg,
    const uint8_t *buf,
    size_t len,
    size_t *consumed);

/**
 * @brief Serialize an OPEN message into a buffer.
 * @param msg OPEN message to serialize (must be initialized).
 * @param buf Output buffer to write into.
 * @param buf_len Size of output buffer in bytes.
 * @param out_len Out parameter set to number of bytes written.
 * @return LIBBGP_OK on success, or an error code on failure.
 */
LIBBGP_API libbgp_err_t libbgp_open_write(
    const libbgp_open_msg_t *msg,
    uint8_t *buf,
    size_t buf_len,
    size_t *out_len);

#endif
