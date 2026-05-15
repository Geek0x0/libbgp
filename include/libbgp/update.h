/**
 * @file update.h
 * @brief BGP UPDATE message construction, parsing, serialization, validation, and AS4 helpers.
 * @ingroup libbgp_messages
 */

#ifndef LIBBGP_UPDATE_H
#define LIBBGP_UPDATE_H


/**
 * @file update.h
 * @brief BGP UPDATE message construction, parsing, serialization, validation, and AS4 helpers.
 * @ingroup libbgp_messages
 */
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "libbgp/pattr.h"
#include "libbgp/prefix4.h"
#include "libbgp/types.h"

/**
 * @brief BGP UPDATE message with withdrawn routes, path attributes, and IPv4 NLRI.
 *
 * Call `libbgp_update_init()` before first use and `libbgp_update_destroy()`
 * when done. Path attributes added to the message are retained by reference.
 */
struct libbgp_update_msg {
    libbgp_prefix4_t *withdrawn;
    size_t withdrawn_count;
    libbgp_pattr_t **attrs;
    size_t attr_count;
    libbgp_prefix4_t *nlri;
    size_t nlri_count;
};

/**
 * @brief Initialize an UPDATE message object.
 * @param msg Message object to initialize.
 */
LIBBGP_API void libbgp_update_init(libbgp_update_msg_t *msg);

/**
 * @brief Destroy an UPDATE message and free owned resources.
 * @param msg Message object previously initialized with the matching init function.
 */
LIBBGP_API void libbgp_update_destroy(libbgp_update_msg_t *msg);

/**
 * @brief Add a withdrawn prefix to the UPDATE message.
 * @param msg Initialized UPDATE message to modify.
 * @param p Prefix to add (copied or referenced as appropriate).
 * @return LIBBGP_OK on success, or an error code on failure.
 */
LIBBGP_API libbgp_err_t libbgp_update_add_withdrawn(libbgp_update_msg_t *msg, const libbgp_prefix4_t *p);

/**
 * @brief Add a path attribute to the UPDATE message (retained by reference).
 * @param msg Initialized UPDATE message to modify.
 * @param attr Path attribute object to add.
 * @return LIBBGP_OK on success, or an error code on failure.
 */
LIBBGP_API libbgp_err_t libbgp_update_add_attr(libbgp_update_msg_t *msg, libbgp_pattr_t *attr);

/**
 * @brief Add an NLRI prefix to the UPDATE message.
 * @param msg Initialized UPDATE message to modify.
 * @param p IPv4 prefix to add.
 * @return LIBBGP_OK on success, or an error code on failure.
 */
LIBBGP_API libbgp_err_t libbgp_update_add_nlri(libbgp_update_msg_t *msg, const libbgp_prefix4_t *p);

/**
 * @brief Find the first path attribute of the given type in the UPDATE message.
 * @param msg Initialized UPDATE message to search.
 * @param type Attribute type to find.
 * @return Pointer to attribute when found, or NULL when not present.
 */
LIBBGP_API libbgp_pattr_t *libbgp_update_find_attr(const libbgp_update_msg_t *msg, libbgp_pattr_type_t type);

/**
 * @brief Validate an UPDATE message for internal consistency.
 * @param msg Initialized UPDATE message to validate.
 * @return LIBBGP_OK when valid, or an error code describing the violation.
 */
LIBBGP_API libbgp_err_t libbgp_update_validate(const libbgp_update_msg_t *msg);

/**
 * @brief Prepend an ASN to the AS_PATH attributes (used when advertising via confederations or AS prepend).
 * @param msg UPDATE message to modify (must be initialized).
 * @param asn ASN value to prepend.
 * @param use_4b_asn When true, use 4-byte ASN representation; otherwise use 2-byte.
 * @return LIBBGP_OK on success, or an error code on failure.
 */
LIBBGP_API libbgp_err_t libbgp_update_prepend_asn(libbgp_update_msg_t *msg, uint32_t asn, bool use_4b_asn);

/**
 * @brief Restore AS_PATH attributes from a downgraded representation.
 * @param msg UPDATE message to modify (must be initialized).
 * @return LIBBGP_OK on success, or an error code on failure.
 */
LIBBGP_API libbgp_err_t libbgp_update_restore_as_path(libbgp_update_msg_t *msg);

/**
 * @brief Downgrade AS_PATH attributes to 2-byte form when needed.
 * @param msg UPDATE message to modify (must be initialized).
 * @return LIBBGP_OK on success, or an error code on failure.
 */
LIBBGP_API libbgp_err_t libbgp_update_downgrade_as_path(libbgp_update_msg_t *msg);

/**
 * @brief Restore AGGREGATOR attribute from a downgraded representation.
 * @param msg UPDATE message to modify (must be initialized).
 * @return LIBBGP_OK on success, or an error code on failure.
 */
LIBBGP_API libbgp_err_t libbgp_update_restore_aggregator(libbgp_update_msg_t *msg);

/**
 * @brief Downgrade AGGREGATOR attribute to 2-byte AS form when needed.
 * @param msg UPDATE message to modify (must be initialized).
 * @return LIBBGP_OK on success, or an error code on failure.
 */
LIBBGP_API libbgp_err_t libbgp_update_downgrade_aggregator(libbgp_update_msg_t *msg);

/**
 * @brief Parse a BGP UPDATE message from a buffer.
 * @param msg Initialized UPDATE message to populate.
 * @param buf Input buffer containing the UPDATE message body.
 * @param len Length of buf in bytes.
 * @param consumed Out parameter set to number of bytes consumed from buf.
 * @return LIBBGP_OK on success, or an error code on failure.
 */
LIBBGP_API libbgp_err_t libbgp_update_parse(
    libbgp_update_msg_t *msg,
    const uint8_t *buf,
    size_t len,
    size_t *consumed);

/**
 * @brief Parse a BGP UPDATE message with AS4 (4-byte ASN) handling.
 * @param msg Initialized UPDATE message to populate.
 * @param buf Input buffer containing the UPDATE message body.
 * @param len Length of buf in bytes.
 * @param use_4b_asn When true, interpret/restore 4-byte ASN information where applicable.
 * @param consumed Out parameter set to number of bytes consumed from buf.
 * @return LIBBGP_OK on success, or an error code on failure.
 */
LIBBGP_API libbgp_err_t libbgp_update_parse_as4(
    libbgp_update_msg_t *msg,
    const uint8_t *buf,
    size_t len,
    bool use_4b_asn,
    size_t *consumed);

/**
 * @brief Serialize an UPDATE message into a buffer.
 * @param msg UPDATE message to serialize (must be initialized).
 * @param buf Output buffer to write into.
 * @param buf_len Size of output buffer in bytes.
 * @param out_len Out parameter set to number of bytes written.
 * @return LIBBGP_OK on success, or an error code on failure.
 */
LIBBGP_API libbgp_err_t libbgp_update_write(
    const libbgp_update_msg_t *msg,
    uint8_t *buf,
    size_t buf_len,
    size_t *out_len);

#endif
