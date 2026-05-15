/**
 * @file notification.h
 * @brief BGP NOTIFICATION message construction, parsing, and serialization.
 * @ingroup libbgp_messages
 */

#ifndef LIBBGP_NOTIFICATION_H
#define LIBBGP_NOTIFICATION_H


/**
 * @file notification.h
 * @brief BGP NOTIFICATION message construction, parsing, and serialization.
 * @ingroup libbgp_messages
 */
#include <stddef.h>
#include <stdint.h>

#include "libbgp/types.h"

/**
 * @brief BGP NOTIFICATION message containing error code, subcode and optional data.
 *
 * Call `libbgp_notification_init()` before first use and
 * `libbgp_notification_destroy()` when done. The data buffer is owned by the
 * notification message and will be freed by the destroy function.
 */
struct libbgp_notification_msg {
    uint8_t err_code;
    uint8_t err_subcode;
    uint8_t *data;
    size_t data_len;
};

/**
 * @brief Initialize a NOTIFICATION message object.
 * @param msg Message object to initialize.
 */
LIBBGP_API void libbgp_notification_init(libbgp_notification_msg_t *msg);

/**
 * @brief Destroy a NOTIFICATION message and free owned resources.
 * @param msg Message object previously initialized with the matching init function.
 */
LIBBGP_API void libbgp_notification_destroy(libbgp_notification_msg_t *msg);

/**
 * @brief Parse a BGP NOTIFICATION message from a buffer.
 * @param msg Initialized NOTIFICATION message to populate.
 * @param buf Input buffer containing the NOTIFICATION message body.
 * @param len Length of buf in bytes.
 * @param consumed Out parameter set to number of bytes consumed from buf.
 * @return LIBBGP_OK on success, or an error code on failure.
 */
LIBBGP_API libbgp_err_t libbgp_notification_parse(
    libbgp_notification_msg_t *msg,
    const uint8_t *buf,
    size_t len,
    size_t *consumed);

/**
 * @brief Serialize a NOTIFICATION message into a buffer.
 * @param msg NOTIFICATION message to serialize (must be initialized).
 * @param buf Output buffer to write into.
 * @param buf_len Size of output buffer in bytes.
 * @param out_len Out parameter set to number of bytes written.
 * @return LIBBGP_OK on success, or an error code on failure.
 */
LIBBGP_API libbgp_err_t libbgp_notification_write(
    const libbgp_notification_msg_t *msg,
    uint8_t *buf,
    size_t buf_len,
    size_t *out_len);

#endif
