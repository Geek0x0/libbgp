#ifndef LIBBGP_NOTIFICATION_H
#define LIBBGP_NOTIFICATION_H

#include <stddef.h>
#include <stdint.h>

#include "libbgp/types.h"

struct libbgp_notification_msg {
    uint8_t err_code;
    uint8_t err_subcode;
    uint8_t *data;
    size_t data_len;
};

LIBBGP_API void libbgp_notification_init(libbgp_notification_msg_t *msg);
LIBBGP_API void libbgp_notification_destroy(libbgp_notification_msg_t *msg);

LIBBGP_API libbgp_err_t libbgp_notification_parse(
    libbgp_notification_msg_t *msg,
    const uint8_t *buf,
    size_t len,
    size_t *consumed);

LIBBGP_API libbgp_err_t libbgp_notification_write(
    const libbgp_notification_msg_t *msg,
    uint8_t *buf,
    size_t buf_len,
    size_t *out_len);

#endif
