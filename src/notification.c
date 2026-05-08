#include "libbgp/notification.h"

#include <string.h>

#include "internal.h"

void libbgp_notification_init(libbgp_notification_msg_t *msg)
{
    if (msg == NULL) {
        return;
    }
    memset(msg, 0, sizeof(*msg));
}

void libbgp_notification_destroy(libbgp_notification_msg_t *msg)
{
    if (msg == NULL) {
        return;
    }
    bgp_free(msg->data);
    msg->data = NULL;
    msg->data_len = 0u;
    msg->err_code = 0u;
    msg->err_subcode = 0u;
}

libbgp_err_t libbgp_notification_parse(
    libbgp_notification_msg_t *msg,
    const uint8_t *buf,
    size_t len,
    size_t *consumed)
{
    uint8_t *copy = NULL;
    size_t data_len;

    if (msg == NULL || buf == NULL || len < 2u) {
        return LIBBGP_ERR_BAD_LEN;
    }

    data_len = len - 2u;
    if (data_len != 0u) {
        copy = (uint8_t *)bgp_malloc(data_len);
        if (copy == NULL) {
            return LIBBGP_ERR_NOMEM;
        }
        memcpy(copy, buf + 2u, data_len);
    }

    libbgp_notification_destroy(msg);
    msg->err_code = buf[0];
    msg->err_subcode = buf[1];
    msg->data = copy;
    msg->data_len = data_len;
    if (consumed != NULL) {
        *consumed = len;
    }
    return LIBBGP_OK;
}

libbgp_err_t libbgp_notification_write(
    const libbgp_notification_msg_t *msg,
    uint8_t *buf,
    size_t buf_len,
    size_t *out_len)
{
    size_t len;

    if (msg == NULL || buf == NULL) {
        return LIBBGP_ERR_BAD_LEN;
    }
    if (msg->data_len != 0u && msg->data == NULL) {
        return LIBBGP_ERR_BAD_LEN;
    }
    if (msg->data_len > SIZE_MAX - 2u) {
        return LIBBGP_ERR_BAD_LEN;
    }
    len = 2u + msg->data_len;
    if (buf_len < len) {
        return LIBBGP_ERR_BUFFER;
    }

    buf[0] = msg->err_code;
    buf[1] = msg->err_subcode;
    if (msg->data_len != 0u) {
        memcpy(buf + 2u, msg->data, msg->data_len);
    }
    if (out_len != NULL) {
        *out_len = len;
    }
    return LIBBGP_OK;
}
