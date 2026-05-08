#ifndef LIBBGP_PACKET_H
#define LIBBGP_PACKET_H

#include <stddef.h>
#include <stdint.h>

#include "libbgp/notification.h"
#include "libbgp/open.h"
#include "libbgp/types.h"
#include "libbgp/update.h"

typedef enum libbgp_packet_type {
    LIBBGP_PACKET_OPEN = 1,
    LIBBGP_PACKET_UPDATE = 2,
    LIBBGP_PACKET_NOTIFICATION = 3,
    LIBBGP_PACKET_KEEPALIVE = 4,
    LIBBGP_PACKET_UNKNOWN = 255
} libbgp_packet_type_t;

struct libbgp_packet {
    libbgp_packet_type_t type;
    union {
        libbgp_open_msg_t open;
        libbgp_update_msg_t update;
        libbgp_notification_msg_t notification;
    } data;
    uint8_t *raw_body;
    size_t raw_body_len;
    uint8_t raw_type;
};

LIBBGP_API void libbgp_packet_init(libbgp_packet_t *pkt);
LIBBGP_API void libbgp_packet_destroy(libbgp_packet_t *pkt);

LIBBGP_API libbgp_err_t libbgp_packet_parse(
    libbgp_packet_t *pkt,
    const uint8_t *buf,
    size_t len,
    size_t *consumed);

LIBBGP_API libbgp_err_t libbgp_packet_write(
    const libbgp_packet_t *pkt,
    uint8_t *buf,
    size_t buf_len,
    size_t *out_len);

#endif
