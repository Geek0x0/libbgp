#ifndef LIBBGP_OPEN_H
#define LIBBGP_OPEN_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "libbgp/capability.h"
#include "libbgp/types.h"

struct libbgp_open_msg {
    uint8_t version;
    uint16_t my_asn;
    uint16_t hold_time;
    uint32_t bgp_id;
    libbgp_capability_t **capabilities;
    size_t capability_count;
};

LIBBGP_API void libbgp_open_init(libbgp_open_msg_t *msg);
LIBBGP_API void libbgp_open_destroy(libbgp_open_msg_t *msg);
LIBBGP_API libbgp_err_t libbgp_open_add_capability(libbgp_open_msg_t *msg, libbgp_capability_t *cap);
LIBBGP_API uint32_t libbgp_open_get_4b_asn(const libbgp_open_msg_t *msg);
LIBBGP_API bool libbgp_open_has_mpbgp(const libbgp_open_msg_t *msg, uint16_t afi, uint8_t safi);

LIBBGP_API libbgp_err_t libbgp_open_parse(
    libbgp_open_msg_t *msg,
    const uint8_t *buf,
    size_t len,
    size_t *consumed);

LIBBGP_API libbgp_err_t libbgp_open_write(
    const libbgp_open_msg_t *msg,
    uint8_t *buf,
    size_t buf_len,
    size_t *out_len);

#endif
