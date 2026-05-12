#include "libbgp/open.h"

#include <string.h>

#include "internal.h"

#define LIBBGP_OPEN_FIXED_LEN 10u
#define LIBBGP_OPEN_OPT_CAPABILITY 2u

void libbgp_open_init(libbgp_open_msg_t *msg)
{
    if (msg == NULL) {
        return;
    }
    memset(msg, 0, sizeof(*msg));
}

void libbgp_open_destroy(libbgp_open_msg_t *msg)
{
    size_t i;

    if (msg == NULL) {
        return;
    }
    for (i = 0u; i < msg->capability_count; i++) {
        libbgp_capability_unref(msg->capabilities[i]);
    }
    bgp_free(msg->capabilities);
    msg->capabilities = NULL;
    msg->capability_count = 0u;
}

libbgp_err_t libbgp_open_add_capability(libbgp_open_msg_t *msg, libbgp_capability_t *cap)
{
    libbgp_capability_t **next;

    if (msg == NULL || cap == NULL) {
        return LIBBGP_ERR_BAD_LEN;
    }
    if (msg->capability_count > (SIZE_MAX / sizeof(msg->capabilities[0])) - 1u) {
        return LIBBGP_ERR_BAD_LEN;
    }

    next = (libbgp_capability_t **)bgp_realloc(
        msg->capabilities,
        (msg->capability_count + 1u) * sizeof(msg->capabilities[0]));
    if (next == NULL) {
        return LIBBGP_ERR_NOMEM;
    }
    msg->capabilities = next;
    msg->capabilities[msg->capability_count] = libbgp_capability_ref(cap);
    msg->capability_count++;
    return LIBBGP_OK;
}

bool libbgp_open_has_4b_asn(const libbgp_open_msg_t *msg)
{
    size_t i;

    if (msg == NULL) {
        return false;
    }
    for (i = 0u; i < msg->capability_count; i++) {
        const libbgp_capability_t *cap = msg->capabilities[i];
        if (cap != NULL && cap->type == LIBBGP_CAP_4B_ASN) {
            return true;
        }
    }
    return false;
}

uint32_t libbgp_open_get_4b_asn(const libbgp_open_msg_t *msg)
{
    size_t i;

    if (msg == NULL) {
        return 0u;
    }
    for (i = 0u; i < msg->capability_count; i++) {
        const libbgp_capability_t *cap = msg->capabilities[i];
        if (cap != NULL && cap->type == LIBBGP_CAP_4B_ASN) {
            return cap->data.asn_4b.asn;
        }
    }
    return msg->my_asn;
}

bool libbgp_open_has_mpbgp(const libbgp_open_msg_t *msg, uint16_t afi, uint8_t safi)
{
    size_t i;

    if (msg == NULL) {
        return false;
    }
    for (i = 0u; i < msg->capability_count; i++) {
        const libbgp_capability_t *cap = msg->capabilities[i];
        if (cap != NULL &&
            cap->type == LIBBGP_CAP_MP_BGP &&
            cap->data.mp_bgp.afi == afi &&
            cap->data.mp_bgp.safi == safi) {
            return true;
        }
    }
    return false;
}

static libbgp_err_t open_parse_capabilities(
    libbgp_open_msg_t *tmp,
    const uint8_t *buf,
    size_t len)
{
    size_t pos = 0u;

    while (pos < len) {
        libbgp_capability_t *cap;
        size_t used = 0u;
        libbgp_err_t err;

        cap = libbgp_capability_new(LIBBGP_CAP_UNKNOWN);
        if (cap == NULL) {
            return LIBBGP_ERR_NOMEM;
        }
        err = libbgp_capability_parse(cap, buf + pos, len - pos, &used);
        if (err == LIBBGP_OK) {
            err = libbgp_open_add_capability(tmp, cap);
        }
        libbgp_capability_unref(cap);
        if (err != LIBBGP_OK) {
            return err;
        }
        if (used == 0u || used > len - pos) {
            return LIBBGP_ERR_BAD_LEN;
        }
        pos += used;
    }
    return LIBBGP_OK;
}

static libbgp_err_t open_parse_optional(
    libbgp_open_msg_t *tmp,
    const uint8_t *buf,
    size_t len)
{
    size_t pos = 0u;

    while (pos < len) {
        uint8_t param_type;
        uint8_t param_len;
        libbgp_err_t err;

        if (len - pos < 2u) {
            return LIBBGP_ERR_BAD_LEN;
        }
        param_type = buf[pos];
        param_len = buf[pos + 1u];
        pos += 2u;
        if (len - pos < (size_t)param_len) {
            return LIBBGP_ERR_BAD_LEN;
        }
        if (param_type == LIBBGP_OPEN_OPT_CAPABILITY) {
            err = open_parse_capabilities(tmp, buf + pos, param_len);
            if (err != LIBBGP_OK) {
                return err;
            }
        } else {
            return LIBBGP_ERR_BAD_TYPE;
        }
        pos += param_len;
    }
    return LIBBGP_OK;
}

libbgp_err_t libbgp_open_parse(
    libbgp_open_msg_t *msg,
    const uint8_t *buf,
    size_t len,
    size_t *consumed)
{
    libbgp_open_msg_t tmp;
    uint8_t opt_len;
    libbgp_err_t err;

    if (msg == NULL || buf == NULL || len < LIBBGP_OPEN_FIXED_LEN) {
        return LIBBGP_ERR_BAD_LEN;
    }
    opt_len = buf[9];
    if (len - LIBBGP_OPEN_FIXED_LEN < (size_t)opt_len) {
        return LIBBGP_ERR_BAD_LEN;
    }
    libbgp_open_init(&tmp);
    tmp.version = buf[0];
    tmp.my_asn = bgp_get_be16(buf + 1u);
    tmp.hold_time = bgp_get_be16(buf + 3u);
    tmp.bgp_id = bgp_get_be32(buf + 5u);

    err = open_parse_optional(&tmp, buf + LIBBGP_OPEN_FIXED_LEN, opt_len);
    if (err != LIBBGP_OK) {
        libbgp_open_destroy(&tmp);
        return err;
    }

    libbgp_open_destroy(msg);
    msg->version = tmp.version;
    msg->my_asn = tmp.my_asn;
    msg->hold_time = tmp.hold_time;
    msg->bgp_id = tmp.bgp_id;
    msg->capabilities = tmp.capabilities;
    msg->capability_count = tmp.capability_count;
    tmp.capabilities = NULL;
    tmp.capability_count = 0u;
    if (consumed != NULL) {
        *consumed = LIBBGP_OPEN_FIXED_LEN + (size_t)opt_len;
    }
    return LIBBGP_OK;
}

static libbgp_err_t open_capabilities_len(const libbgp_open_msg_t *msg, size_t *caps_len)
{
    uint8_t scratch[512];
    size_t i;
    size_t total = 0u;

    for (i = 0u; i < msg->capability_count; i++) {
        size_t one_len = 0u;
        libbgp_err_t err;

        err = libbgp_capability_write(msg->capabilities[i], scratch, sizeof(scratch), &one_len);
        if (err != LIBBGP_OK) {
            return err;
        }
        if (one_len > 255u || total > 255u - one_len) {
            return LIBBGP_ERR_BAD_LEN;
        }
        total += one_len;
    }
    *caps_len = total;
    return LIBBGP_OK;
}

libbgp_err_t libbgp_open_write(
    const libbgp_open_msg_t *msg,
    uint8_t *buf,
    size_t buf_len,
    size_t *out_len)
{
    size_t caps_len = 0u;
    size_t opt_len = 0u;
    size_t total_len;
    size_t pos;
    size_t i;
    libbgp_err_t err;

    if (msg == NULL || buf == NULL) {
        return LIBBGP_ERR_BAD_LEN;
    }
    if (msg->version != 4u) {
        return LIBBGP_ERR_BAD_LEN;
    }
    if (msg->capability_count != 0u && msg->capabilities == NULL) {
        return LIBBGP_ERR_BAD_LEN;
    }

    err = open_capabilities_len(msg, &caps_len);
    if (err != LIBBGP_OK) {
        return err;
    }
    if (caps_len != 0u) {
        if (caps_len > 255u) {
            return LIBBGP_ERR_BAD_LEN;
        }
        opt_len = 2u + caps_len;
    }
    if (opt_len > 255u) {
        return LIBBGP_ERR_BAD_LEN;
    }
    total_len = LIBBGP_OPEN_FIXED_LEN + opt_len;
    if (buf_len < total_len) {
        return LIBBGP_ERR_BUFFER;
    }

    buf[0] = msg->version;
    bgp_put_be16(buf + 1u, msg->my_asn);
    bgp_put_be16(buf + 3u, msg->hold_time);
    bgp_put_be32(buf + 5u, msg->bgp_id);
    buf[9] = (uint8_t)opt_len;
    pos = LIBBGP_OPEN_FIXED_LEN;
    if (caps_len != 0u) {
        buf[pos++] = LIBBGP_OPEN_OPT_CAPABILITY;
        buf[pos++] = (uint8_t)caps_len;
        for (i = 0u; i < msg->capability_count; i++) {
            size_t one_len = 0u;
            err = libbgp_capability_write(msg->capabilities[i], buf + pos, total_len - pos, &one_len);
            if (err != LIBBGP_OK) {
                return err;
            }
            pos += one_len;
        }
    }
    if (out_len != NULL) {
        *out_len = total_len;
    }
    return LIBBGP_OK;
}
