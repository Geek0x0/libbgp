#include "libbgp/packet.h"

#include <string.h>

#include "internal.h"
#include "libbgp/keepalive.h"

void libbgp_packet_init(libbgp_packet_t *pkt)
{
    if (pkt == NULL) {
        return;
    }
    memset(pkt, 0, sizeof(*pkt));
    pkt->type = LIBBGP_PACKET_UNKNOWN;
    pkt->raw_type = (uint8_t)LIBBGP_PACKET_UNKNOWN;
}

void libbgp_packet_destroy(libbgp_packet_t *pkt)
{
    if (pkt == NULL) {
        return;
    }
    switch (pkt->type) {
    case LIBBGP_PACKET_OPEN:
        libbgp_open_destroy(&pkt->data.open);
        break;
    case LIBBGP_PACKET_UPDATE:
        libbgp_update_destroy(&pkt->data.update);
        break;
    case LIBBGP_PACKET_NOTIFICATION:
        libbgp_notification_destroy(&pkt->data.notification);
        break;
    case LIBBGP_PACKET_KEEPALIVE:
    case LIBBGP_PACKET_UNKNOWN:
    default:
        break;
    }
    bgp_free(pkt->raw_body);
    pkt->raw_body = NULL;
    pkt->raw_body_len = 0u;
    pkt->raw_type = (uint8_t)LIBBGP_PACKET_UNKNOWN;
    pkt->type = LIBBGP_PACKET_UNKNOWN;
}

static bool packet_marker_valid(const uint8_t *buf)
{
    size_t i;

    for (i = 0u; i < LIBBGP_BGP_MARKER_LEN; i++) {
        if (buf[i] != 0xffu) {
            return false;
        }
    }
    return true;
}

static libbgp_packet_type_t packet_type_from_raw(uint8_t raw_type)
{
    switch (raw_type) {
    case 1u:
        return LIBBGP_PACKET_OPEN;
    case 2u:
        return LIBBGP_PACKET_UPDATE;
    case 3u:
        return LIBBGP_PACKET_NOTIFICATION;
    case 4u:
        return LIBBGP_PACKET_KEEPALIVE;
    default:
        return LIBBGP_PACKET_UNKNOWN;
    }
}

static void packet_parse_detail_set(
    bgp_parse_error_detail_t *detail,
    libbgp_err_t err,
    uint8_t notify_code,
    uint8_t notify_subcode)
{
    if (detail == NULL) {
        return;
    }
    detail->err = err;
    detail->notify_code = notify_code;
    detail->notify_subcode = notify_subcode;
}

static void packet_parse_map_body_error(
    bgp_parse_error_detail_t *detail,
    libbgp_packet_type_t type,
    libbgp_err_t err)
{
    uint8_t code = 0u;
    uint8_t subcode = 0u;

    if (err == LIBBGP_ERR_NOMEM) {
        packet_parse_detail_set(detail, err, 0u, 0u);
        return;
    }
    if (type == LIBBGP_PACKET_UPDATE) {
        code = 3u;
        subcode = err == LIBBGP_ERR_INVALID ? 3u : 1u;
    } else if (type == LIBBGP_PACKET_OPEN) {
        code = 2u;
        if (err == LIBBGP_ERR_BAD_TYPE) {
            subcode = 4u;
        }
    } else if (type == LIBBGP_PACKET_NOTIFICATION || type == LIBBGP_PACKET_KEEPALIVE) {
        code = 1u;
        subcode = 2u;
    }
    packet_parse_detail_set(detail, err, code, subcode);
}

libbgp_err_t bgp_packet_parse_as4_detail(
    libbgp_packet_t *pkt,
    const uint8_t *buf,
    size_t len,
    bool use_4b_asn,
    size_t *consumed,
    bgp_parse_error_detail_t *detail)
{
    libbgp_packet_t tmp;
    uint16_t wire_len;
    uint8_t raw_type;
    const uint8_t *body;
    size_t body_len;
    size_t used = 0u;
    libbgp_err_t err = LIBBGP_OK;

    packet_parse_detail_set(detail, LIBBGP_OK, 0u, 0u);
    if (pkt == NULL || buf == NULL || len < LIBBGP_BGP_HEADER_LEN) {
        packet_parse_detail_set(detail, LIBBGP_ERR_BAD_LEN, 1u, 2u);
        return LIBBGP_ERR_BAD_LEN;
    }
    if (!packet_marker_valid(buf)) {
        packet_parse_detail_set(detail, LIBBGP_ERR_BAD_LEN, 1u, 1u);
        return LIBBGP_ERR_BAD_LEN;
    }
    wire_len = bgp_get_be16(buf + 16u);
    if (wire_len < LIBBGP_BGP_MIN_PACKET_LEN || wire_len > LIBBGP_BGP_MAX_PACKET_LEN ||
        len < (size_t)wire_len) {
        packet_parse_detail_set(detail, LIBBGP_ERR_BAD_LEN, 1u, 2u);
        return LIBBGP_ERR_BAD_LEN;
    }

    raw_type = buf[18];
    body = buf + LIBBGP_BGP_HEADER_LEN;
    body_len = (size_t)wire_len - LIBBGP_BGP_HEADER_LEN;
    libbgp_packet_init(&tmp);
    tmp.type = packet_type_from_raw(raw_type);
    tmp.raw_type = raw_type;
    if (detail != NULL && tmp.type == LIBBGP_PACKET_UNKNOWN) {
        packet_parse_detail_set(detail, LIBBGP_ERR_BAD_TYPE, 1u, 3u);
        return LIBBGP_ERR_BAD_TYPE;
    }

    switch (tmp.type) {
    case LIBBGP_PACKET_OPEN:
        libbgp_open_init(&tmp.data.open);
        err = libbgp_open_parse(&tmp.data.open, body, body_len, &used);
        break;
    case LIBBGP_PACKET_UPDATE:
        libbgp_update_init(&tmp.data.update);
        err = libbgp_update_parse_as4(&tmp.data.update, body, body_len, use_4b_asn, &used);
        break;
    case LIBBGP_PACKET_NOTIFICATION:
        libbgp_notification_init(&tmp.data.notification);
        err = libbgp_notification_parse(&tmp.data.notification, body, body_len, &used);
        break;
    case LIBBGP_PACKET_KEEPALIVE:
        err = libbgp_keepalive_parse(body, body_len, &used);
        break;
    case LIBBGP_PACKET_UNKNOWN:
    default:
        if (body_len != 0u) {
            tmp.raw_body = (uint8_t *)bgp_malloc(body_len);
            if (tmp.raw_body == NULL) {
                return LIBBGP_ERR_NOMEM;
            }
            memcpy(tmp.raw_body, body, body_len);
        }
        tmp.raw_body_len = body_len;
        used = body_len;
        break;
    }

    if (err != LIBBGP_OK) {
        packet_parse_map_body_error(detail, tmp.type, err);
        libbgp_packet_destroy(&tmp);
        return err;
    }
    if (used != body_len) {
        packet_parse_map_body_error(detail, tmp.type, LIBBGP_ERR_BAD_LEN);
        libbgp_packet_destroy(&tmp);
        return LIBBGP_ERR_BAD_LEN;
    }

    libbgp_packet_destroy(pkt);
    *pkt = tmp;
    if (consumed != NULL) {
        *consumed = wire_len;
    }
    return LIBBGP_OK;
}

libbgp_err_t libbgp_packet_parse_as4(
    libbgp_packet_t *pkt,
    const uint8_t *buf,
    size_t len,
    bool use_4b_asn,
    size_t *consumed)
{
    return bgp_packet_parse_as4_detail(pkt, buf, len, use_4b_asn, consumed, NULL);
}

libbgp_err_t libbgp_packet_parse(
    libbgp_packet_t *pkt,
    const uint8_t *buf,
    size_t len,
    size_t *consumed)
{
    return libbgp_packet_parse_as4(pkt, buf, len, false, consumed);
}

static libbgp_err_t packet_write_body(
    const libbgp_packet_t *pkt,
    uint8_t *body,
    size_t body_cap,
    uint8_t *raw_type,
    size_t *body_len)
{
    switch (pkt->type) {
    case LIBBGP_PACKET_OPEN:
        *raw_type = 1u;
        return libbgp_open_write(&pkt->data.open, body, body_cap, body_len);
    case LIBBGP_PACKET_UPDATE:
        *raw_type = 2u;
        return libbgp_update_write(&pkt->data.update, body, body_cap, body_len);
    case LIBBGP_PACKET_NOTIFICATION:
        *raw_type = 3u;
        return libbgp_notification_write(&pkt->data.notification, body, body_cap, body_len);
    case LIBBGP_PACKET_KEEPALIVE:
        *raw_type = 4u;
        return libbgp_keepalive_write(body, body_cap, body_len);
    case LIBBGP_PACKET_UNKNOWN:
        if (pkt->raw_body_len != 0u && pkt->raw_body == NULL) {
            return LIBBGP_ERR_BAD_LEN;
        }
        if (body_cap < pkt->raw_body_len) {
            return LIBBGP_ERR_BUFFER;
        }
        if (pkt->raw_body_len != 0u) {
            memcpy(body, pkt->raw_body, pkt->raw_body_len);
        }
        *raw_type = pkt->raw_type;
        *body_len = pkt->raw_body_len;
        return LIBBGP_OK;
    default:
        return LIBBGP_ERR_BAD_TYPE;
    }
}

libbgp_err_t libbgp_packet_write(
    const libbgp_packet_t *pkt,
    uint8_t *buf,
    size_t buf_len,
    size_t *out_len)
{
    uint8_t raw_type = 0u;
    size_t body_len = 0u;
    size_t max_body_len = LIBBGP_BGP_MAX_PACKET_LEN - LIBBGP_BGP_HEADER_LEN;
    size_t body_cap;
    size_t total_len;
    size_t i;
    libbgp_err_t err;

    if (pkt == NULL || buf == NULL) {
        return LIBBGP_ERR_BAD_LEN;
    }
    if (pkt->type == LIBBGP_PACKET_UNKNOWN) {
        if (pkt->raw_body_len != 0u && pkt->raw_body == NULL) {
            return LIBBGP_ERR_BAD_LEN;
        }
        if (pkt->raw_body_len > max_body_len) {
            return LIBBGP_ERR_BAD_LEN;
        }
        total_len = LIBBGP_BGP_HEADER_LEN + pkt->raw_body_len;
        if (buf_len < total_len) {
            return LIBBGP_ERR_BUFFER;
        }
    } else if (buf_len < LIBBGP_BGP_HEADER_LEN) {
        uint8_t scratch = 0u;

        err = packet_write_body(pkt, &scratch, 0u, &raw_type, &body_len);
        if (err != LIBBGP_OK) {
            return err;
        }
        return LIBBGP_ERR_BUFFER;
    }

    body_cap = buf_len - LIBBGP_BGP_HEADER_LEN;
    if (body_cap > max_body_len) {
        body_cap = max_body_len;
    }
    err = packet_write_body(
        pkt,
        buf + LIBBGP_BGP_HEADER_LEN,
        body_cap,
        &raw_type,
        &body_len);
    if (err != LIBBGP_OK) {
        return err;
    }
    if (body_len > max_body_len) {
        return LIBBGP_ERR_BAD_LEN;
    }
    total_len = LIBBGP_BGP_HEADER_LEN + body_len;
    if (buf_len < total_len) {
        return LIBBGP_ERR_BUFFER;
    }

    for (i = 0u; i < LIBBGP_BGP_MARKER_LEN; i++) {
        buf[i] = 0xffu;
    }
    bgp_put_be16(buf + 16u, (uint16_t)total_len);
    buf[18] = raw_type;
    if (out_len != NULL) {
        *out_len = total_len;
    }
    return LIBBGP_OK;
}
