#include "libbgp/capability.h"

#include <string.h>

#include "internal.h"

#define LIBBGP_CAP_CODE_MP_BGP 1u
#define LIBBGP_CAP_CODE_4B_ASN 65u
#define LIBBGP_CAP_KNOWN_VALUE_LEN 4u

static int capability_type_code(libbgp_cap_type_t type, uint8_t *code)
{
    switch (type) {
    case LIBBGP_CAP_4B_ASN:
        *code = LIBBGP_CAP_CODE_4B_ASN;
        return 1;
    case LIBBGP_CAP_MP_BGP:
        *code = LIBBGP_CAP_CODE_MP_BGP;
        return 1;
    case LIBBGP_CAP_UNKNOWN:
        *code = 0u;
        return 1;
    default:
        return 0;
    }
}

static void capability_free_unknown(libbgp_capability_t *cap)
{
    if (cap->type == LIBBGP_CAP_UNKNOWN && cap->data.unknown.value != NULL) {
        bgp_free(cap->data.unknown.value);
        cap->data.unknown.value = NULL;
        cap->data.unknown.len = 0u;
    }
}

libbgp_capability_t *libbgp_capability_new(libbgp_cap_type_t type)
{
    libbgp_capability_t *cap;
    uint8_t code;

    if (!capability_type_code(type, &code)) {
        return NULL;
    }

    cap = (libbgp_capability_t *)bgp_calloc(1u, sizeof(*cap));
    if (cap == NULL) {
        return NULL;
    }

    cap->refcount = 1u;
    cap->code = code;
    cap->type = type;
    return cap;
}

libbgp_capability_t *libbgp_capability_ref(libbgp_capability_t *cap)
{
    if (cap == NULL) {
        return NULL;
    }

    if (cap->refcount != UINT32_MAX) {
        cap->refcount++;
    }
    return cap;
}

void libbgp_capability_unref(libbgp_capability_t *cap)
{
    if (cap == NULL || cap->refcount == 0u) {
        return;
    }

    cap->refcount--;
    if (cap->refcount != 0u) {
        return;
    }

    capability_free_unknown(cap);
    bgp_free(cap);
}

libbgp_err_t libbgp_capability_parse(
    libbgp_capability_t *cap,
    const uint8_t *buf,
    size_t len,
    size_t *consumed)
{
    uint8_t code;
    uint8_t value_len;
    const uint8_t *value;

    if (cap == NULL || buf == NULL || len < 2u) {
        return LIBBGP_ERR_BAD_LEN;
    }

    code = buf[0];
    value_len = buf[1];
    if (len < 2u + (size_t)value_len) {
        return LIBBGP_ERR_BAD_LEN;
    }

    value = buf + 2u;
    if (code == LIBBGP_CAP_CODE_4B_ASN) {
        uint32_t asn;

        if (value_len != LIBBGP_CAP_KNOWN_VALUE_LEN) {
            return LIBBGP_ERR_BAD_LEN;
        }

        asn = bgp_get_be32(value);
        capability_free_unknown(cap);
        cap->code = code;
        cap->type = LIBBGP_CAP_4B_ASN;
        cap->data.asn_4b.asn = asn;
    } else if (code == LIBBGP_CAP_CODE_MP_BGP) {
        uint16_t afi;
        uint8_t safi;

        if (value_len != LIBBGP_CAP_KNOWN_VALUE_LEN) {
            return LIBBGP_ERR_BAD_LEN;
        }

        afi = bgp_get_be16(value);
        safi = value[3];
        capability_free_unknown(cap);
        cap->code = code;
        cap->type = LIBBGP_CAP_MP_BGP;
        cap->data.mp_bgp.afi = afi;
        cap->data.mp_bgp.safi = safi;
    } else {
        uint8_t *copy = NULL;

        if (value_len != 0u) {
            copy = (uint8_t *)bgp_malloc(value_len);
            if (copy == NULL) {
                return LIBBGP_ERR_NOMEM;
            }
            memcpy(copy, value, value_len);
        }

        capability_free_unknown(cap);
        cap->code = code;
        cap->type = LIBBGP_CAP_UNKNOWN;
        cap->data.unknown.value = copy;
        cap->data.unknown.len = value_len;
    }

    if (consumed != NULL) {
        *consumed = 2u + (size_t)value_len;
    }
    return LIBBGP_OK;
}

libbgp_err_t libbgp_capability_write(
    const libbgp_capability_t *cap,
    uint8_t *buf,
    size_t buf_len,
    size_t *out_len)
{
    size_t len;

    if (cap == NULL || buf == NULL) {
        return LIBBGP_ERR_BAD_LEN;
    }

    switch (cap->type) {
    case LIBBGP_CAP_4B_ASN:
        len = 2u + LIBBGP_CAP_KNOWN_VALUE_LEN;
        if (buf_len < len) {
            return LIBBGP_ERR_BUFFER;
        }
        buf[0] = LIBBGP_CAP_CODE_4B_ASN;
        buf[1] = LIBBGP_CAP_KNOWN_VALUE_LEN;
        bgp_put_be32(buf + 2u, cap->data.asn_4b.asn);
        break;
    case LIBBGP_CAP_MP_BGP:
        len = 2u + LIBBGP_CAP_KNOWN_VALUE_LEN;
        if (buf_len < len) {
            return LIBBGP_ERR_BUFFER;
        }
        buf[0] = LIBBGP_CAP_CODE_MP_BGP;
        buf[1] = LIBBGP_CAP_KNOWN_VALUE_LEN;
        bgp_put_be16(buf + 2u, cap->data.mp_bgp.afi);
        buf[4] = 0u;
        buf[5] = cap->data.mp_bgp.safi;
        break;
    case LIBBGP_CAP_UNKNOWN:
        if (cap->data.unknown.len > 255u ||
            (cap->data.unknown.len > 0u && cap->data.unknown.value == NULL)) {
            return LIBBGP_ERR_BAD_LEN;
        }
        len = 2u + cap->data.unknown.len;
        if (buf_len < len) {
            return LIBBGP_ERR_BUFFER;
        }
        buf[0] = cap->code;
        buf[1] = (uint8_t)cap->data.unknown.len;
        if (cap->data.unknown.len != 0u) {
            memcpy(buf + 2u, cap->data.unknown.value, cap->data.unknown.len);
        }
        break;
    default:
        return LIBBGP_ERR_BAD_LEN;
    }

    if (out_len != NULL) {
        *out_len = len;
    }
    return LIBBGP_OK;
}
