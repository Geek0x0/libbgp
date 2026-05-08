#include "libbgp/pattr.h"

#include <limits.h>
#include <string.h>

#include "internal.h"

static libbgp_pattr_type_t pattr_type_from_code(uint8_t code)
{
    switch (code) {
    case LIBBGP_PATTR_CODE_ORIGIN:
        return LIBBGP_PATTR_ORIGIN;
    case LIBBGP_PATTR_CODE_AS_PATH:
        return LIBBGP_PATTR_AS_PATH;
    case LIBBGP_PATTR_CODE_NEXT_HOP:
        return LIBBGP_PATTR_NEXT_HOP;
    case LIBBGP_PATTR_CODE_MED:
        return LIBBGP_PATTR_MED;
    case LIBBGP_PATTR_CODE_LOCAL_PREF:
        return LIBBGP_PATTR_LOCAL_PREF;
    case LIBBGP_PATTR_CODE_ATOMIC_AGGREGATE:
        return LIBBGP_PATTR_ATOMIC_AGGREGATE;
    case LIBBGP_PATTR_CODE_AGGREGATOR:
        return LIBBGP_PATTR_AGGREGATOR;
    case LIBBGP_PATTR_CODE_COMMUNITY:
        return LIBBGP_PATTR_COMMUNITY;
    case LIBBGP_PATTR_CODE_AS4_PATH:
        return LIBBGP_PATTR_AS4_PATH;
    case LIBBGP_PATTR_CODE_AS4_AGGREGATOR:
        return LIBBGP_PATTR_AS4_AGGREGATOR;
    case LIBBGP_PATTR_CODE_MP_REACH_NLRI:
        return LIBBGP_PATTR_MP_REACH_IPV6;
    case LIBBGP_PATTR_CODE_MP_UNREACH_NLRI:
        return LIBBGP_PATTR_MP_UNREACH_IPV6;
    default:
        return LIBBGP_PATTR_UNKNOWN;
    }
}

static void pattr_set_defaults(libbgp_pattr_t *attr, libbgp_pattr_type_t type)
{
    attr->type = type;
    switch (type) {
    case LIBBGP_PATTR_ORIGIN:
        attr->flags = LIBBGP_PATTR_FLAG_TRANSITIVE;
        attr->type_code = LIBBGP_PATTR_CODE_ORIGIN;
        break;
    case LIBBGP_PATTR_AS_PATH:
        attr->flags = LIBBGP_PATTR_FLAG_TRANSITIVE;
        attr->type_code = LIBBGP_PATTR_CODE_AS_PATH;
        attr->data.as_path.is_4b = false;
        break;
    case LIBBGP_PATTR_NEXT_HOP:
        attr->flags = LIBBGP_PATTR_FLAG_TRANSITIVE;
        attr->type_code = LIBBGP_PATTR_CODE_NEXT_HOP;
        break;
    case LIBBGP_PATTR_MED:
        attr->flags = LIBBGP_PATTR_FLAG_OPTIONAL;
        attr->type_code = LIBBGP_PATTR_CODE_MED;
        break;
    case LIBBGP_PATTR_LOCAL_PREF:
        attr->flags = LIBBGP_PATTR_FLAG_TRANSITIVE;
        attr->type_code = LIBBGP_PATTR_CODE_LOCAL_PREF;
        break;
    case LIBBGP_PATTR_ATOMIC_AGGREGATE:
        attr->flags = LIBBGP_PATTR_FLAG_TRANSITIVE;
        attr->type_code = LIBBGP_PATTR_CODE_ATOMIC_AGGREGATE;
        break;
    case LIBBGP_PATTR_AGGREGATOR:
        attr->flags = LIBBGP_PATTR_FLAG_OPTIONAL | LIBBGP_PATTR_FLAG_TRANSITIVE;
        attr->type_code = LIBBGP_PATTR_CODE_AGGREGATOR;
        attr->data.aggregator.is_4b = false;
        break;
    case LIBBGP_PATTR_COMMUNITY:
        attr->flags = LIBBGP_PATTR_FLAG_OPTIONAL | LIBBGP_PATTR_FLAG_TRANSITIVE;
        attr->type_code = LIBBGP_PATTR_CODE_COMMUNITY;
        break;
    case LIBBGP_PATTR_AS4_PATH:
        attr->flags = LIBBGP_PATTR_FLAG_OPTIONAL | LIBBGP_PATTR_FLAG_TRANSITIVE;
        attr->type_code = LIBBGP_PATTR_CODE_AS4_PATH;
        attr->data.as_path.is_4b = true;
        break;
    case LIBBGP_PATTR_AS4_AGGREGATOR:
        attr->flags = LIBBGP_PATTR_FLAG_OPTIONAL | LIBBGP_PATTR_FLAG_TRANSITIVE;
        attr->type_code = LIBBGP_PATTR_CODE_AS4_AGGREGATOR;
        attr->data.aggregator.is_4b = true;
        break;
    case LIBBGP_PATTR_MP_REACH_IPV6:
        attr->flags = LIBBGP_PATTR_FLAG_OPTIONAL;
        attr->type_code = LIBBGP_PATTR_CODE_MP_REACH_NLRI;
        break;
    case LIBBGP_PATTR_MP_UNREACH_IPV6:
        attr->flags = LIBBGP_PATTR_FLAG_OPTIONAL;
        attr->type_code = LIBBGP_PATTR_CODE_MP_UNREACH_NLRI;
        break;
    case LIBBGP_PATTR_UNKNOWN:
        attr->flags = 0u;
        attr->type_code = 0u;
        break;
    }
}

static void pattr_free_data(libbgp_pattr_t *attr)
{
    size_t i;

    if (attr == NULL) {
        return;
    }

    switch (attr->type) {
    case LIBBGP_PATTR_AS_PATH:
    case LIBBGP_PATTR_AS4_PATH:
        if (attr->data.as_path.segments != NULL) {
            for (i = 0u; i < attr->data.as_path.segment_count; i++) {
                bgp_free(attr->data.as_path.segments[i].asns);
            }
        }
        bgp_free(attr->data.as_path.segments);
        break;
    case LIBBGP_PATTR_COMMUNITY:
        bgp_free(attr->data.community.values);
        break;
    case LIBBGP_PATTR_MP_REACH_IPV6:
        bgp_free(attr->data.mp_reach_ipv6.nlri);
        break;
    case LIBBGP_PATTR_MP_UNREACH_IPV6:
        bgp_free(attr->data.mp_unreach_ipv6.withdrawn);
        break;
    case LIBBGP_PATTR_UNKNOWN:
        bgp_free(attr->data.unknown.value);
        break;
    default:
        break;
    }

    memset(&attr->data, 0, sizeof(attr->data));
}

libbgp_pattr_t *libbgp_pattr_new(libbgp_pattr_type_t type)
{
    libbgp_pattr_t *attr;

    if (type < LIBBGP_PATTR_ORIGIN || type > LIBBGP_PATTR_UNKNOWN) {
        return NULL;
    }

    attr = (libbgp_pattr_t *)bgp_calloc(1u, sizeof(*attr));
    if (attr == NULL) {
        return NULL;
    }

    attr->refcount = 1u;
    pattr_set_defaults(attr, type);
    return attr;
}

libbgp_pattr_t *libbgp_pattr_ref(libbgp_pattr_t *attr)
{
    if (attr == NULL) {
        return NULL;
    }
    if (attr->refcount < UINT32_MAX) {
        attr->refcount++;
    }
    return attr;
}

void libbgp_pattr_unref(libbgp_pattr_t *attr)
{
    if (attr == NULL || attr->refcount == 0u) {
        return;
    }
    attr->refcount--;
    if (attr->refcount != 0u) {
        return;
    }
    pattr_free_data(attr);
    bgp_free(attr);
}

libbgp_pattr_type_t libbgp_pattr_type_from_buf(const uint8_t *buf, size_t len)
{
    if (buf == NULL || len < 3u) {
        return LIBBGP_PATTR_UNKNOWN;
    }
    if ((buf[0] & LIBBGP_PATTR_FLAG_EXTENDED_LENGTH) != 0u && len < 4u) {
        return LIBBGP_PATTR_UNKNOWN;
    }
    return pattr_type_from_code(buf[1]);
}

const char *libbgp_pattr_type_name(libbgp_pattr_type_t type)
{
    switch (type) {
    case LIBBGP_PATTR_ORIGIN:
        return "ORIGIN";
    case LIBBGP_PATTR_AS_PATH:
        return "AS_PATH";
    case LIBBGP_PATTR_NEXT_HOP:
        return "NEXT_HOP";
    case LIBBGP_PATTR_MED:
        return "MED";
    case LIBBGP_PATTR_LOCAL_PREF:
        return "LOCAL_PREF";
    case LIBBGP_PATTR_ATOMIC_AGGREGATE:
        return "ATOMIC_AGGREGATE";
    case LIBBGP_PATTR_AGGREGATOR:
        return "AGGREGATOR";
    case LIBBGP_PATTR_COMMUNITY:
        return "COMMUNITY";
    case LIBBGP_PATTR_AS4_PATH:
        return "AS4_PATH";
    case LIBBGP_PATTR_AS4_AGGREGATOR:
        return "AS4_AGGREGATOR";
    case LIBBGP_PATTR_MP_REACH_IPV6:
        return "MP_REACH_IPV6";
    case LIBBGP_PATTR_MP_UNREACH_IPV6:
        return "MP_UNREACH_IPV6";
    case LIBBGP_PATTR_UNKNOWN:
    default:
        return "UNKNOWN";
    }
}

static libbgp_err_t parse_unknown(
    libbgp_pattr_t *tmp,
    const uint8_t *value,
    size_t value_len)
{
    tmp->type = LIBBGP_PATTR_UNKNOWN;
    tmp->data.unknown.len = value_len;
    if (value_len == 0u) {
        tmp->data.unknown.value = NULL;
        return LIBBGP_OK;
    }
    tmp->data.unknown.value = (uint8_t *)bgp_malloc(value_len);
    if (tmp->data.unknown.value == NULL) {
        return LIBBGP_ERR_NOMEM;
    }
    memcpy(tmp->data.unknown.value, value, value_len);
    return LIBBGP_OK;
}

static libbgp_err_t parse_as_path(
    libbgp_pattr_t *tmp,
    const uint8_t *value,
    size_t value_len,
    bool is_4b)
{
    size_t pos = 0u;
    size_t segment_count = 0u;
    size_t asn_size = is_4b ? 4u : 2u;
    size_t i;

    while (pos < value_len) {
        size_t count;
        size_t bytes;

        if (value_len - pos < 2u) {
            return LIBBGP_ERR_BAD_LEN;
        }
        if (value[pos] < 1u || value[pos] > 2u) {
            return LIBBGP_ERR_INVALID;
        }
        count = value[pos + 1u];
        if (count > (SIZE_MAX - 2u) / asn_size) {
            return LIBBGP_ERR_BAD_LEN;
        }
        bytes = 2u + count * asn_size;
        if (value_len - pos < bytes) {
            return LIBBGP_ERR_BAD_LEN;
        }
        segment_count++;
        pos += bytes;
    }

    tmp->data.as_path.is_4b = is_4b;
    tmp->data.as_path.segment_count = segment_count;
    if (segment_count == 0u) {
        return LIBBGP_OK;
    }

    tmp->data.as_path.segments = (libbgp_as_path_segment_t *)bgp_calloc(
        segment_count, sizeof(tmp->data.as_path.segments[0]));
    if (tmp->data.as_path.segments == NULL) {
        return LIBBGP_ERR_NOMEM;
    }

    pos = 0u;
    for (i = 0u; i < segment_count; i++) {
        size_t j;
        size_t count = value[pos + 1u];

        tmp->data.as_path.segments[i].type = value[pos];
        tmp->data.as_path.segments[i].asn_count = count;
        pos += 2u;
        if (count != 0u) {
            tmp->data.as_path.segments[i].asns = (uint32_t *)bgp_malloc(
                count * sizeof(tmp->data.as_path.segments[i].asns[0]));
            if (tmp->data.as_path.segments[i].asns == NULL) {
                return LIBBGP_ERR_NOMEM;
            }
        }
        for (j = 0u; j < count; j++) {
            if (is_4b) {
                tmp->data.as_path.segments[i].asns[j] = bgp_get_be32(value + pos);
            } else {
                tmp->data.as_path.segments[i].asns[j] = bgp_get_be16(value + pos);
            }
            pos += asn_size;
        }
    }

    return LIBBGP_OK;
}

static libbgp_err_t parse_community(
    libbgp_pattr_t *tmp,
    const uint8_t *value,
    size_t value_len)
{
    size_t count;
    size_t i;

    if ((value_len % 4u) != 0u) {
        return LIBBGP_ERR_BAD_LEN;
    }
    count = value_len / 4u;
    tmp->data.community.count = count;
    if (count == 0u) {
        return LIBBGP_OK;
    }
    tmp->data.community.values = (uint32_t *)bgp_malloc(
        count * sizeof(tmp->data.community.values[0]));
    if (tmp->data.community.values == NULL) {
        return LIBBGP_ERR_NOMEM;
    }
    for (i = 0u; i < count; i++) {
        tmp->data.community.values[i] = bgp_get_be32(value + i * 4u);
    }
    return LIBBGP_OK;
}

static libbgp_err_t parse_mp_unreach_ipv6(
    libbgp_pattr_t *tmp,
    const uint8_t *value,
    size_t value_len)
{
    size_t pos;
    size_t count = 0u;
    libbgp_prefix6_t p;
    size_t consumed;
    size_t i;

    if (value_len < 3u) {
        return LIBBGP_ERR_BAD_LEN;
    }
    if (bgp_get_be16(value) != LIBBGP_AFI_IPV6 || value[2] != LIBBGP_SAFI_UNICAST) {
        return parse_unknown(tmp, value, value_len);
    }

    pos = 3u;
    while (pos < value_len) {
        libbgp_err_t err = libbgp_prefix6_parse(&p, value + pos, value_len - pos, &consumed);
        if (err != LIBBGP_OK) {
            return err;
        }
        count++;
        pos += consumed;
    }

    tmp->data.mp_unreach_ipv6.withdrawn_count = count;
    if (count == 0u) {
        return LIBBGP_OK;
    }
    tmp->data.mp_unreach_ipv6.withdrawn = (libbgp_prefix6_t *)bgp_calloc(
        count, sizeof(tmp->data.mp_unreach_ipv6.withdrawn[0]));
    if (tmp->data.mp_unreach_ipv6.withdrawn == NULL) {
        return LIBBGP_ERR_NOMEM;
    }
    pos = 3u;
    for (i = 0u; i < count; i++) {
        libbgp_err_t err = libbgp_prefix6_parse(
            &tmp->data.mp_unreach_ipv6.withdrawn[i],
            value + pos,
            value_len - pos,
            &consumed);
        if (err != LIBBGP_OK) {
            return err;
        }
        pos += consumed;
    }
    return LIBBGP_OK;
}

static libbgp_err_t parse_mp_reach_ipv6(
    libbgp_pattr_t *tmp,
    const uint8_t *value,
    size_t value_len)
{
    size_t pos;
    size_t count = 0u;
    libbgp_prefix6_t p;
    size_t consumed;
    size_t i;

    if (value_len < 5u) {
        return LIBBGP_ERR_BAD_LEN;
    }
    if (bgp_get_be16(value) != LIBBGP_AFI_IPV6 || value[2] != LIBBGP_SAFI_UNICAST) {
        return parse_unknown(tmp, value, value_len);
    }
    if (value[3] != 16u && value[3] != 32u) {
        return LIBBGP_ERR_INVALID;
    }
    if (value_len < 5u + (size_t)value[3]) {
        return LIBBGP_ERR_BAD_LEN;
    }

    tmp->data.mp_reach_ipv6.nexthop_len = value[3];
    memcpy(tmp->data.mp_reach_ipv6.nexthop, value + 4u, value[3]);
    pos = 4u + (size_t)value[3];
    if (value[pos] != 0u) {
        return LIBBGP_ERR_INVALID;
    }
    pos++;

    while (pos < value_len) {
        libbgp_err_t err = libbgp_prefix6_parse(&p, value + pos, value_len - pos, &consumed);
        if (err != LIBBGP_OK) {
            return err;
        }
        count++;
        pos += consumed;
    }

    tmp->data.mp_reach_ipv6.nlri_count = count;
    if (count == 0u) {
        return LIBBGP_OK;
    }
    tmp->data.mp_reach_ipv6.nlri = (libbgp_prefix6_t *)bgp_calloc(
        count, sizeof(tmp->data.mp_reach_ipv6.nlri[0]));
    if (tmp->data.mp_reach_ipv6.nlri == NULL) {
        return LIBBGP_ERR_NOMEM;
    }
    pos = 5u + (size_t)value[3];
    for (i = 0u; i < count; i++) {
        libbgp_err_t err = libbgp_prefix6_parse(
            &tmp->data.mp_reach_ipv6.nlri[i],
            value + pos,
            value_len - pos,
            &consumed);
        if (err != LIBBGP_OK) {
            return err;
        }
        pos += consumed;
    }
    return LIBBGP_OK;
}

libbgp_err_t libbgp_pattr_parse(
    libbgp_pattr_t *attr,
    const uint8_t *buf,
    size_t len,
    size_t *consumed)
{
    libbgp_pattr_t tmp;
    uint8_t flags;
    uint8_t code;
    size_t header_len;
    size_t value_len;
    const uint8_t *value;
    libbgp_err_t err = LIBBGP_OK;

    if (attr == NULL || buf == NULL || len < 3u) {
        return LIBBGP_ERR_BAD_LEN;
    }

    flags = buf[0];
    code = buf[1];
    if ((flags & LIBBGP_PATTR_FLAG_EXTENDED_LENGTH) != 0u) {
        if (len < 4u) {
            return LIBBGP_ERR_BAD_LEN;
        }
        header_len = 4u;
        value_len = bgp_get_be16(buf + 2u);
    } else {
        header_len = 3u;
        value_len = buf[2];
    }
    if (len - header_len < value_len) {
        return LIBBGP_ERR_BAD_LEN;
    }

    memset(&tmp, 0, sizeof(tmp));
    tmp.flags = flags;
    tmp.type_code = code;
    tmp.type = pattr_type_from_code(code);
    value = buf + header_len;

    switch (tmp.type) {
    case LIBBGP_PATTR_ORIGIN:
        if (value_len != 1u) {
            err = LIBBGP_ERR_BAD_LEN;
        } else if (value[0] > 2u) {
            err = LIBBGP_ERR_INVALID;
        } else {
            tmp.data.origin.origin = value[0];
        }
        break;
    case LIBBGP_PATTR_AS_PATH:
        err = parse_as_path(&tmp, value, value_len, false);
        break;
    case LIBBGP_PATTR_NEXT_HOP:
        if (value_len != 4u) {
            err = LIBBGP_ERR_BAD_LEN;
        } else {
            tmp.data.next_hop.next_hop = bgp_get_be32(value);
        }
        break;
    case LIBBGP_PATTR_MED:
        if (value_len != 4u) {
            err = LIBBGP_ERR_BAD_LEN;
        } else {
            tmp.data.med.value = bgp_get_be32(value);
        }
        break;
    case LIBBGP_PATTR_LOCAL_PREF:
        if (value_len != 4u) {
            err = LIBBGP_ERR_BAD_LEN;
        } else {
            tmp.data.local_pref.value = bgp_get_be32(value);
        }
        break;
    case LIBBGP_PATTR_ATOMIC_AGGREGATE:
        if (value_len != 0u) {
            err = LIBBGP_ERR_BAD_LEN;
        }
        break;
    case LIBBGP_PATTR_AGGREGATOR:
        if (value_len != 6u) {
            err = LIBBGP_ERR_BAD_LEN;
        } else {
            tmp.data.aggregator.asn = bgp_get_be16(value);
            tmp.data.aggregator.router_id = bgp_get_be32(value + 2u);
            tmp.data.aggregator.is_4b = false;
        }
        break;
    case LIBBGP_PATTR_COMMUNITY:
        err = parse_community(&tmp, value, value_len);
        break;
    case LIBBGP_PATTR_AS4_PATH:
        err = parse_as_path(&tmp, value, value_len, true);
        break;
    case LIBBGP_PATTR_AS4_AGGREGATOR:
        if (value_len != 8u) {
            err = LIBBGP_ERR_BAD_LEN;
        } else {
            tmp.data.aggregator.asn = bgp_get_be32(value);
            tmp.data.aggregator.router_id = bgp_get_be32(value + 4u);
            tmp.data.aggregator.is_4b = true;
        }
        break;
    case LIBBGP_PATTR_MP_REACH_IPV6:
        err = parse_mp_reach_ipv6(&tmp, value, value_len);
        break;
    case LIBBGP_PATTR_MP_UNREACH_IPV6:
        err = parse_mp_unreach_ipv6(&tmp, value, value_len);
        break;
    case LIBBGP_PATTR_UNKNOWN:
        err = parse_unknown(&tmp, value, value_len);
        break;
    }

    if (err != LIBBGP_OK) {
        pattr_free_data(&tmp);
        return err;
    }

    pattr_free_data(attr);
    attr->flags = tmp.flags;
    attr->type_code = tmp.type_code;
    attr->type = tmp.type;
    attr->data = tmp.data;
    if (consumed != NULL) {
        *consumed = header_len + value_len;
    }

    return LIBBGP_OK;
}

static libbgp_err_t add_size(size_t *acc, size_t add)
{
    if (*acc > SIZE_MAX - add) {
        return LIBBGP_ERR_BAD_LEN;
    }
    *acc += add;
    return LIBBGP_OK;
}

static libbgp_err_t pattr_value_len(const libbgp_pattr_t *attr, size_t *value_len)
{
    size_t len = 0u;
    size_t i;

    switch (attr->type) {
    case LIBBGP_PATTR_ORIGIN:
        len = 1u;
        break;
    case LIBBGP_PATTR_AS_PATH:
    case LIBBGP_PATTR_AS4_PATH:
        if (attr->data.as_path.segment_count != 0u &&
            attr->data.as_path.segments == NULL) {
            return LIBBGP_ERR_BAD_LEN;
        }
        for (i = 0u; i < attr->data.as_path.segment_count; i++) {
            size_t asn_size = attr->data.as_path.is_4b ? 4u : 2u;
            size_t count = attr->data.as_path.segments[i].asn_count;

            if (attr->data.as_path.segments[i].type < 1u ||
                attr->data.as_path.segments[i].type > 2u ||
                count > 255u ||
                (count != 0u && attr->data.as_path.segments[i].asns == NULL)) {
                return LIBBGP_ERR_BAD_LEN;
            }
            if (count > (SIZE_MAX - 2u) / asn_size ||
                add_size(&len, 2u + count * asn_size) != LIBBGP_OK) {
                return LIBBGP_ERR_BAD_LEN;
            }
        }
        break;
    case LIBBGP_PATTR_NEXT_HOP:
    case LIBBGP_PATTR_MED:
    case LIBBGP_PATTR_LOCAL_PREF:
        len = 4u;
        break;
    case LIBBGP_PATTR_ATOMIC_AGGREGATE:
        len = 0u;
        break;
    case LIBBGP_PATTR_AGGREGATOR:
        len = 6u;
        if (attr->data.aggregator.asn > 65535u) {
            return LIBBGP_ERR_INVALID;
        }
        break;
    case LIBBGP_PATTR_COMMUNITY:
        if (attr->data.community.count != 0u && attr->data.community.values == NULL) {
            return LIBBGP_ERR_BAD_LEN;
        }
        if (attr->data.community.count > SIZE_MAX / 4u) {
            return LIBBGP_ERR_BAD_LEN;
        }
        len = attr->data.community.count * 4u;
        break;
    case LIBBGP_PATTR_AS4_AGGREGATOR:
        len = 8u;
        break;
    case LIBBGP_PATTR_MP_REACH_IPV6:
        if (attr->data.mp_reach_ipv6.nexthop_len != 16u &&
            attr->data.mp_reach_ipv6.nexthop_len != 32u) {
            return LIBBGP_ERR_BAD_LEN;
        }
        if (attr->data.mp_reach_ipv6.nlri_count != 0u &&
            attr->data.mp_reach_ipv6.nlri == NULL) {
            return LIBBGP_ERR_BAD_LEN;
        }
        len = 5u + attr->data.mp_reach_ipv6.nexthop_len;
        for (i = 0u; i < attr->data.mp_reach_ipv6.nlri_count; i++) {
            size_t prefix_len = 1u + ((size_t)attr->data.mp_reach_ipv6.nlri[i].len + 7u) / 8u;
            if (attr->data.mp_reach_ipv6.nlri[i].len > 128u ||
                add_size(&len, prefix_len) != LIBBGP_OK) {
                return LIBBGP_ERR_BAD_LEN;
            }
        }
        break;
    case LIBBGP_PATTR_MP_UNREACH_IPV6:
        if (attr->data.mp_unreach_ipv6.withdrawn_count != 0u &&
            attr->data.mp_unreach_ipv6.withdrawn == NULL) {
            return LIBBGP_ERR_BAD_LEN;
        }
        len = 3u;
        for (i = 0u; i < attr->data.mp_unreach_ipv6.withdrawn_count; i++) {
            size_t prefix_len = 1u + ((size_t)attr->data.mp_unreach_ipv6.withdrawn[i].len + 7u) / 8u;
            if (attr->data.mp_unreach_ipv6.withdrawn[i].len > 128u ||
                add_size(&len, prefix_len) != LIBBGP_OK) {
                return LIBBGP_ERR_BAD_LEN;
            }
        }
        break;
    case LIBBGP_PATTR_UNKNOWN:
        if (attr->data.unknown.len > 65535u ||
            (attr->data.unknown.len != 0u && attr->data.unknown.value == NULL)) {
            return LIBBGP_ERR_BAD_LEN;
        }
        len = attr->data.unknown.len;
        break;
    default:
        return LIBBGP_ERR_BAD_LEN;
    }

    if (len > 65535u) {
        return LIBBGP_ERR_BAD_LEN;
    }
    *value_len = len;
    return LIBBGP_OK;
}

static void write_header(const libbgp_pattr_t *attr, uint8_t *buf, size_t value_len, bool extended)
{
    uint8_t flags = (uint8_t)(attr->flags & (uint8_t)~LIBBGP_PATTR_FLAG_EXTENDED_LENGTH);

    if (extended) {
        flags = (uint8_t)(flags | LIBBGP_PATTR_FLAG_EXTENDED_LENGTH);
    }
    buf[0] = flags;
    buf[1] = attr->type_code;
    if (extended) {
        bgp_put_be16(buf + 2u, (uint16_t)value_len);
    } else {
        buf[2] = (uint8_t)value_len;
    }
}

static void write_as_path_value(const libbgp_pattr_t *attr, uint8_t *buf)
{
    size_t pos = 0u;
    size_t i;

    for (i = 0u; i < attr->data.as_path.segment_count; i++) {
        size_t j;

        buf[pos] = attr->data.as_path.segments[i].type;
        buf[pos + 1u] = (uint8_t)attr->data.as_path.segments[i].asn_count;
        pos += 2u;
        for (j = 0u; j < attr->data.as_path.segments[i].asn_count; j++) {
            if (attr->data.as_path.is_4b) {
                bgp_put_be32(buf + pos, attr->data.as_path.segments[i].asns[j]);
                pos += 4u;
            } else {
                bgp_put_be16(buf + pos, (uint16_t)attr->data.as_path.segments[i].asns[j]);
                pos += 2u;
            }
        }
    }
}

static libbgp_err_t write_value(const libbgp_pattr_t *attr, uint8_t *buf, size_t value_len)
{
    size_t i;
    size_t pos;
    BGP_UNUSED(value_len);

    switch (attr->type) {
    case LIBBGP_PATTR_ORIGIN:
        if (attr->data.origin.origin > 2u) {
            return LIBBGP_ERR_INVALID;
        }
        buf[0] = attr->data.origin.origin;
        break;
    case LIBBGP_PATTR_AS_PATH:
    case LIBBGP_PATTR_AS4_PATH:
        for (i = 0u; i < attr->data.as_path.segment_count; i++) {
            size_t j;
            if (!attr->data.as_path.is_4b) {
                for (j = 0u; j < attr->data.as_path.segments[i].asn_count; j++) {
                    if (attr->data.as_path.segments[i].asns[j] > 65535u) {
                        return LIBBGP_ERR_INVALID;
                    }
                }
            }
        }
        write_as_path_value(attr, buf);
        break;
    case LIBBGP_PATTR_NEXT_HOP:
        bgp_put_be32(buf, attr->data.next_hop.next_hop);
        break;
    case LIBBGP_PATTR_MED:
        bgp_put_be32(buf, attr->data.med.value);
        break;
    case LIBBGP_PATTR_LOCAL_PREF:
        bgp_put_be32(buf, attr->data.local_pref.value);
        break;
    case LIBBGP_PATTR_ATOMIC_AGGREGATE:
        break;
    case LIBBGP_PATTR_AGGREGATOR:
        bgp_put_be16(buf, (uint16_t)attr->data.aggregator.asn);
        bgp_put_be32(buf + 2u, attr->data.aggregator.router_id);
        break;
    case LIBBGP_PATTR_COMMUNITY:
        for (i = 0u; i < attr->data.community.count; i++) {
            bgp_put_be32(buf + i * 4u, attr->data.community.values[i]);
        }
        break;
    case LIBBGP_PATTR_AS4_AGGREGATOR:
        bgp_put_be32(buf, attr->data.aggregator.asn);
        bgp_put_be32(buf + 4u, attr->data.aggregator.router_id);
        break;
    case LIBBGP_PATTR_MP_REACH_IPV6:
        bgp_put_be16(buf, LIBBGP_AFI_IPV6);
        buf[2] = LIBBGP_SAFI_UNICAST;
        buf[3] = (uint8_t)attr->data.mp_reach_ipv6.nexthop_len;
        memcpy(buf + 4u, attr->data.mp_reach_ipv6.nexthop, attr->data.mp_reach_ipv6.nexthop_len);
        pos = 4u + attr->data.mp_reach_ipv6.nexthop_len;
        buf[pos] = 0u;
        pos++;
        for (i = 0u; i < attr->data.mp_reach_ipv6.nlri_count; i++) {
            size_t wrote = 0u;
            libbgp_err_t err = libbgp_prefix6_write(
                &attr->data.mp_reach_ipv6.nlri[i],
                buf + pos,
                value_len - pos,
                &wrote);
            if (err != LIBBGP_OK) {
                return err;
            }
            pos += wrote;
        }
        break;
    case LIBBGP_PATTR_MP_UNREACH_IPV6:
        bgp_put_be16(buf, LIBBGP_AFI_IPV6);
        buf[2] = LIBBGP_SAFI_UNICAST;
        pos = 3u;
        for (i = 0u; i < attr->data.mp_unreach_ipv6.withdrawn_count; i++) {
            size_t wrote = 0u;
            libbgp_err_t err = libbgp_prefix6_write(
                &attr->data.mp_unreach_ipv6.withdrawn[i],
                buf + pos,
                value_len - pos,
                &wrote);
            if (err != LIBBGP_OK) {
                return err;
            }
            pos += wrote;
        }
        break;
    case LIBBGP_PATTR_UNKNOWN:
        if (attr->data.unknown.len != 0u) {
            memcpy(buf, attr->data.unknown.value, attr->data.unknown.len);
        }
        break;
    default:
        return LIBBGP_ERR_BAD_LEN;
    }

    return LIBBGP_OK;
}

libbgp_err_t libbgp_pattr_write(
    const libbgp_pattr_t *attr,
    uint8_t *buf,
    size_t buf_len,
    size_t *out_len)
{
    size_t value_len;
    size_t header_len;
    bool extended;
    libbgp_err_t err;

    if (attr == NULL || buf == NULL) {
        return LIBBGP_ERR_BAD_LEN;
    }

    err = pattr_value_len(attr, &value_len);
    if (err != LIBBGP_OK) {
        return err;
    }

    extended = value_len > 255u ||
        (attr->flags & LIBBGP_PATTR_FLAG_EXTENDED_LENGTH) != 0u;
    header_len = extended ? 4u : 3u;
    if (buf_len < header_len + value_len) {
        return LIBBGP_ERR_BUFFER;
    }

    err = write_value(attr, buf + header_len, value_len);
    if (err != LIBBGP_OK) {
        return err;
    }
    write_header(attr, buf, value_len, extended);
    if (out_len != NULL) {
        *out_len = header_len + value_len;
    }

    return LIBBGP_OK;
}
