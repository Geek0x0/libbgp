#include "libbgp/pattr.h"

#include <limits.h>
#include <stdarg.h>
#include <stdio.h>
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

static uint8_t pattr_default_flags(libbgp_pattr_type_t type)
{
    switch (type) {
    case LIBBGP_PATTR_ORIGIN:
    case LIBBGP_PATTR_AS_PATH:
    case LIBBGP_PATTR_NEXT_HOP:
    case LIBBGP_PATTR_LOCAL_PREF:
    case LIBBGP_PATTR_ATOMIC_AGGREGATE:
        return LIBBGP_PATTR_FLAG_TRANSITIVE;
    case LIBBGP_PATTR_MED:
    case LIBBGP_PATTR_MP_REACH_IPV6:
    case LIBBGP_PATTR_MP_UNREACH_IPV6:
        return LIBBGP_PATTR_FLAG_OPTIONAL;
    case LIBBGP_PATTR_AGGREGATOR:
    case LIBBGP_PATTR_COMMUNITY:
    case LIBBGP_PATTR_AS4_PATH:
    case LIBBGP_PATTR_AS4_AGGREGATOR:
        return LIBBGP_PATTR_FLAG_OPTIONAL | LIBBGP_PATTR_FLAG_TRANSITIVE;
    case LIBBGP_PATTR_UNKNOWN:
    default:
        return 0u;
    }
}

static uint8_t pattr_default_type_code(libbgp_pattr_type_t type)
{
    switch (type) {
    case LIBBGP_PATTR_ORIGIN:
        return LIBBGP_PATTR_CODE_ORIGIN;
    case LIBBGP_PATTR_AS_PATH:
        return LIBBGP_PATTR_CODE_AS_PATH;
    case LIBBGP_PATTR_NEXT_HOP:
        return LIBBGP_PATTR_CODE_NEXT_HOP;
    case LIBBGP_PATTR_MED:
        return LIBBGP_PATTR_CODE_MED;
    case LIBBGP_PATTR_LOCAL_PREF:
        return LIBBGP_PATTR_CODE_LOCAL_PREF;
    case LIBBGP_PATTR_ATOMIC_AGGREGATE:
        return LIBBGP_PATTR_CODE_ATOMIC_AGGREGATE;
    case LIBBGP_PATTR_AGGREGATOR:
        return LIBBGP_PATTR_CODE_AGGREGATOR;
    case LIBBGP_PATTR_COMMUNITY:
        return LIBBGP_PATTR_CODE_COMMUNITY;
    case LIBBGP_PATTR_AS4_PATH:
        return LIBBGP_PATTR_CODE_AS4_PATH;
    case LIBBGP_PATTR_AS4_AGGREGATOR:
        return LIBBGP_PATTR_CODE_AS4_AGGREGATOR;
    case LIBBGP_PATTR_MP_REACH_IPV6:
        return LIBBGP_PATTR_CODE_MP_REACH_NLRI;
    case LIBBGP_PATTR_MP_UNREACH_IPV6:
        return LIBBGP_PATTR_CODE_MP_UNREACH_NLRI;
    case LIBBGP_PATTR_UNKNOWN:
    default:
        return 0u;
    }
}

static bool pattr_known_flags_valid(libbgp_pattr_type_t type, uint8_t flags)
{
    uint8_t allowed = LIBBGP_PATTR_FLAG_OPTIONAL |
        LIBBGP_PATTR_FLAG_TRANSITIVE |
        LIBBGP_PATTR_FLAG_PARTIAL |
        LIBBGP_PATTR_FLAG_EXTENDED_LENGTH;
    uint8_t base = (uint8_t)(flags &
        (uint8_t)~(LIBBGP_PATTR_FLAG_EXTENDED_LENGTH | LIBBGP_PATTR_FLAG_PARTIAL));
    uint8_t defaults;

    if ((flags & (uint8_t)~allowed) != 0u) {
        return false;
    }
    if (type == LIBBGP_PATTR_UNKNOWN) {
        if ((flags & LIBBGP_PATTR_FLAG_OPTIONAL) == 0u) {
            return false;
        }
        if ((flags & LIBBGP_PATTR_FLAG_PARTIAL) != 0u &&
            (flags & LIBBGP_PATTR_FLAG_TRANSITIVE) == 0u) {
            return false;
        }
        return true;
    }
    defaults = pattr_default_flags(type);
    if (base != defaults) {
        return false;
    }
    if ((flags & LIBBGP_PATTR_FLAG_PARTIAL) != 0u &&
        (defaults & (LIBBGP_PATTR_FLAG_OPTIONAL | LIBBGP_PATTR_FLAG_TRANSITIVE)) !=
            (LIBBGP_PATTR_FLAG_OPTIONAL | LIBBGP_PATTR_FLAG_TRANSITIVE)) {
        return false;
    }
    return true;
}

typedef struct pattr_as_path_block {
    struct pattr_as_path_block *prev;
    struct pattr_as_path_block *next;
    libbgp_as_path_segment_t *segments;
} pattr_as_path_block_t;

#ifdef BGP_THREADSAFE
static bgp_lock_t pattr_as_path_block_lock = PTHREAD_MUTEX_INITIALIZER;
#else
static bgp_lock_t pattr_as_path_block_lock;
#endif
static pattr_as_path_block_t *pattr_as_path_blocks;

static bool pattr_align_offset(size_t offset, size_t align, size_t *aligned)
{
    size_t rem;

    if (align == 0u) {
        return false;
    }
    rem = offset % align;
    if (rem != 0u) {
        size_t padding = align - rem;

        if (offset > SIZE_MAX - padding) {
            return false;
        }
        offset += padding;
    }
    *aligned = offset;
    return true;
}

static bool pattr_as_path_block_layout(
    size_t segment_count,
    size_t asn_count,
    size_t *segments_offset,
    size_t *asn_offset,
    size_t *block_size)
{
    size_t seg_bytes;
    size_t asn_bytes;
    size_t offset;

    if (segment_count > SIZE_MAX / sizeof(libbgp_as_path_segment_t) ||
        asn_count > SIZE_MAX / sizeof(uint32_t)) {
        return false;
    }
    seg_bytes = segment_count * sizeof(libbgp_as_path_segment_t);
    asn_bytes = asn_count * sizeof(uint32_t);
    if (!pattr_align_offset(
            sizeof(pattr_as_path_block_t),
            _Alignof(libbgp_as_path_segment_t),
            &offset)) {
        return false;
    }
    if (segments_offset != NULL) {
        *segments_offset = offset;
    }
    if (offset > SIZE_MAX - seg_bytes) {
        return false;
    }
    offset += seg_bytes;
    if (!pattr_align_offset(offset, _Alignof(uint32_t), &offset)) {
        return false;
    }
    if (offset > SIZE_MAX - asn_bytes) {
        return false;
    }
    if (asn_offset != NULL) {
        *asn_offset = offset;
    }
    if (block_size != NULL) {
        *block_size = offset + asn_bytes;
    }
    return true;
}

static void pattr_as_path_block_register(
    pattr_as_path_block_t *block,
    libbgp_as_path_segment_t *segments)
{
    block->segments = segments;

    bgp_lock(&pattr_as_path_block_lock);
    block->prev = NULL;
    block->next = pattr_as_path_blocks;
    if (pattr_as_path_blocks != NULL) {
        pattr_as_path_blocks->prev = block;
    }
    pattr_as_path_blocks = block;
    bgp_unlock(&pattr_as_path_block_lock);
}

static pattr_as_path_block_t *pattr_as_path_block_take(libbgp_as_path_segment_t *segments)
{
    pattr_as_path_block_t *block;

    bgp_lock(&pattr_as_path_block_lock);
    for (block = pattr_as_path_blocks; block != NULL; block = block->next) {
        if (block->segments == segments) {
            if (block->prev != NULL) {
                block->prev->next = block->next;
            } else {
                pattr_as_path_blocks = block->next;
            }
            if (block->next != NULL) {
                block->next->prev = block->prev;
            }
            block->prev = NULL;
            block->next = NULL;
            bgp_unlock(&pattr_as_path_block_lock);
            return block;
        }
    }
    bgp_unlock(&pattr_as_path_block_lock);
    return NULL;
}

void bgp_as_path_segments_free(libbgp_as_path_segment_t *segments, size_t segment_count)
{
    pattr_as_path_block_t *block;
    size_t i;

    if (segments == NULL) {
        return;
    }
    block = pattr_as_path_block_take(segments);
    if (block != NULL) {
        bgp_free(block);
        return;
    }
    for (i = 0u; i < segment_count; i++) {
        bgp_free(segments[i].asns);
    }
    bgp_free(segments);
}

static void pattr_free_data(libbgp_pattr_t *attr)
{
    if (attr == NULL) {
        return;
    }

    switch (attr->type) {
    case LIBBGP_PATTR_AS_PATH:
    case LIBBGP_PATTR_AS4_PATH:
        bgp_as_path_segments_free(
            attr->data.as_path.segments,
            attr->data.as_path.segment_count);
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
    size_t total_asns = 0u;
    size_t asn_size = is_4b ? 4u : 2u;
    size_t segments_offset;
    size_t asn_offset;
    size_t block_size;
    pattr_as_path_block_t *block;
    uint32_t *asn_pool;
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
        if (total_asns > SIZE_MAX - count) {
            return LIBBGP_ERR_BAD_LEN;
        }
        total_asns += count;
        segment_count++;
        pos += bytes;
    }

    tmp->data.as_path.is_4b = is_4b;
    tmp->data.as_path.segment_count = segment_count;
    if (segment_count == 0u) {
        return LIBBGP_OK;
    }

    if (!pattr_as_path_block_layout(
            segment_count,
            total_asns,
            &segments_offset,
            &asn_offset,
            &block_size)) {
        return LIBBGP_ERR_BAD_LEN;
    }
    block = (pattr_as_path_block_t *)bgp_malloc(block_size);
    if (block == NULL) {
        return LIBBGP_ERR_NOMEM;
    }
    tmp->data.as_path.segments =
        (libbgp_as_path_segment_t *)((uint8_t *)block + segments_offset);
    asn_pool = (uint32_t *)((uint8_t *)block + asn_offset);

    pos = 0u;
    for (i = 0u; i < segment_count; i++) {
        size_t j;
        size_t count = value[pos + 1u];

        tmp->data.as_path.segments[i].type = value[pos];
        tmp->data.as_path.segments[i].asn_count = count;
        pos += 2u;
        if (count != 0u) {
            tmp->data.as_path.segments[i].asns = asn_pool;
        } else {
            tmp->data.as_path.segments[i].asns = NULL;
        }
        for (j = 0u; j < count; j++) {
            if (is_4b) {
                tmp->data.as_path.segments[i].asns[j] = bgp_get_be32(value + pos);
            } else {
                tmp->data.as_path.segments[i].asns[j] = bgp_get_be16(value + pos);
            }
            pos += asn_size;
        }
        asn_pool += count;
    }

    pattr_as_path_block_register(block, tmp->data.as_path.segments);
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
    size_t cap = 0u;
    libbgp_prefix6_t *withdrawn = NULL;
    libbgp_prefix6_t p;
    size_t consumed;

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
            bgp_free(withdrawn);
            return err;
        }
        if (consumed == 0u || consumed > value_len - pos) {
            bgp_free(withdrawn);
            return LIBBGP_ERR_BAD_LEN;
        }
        if (count >= cap) {
            size_t new_cap = cap == 0u ? 8u : cap * 2u;
            libbgp_prefix6_t *next;

            if (new_cap <= cap || new_cap > SIZE_MAX / sizeof(*withdrawn)) {
                bgp_free(withdrawn);
                return LIBBGP_ERR_BAD_LEN;
            }
            next = (libbgp_prefix6_t *)bgp_realloc(withdrawn, new_cap * sizeof(*withdrawn));
            if (next == NULL) {
                bgp_free(withdrawn);
                return LIBBGP_ERR_NOMEM;
            }
            withdrawn = next;
            cap = new_cap;
        }
        withdrawn[count] = p;
        count++;
        pos += consumed;
    }

    tmp->data.mp_unreach_ipv6.withdrawn = withdrawn;
    tmp->data.mp_unreach_ipv6.withdrawn_count = count;
    return LIBBGP_OK;
}

static libbgp_err_t parse_mp_reach_ipv6(
    libbgp_pattr_t *tmp,
    const uint8_t *value,
    size_t value_len)
{
    size_t pos;
    size_t count = 0u;
    size_t cap = 0u;
    libbgp_prefix6_t *nlri = NULL;
    libbgp_prefix6_t p;
    size_t consumed;

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
            bgp_free(nlri);
            return err;
        }
        if (consumed == 0u || consumed > value_len - pos) {
            bgp_free(nlri);
            return LIBBGP_ERR_BAD_LEN;
        }
        if (count >= cap) {
            size_t new_cap = cap == 0u ? 8u : cap * 2u;
            libbgp_prefix6_t *next;

            if (new_cap <= cap || new_cap > SIZE_MAX / sizeof(*nlri)) {
                bgp_free(nlri);
                return LIBBGP_ERR_BAD_LEN;
            }
            next = (libbgp_prefix6_t *)bgp_realloc(nlri, new_cap * sizeof(*nlri));
            if (next == NULL) {
                bgp_free(nlri);
                return LIBBGP_ERR_NOMEM;
            }
            nlri = next;
            cap = new_cap;
        }
        nlri[count] = p;
        count++;
        pos += consumed;
    }

    tmp->data.mp_reach_ipv6.nlri = nlri;
    tmp->data.mp_reach_ipv6.nlri_count = count;
    return LIBBGP_OK;
}

libbgp_err_t libbgp_pattr_parse_as4(
    libbgp_pattr_t *attr,
    const uint8_t *buf,
    size_t len,
    bool use_4b_asn,
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
    if (!pattr_known_flags_valid(tmp.type, flags)) {
        return LIBBGP_ERR_INVALID;
    }

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
        err = parse_as_path(&tmp, value, value_len, use_4b_asn);
        break;
    case LIBBGP_PATTR_NEXT_HOP:
        if (value_len != 4u) {
            err = LIBBGP_ERR_BAD_LEN;
        } else {
            memcpy(&tmp.data.next_hop.next_hop, value, 4u);
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
        if (value_len != (use_4b_asn ? 8u : 6u)) {
            err = LIBBGP_ERR_BAD_LEN;
        } else if (use_4b_asn) {
            tmp.data.aggregator.asn = bgp_get_be32(value);
            tmp.data.aggregator.router_id = bgp_get_be32(value + 4u);
            tmp.data.aggregator.is_4b = true;
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

libbgp_err_t libbgp_pattr_parse(
    libbgp_pattr_t *attr,
    const uint8_t *buf,
    size_t len,
    size_t *consumed)
{
    return libbgp_pattr_parse_as4(attr, buf, len, false, consumed);
}

libbgp_err_t libbgp_pattr_prepare_for_ebgp_forward(libbgp_pattr_t *attr)
{
    if (attr == NULL) {
        return LIBBGP_ERR_INVALID;
    }
    if (attr->type == LIBBGP_PATTR_UNKNOWN &&
        (attr->flags & LIBBGP_PATTR_FLAG_OPTIONAL) != 0u &&
        (attr->flags & LIBBGP_PATTR_FLAG_TRANSITIVE) != 0u) {
        attr->flags |= LIBBGP_PATTR_FLAG_PARTIAL;
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

    if (attr->type != LIBBGP_PATTR_UNKNOWN &&
        attr->type_code != pattr_default_type_code(attr->type)) {
        return LIBBGP_ERR_BAD_LEN;
    }
    if (!pattr_known_flags_valid(attr->type, attr->flags)) {
        return LIBBGP_ERR_BAD_LEN;
    }

    switch (attr->type) {
    case LIBBGP_PATTR_ORIGIN:
        len = 1u;
        break;
    case LIBBGP_PATTR_AS_PATH:
    case LIBBGP_PATTR_AS4_PATH:
        if (attr->type == LIBBGP_PATTR_AS4_PATH && !attr->data.as_path.is_4b) {
            return LIBBGP_ERR_BAD_LEN;
        }
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
        len = attr->data.aggregator.is_4b ? 8u : 6u;
        if (!attr->data.aggregator.is_4b && attr->data.aggregator.asn > 65535u) {
            return LIBBGP_ERR_BAD_LEN;
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

libbgp_err_t libbgp_pattr_wire_len(const libbgp_pattr_t *attr, size_t *out_len)
{
    size_t value_len;
    size_t header_len;
    bool extended;
    libbgp_err_t err;

    if (attr == NULL || out_len == NULL) {
        return LIBBGP_ERR_BAD_LEN;
    }

    err = pattr_value_len(attr, &value_len);
    if (err != LIBBGP_OK) {
        return err;
    }
    switch (attr->type) {
    case LIBBGP_PATTR_ORIGIN:
        if (attr->data.origin.origin > 2u) {
            return LIBBGP_ERR_BAD_LEN;
        }
        break;
    case LIBBGP_PATTR_AS_PATH:
    case LIBBGP_PATTR_AS4_PATH:
        if (!attr->data.as_path.is_4b) {
            size_t i;

            for (i = 0u; i < attr->data.as_path.segment_count; i++) {
                size_t j;

                for (j = 0u; j < attr->data.as_path.segments[i].asn_count; j++) {
                    if (attr->data.as_path.segments[i].asns[j] > 65535u) {
                        return LIBBGP_ERR_BAD_LEN;
                    }
                }
            }
        }
        break;
    default:
        break;
    }

    extended = value_len > 255u ||
        (attr->flags & LIBBGP_PATTR_FLAG_EXTENDED_LENGTH) != 0u;
    header_len = extended ? 4u : 3u;
    if (value_len > SIZE_MAX - header_len) {
        return LIBBGP_ERR_BAD_LEN;
    }
    *out_len = header_len + value_len;
    return LIBBGP_OK;
}

static libbgp_err_t write_value(const libbgp_pattr_t *attr, uint8_t *buf, size_t value_len)
{
    size_t i;
    size_t pos;
    BGP_UNUSED(value_len);

    switch (attr->type) {
    case LIBBGP_PATTR_ORIGIN:
        if (attr->data.origin.origin > 2u) {
            return LIBBGP_ERR_BAD_LEN;
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
                        return LIBBGP_ERR_BAD_LEN;
                    }
                }
            }
        }
        write_as_path_value(attr, buf);
        break;
    case LIBBGP_PATTR_NEXT_HOP:
        memcpy(buf, &attr->data.next_hop.next_hop, 4u);
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
        if (attr->data.aggregator.is_4b) {
            bgp_put_be32(buf, attr->data.aggregator.asn);
            bgp_put_be32(buf + 4u, attr->data.aggregator.router_id);
        } else {
            bgp_put_be16(buf, (uint16_t)attr->data.aggregator.asn);
            bgp_put_be32(buf + 2u, attr->data.aggregator.router_id);
        }
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

static libbgp_err_t pattr_format_append(char *buf, size_t buf_len, size_t *pos, const char *fmt, ...)
{
    char dummy[1];
    va_list ap;
    int wrote;

    if (pos == NULL || fmt == NULL) {
        return LIBBGP_ERR_INVALID;
    }
    va_start(ap, fmt);
    if (buf != NULL && *pos < buf_len) {
        wrote = vsnprintf(buf + *pos, buf_len - *pos, fmt, ap);
    } else {
        wrote = vsnprintf(dummy, 0u, fmt, ap);
    }
    va_end(ap);
    if (wrote < 0) {
        return LIBBGP_ERR_INVALID;
    }
    *pos += (size_t)wrote;
    return LIBBGP_OK;
}

static libbgp_err_t pattr_format_as_path(const libbgp_pattr_t *attr, char *buf, size_t buf_len, size_t *pos)
{
    size_t i;
    libbgp_err_t err;

    err = pattr_format_append(
        buf,
        buf_len,
        pos,
        " is_4b=%u segments=%zu",
        attr->data.as_path.is_4b ? 1u : 0u,
        attr->data.as_path.segment_count);
    if (err != LIBBGP_OK) {
        return err;
    }
    if (attr->data.as_path.segment_count != 0u && attr->data.as_path.segments == NULL) {
        return pattr_format_append(buf, buf_len, pos, " malformed");
    }
    for (i = 0u; i < attr->data.as_path.segment_count; i++) {
        const libbgp_as_path_segment_t *segment = &attr->data.as_path.segments[i];
        size_t j;

        err = pattr_format_append(buf, buf_len, pos, " segment[%zu]={type=%u asns=[", i, segment->type);
        if (err != LIBBGP_OK) {
            return err;
        }
        if (segment->asn_count != 0u && segment->asns == NULL) {
            err = pattr_format_append(buf, buf_len, pos, "malformed");
        } else {
            for (j = 0u; j < segment->asn_count; j++) {
                err = pattr_format_append(
                    buf,
                    buf_len,
                    pos,
                    "%s%u",
                    j == 0u ? "" : ",",
                    segment->asns[j]);
                if (err != LIBBGP_OK) {
                    return err;
                }
            }
        }
        if (err != LIBBGP_OK) {
            return err;
        }
        err = pattr_format_append(buf, buf_len, pos, "]}");
        if (err != LIBBGP_OK) {
            return err;
        }
    }
    return LIBBGP_OK;
}

static libbgp_err_t pattr_format_u32_list(
    char *buf,
    size_t buf_len,
    size_t *pos,
    const uint32_t *values,
    size_t count)
{
    size_t i;
    libbgp_err_t err;

    if (count != 0u && values == NULL) {
        return pattr_format_append(buf, buf_len, pos, " malformed");
    }
    err = pattr_format_append(buf, buf_len, pos, " values=[");
    if (err != LIBBGP_OK) {
        return err;
    }
    for (i = 0u; i < count; i++) {
        err = pattr_format_append(buf, buf_len, pos, "%s%u", i == 0u ? "" : ",", values[i]);
        if (err != LIBBGP_OK) {
            return err;
        }
    }
    return pattr_format_append(buf, buf_len, pos, "]");
}

libbgp_err_t libbgp_pattr_format(
    const libbgp_pattr_t *attr,
    char *buf,
    size_t buf_len,
    size_t *out_len)
{
    size_t pos = 0u;
    libbgp_err_t err;

    if (out_len != NULL) {
        *out_len = 0u;
    }
    if (attr == NULL || (buf == NULL && buf_len != 0u)) {
        return LIBBGP_ERR_INVALID;
    }
    err = pattr_format_append(
        buf,
        buf_len,
        &pos,
        "%s flags=0x%02x code=%u",
        libbgp_pattr_type_name(attr->type),
        attr->flags,
        attr->type_code);
    if (err != LIBBGP_OK) {
        return err;
    }
    switch (attr->type) {
    case LIBBGP_PATTR_ORIGIN:
        err = pattr_format_append(buf, buf_len, &pos, " origin=%u", attr->data.origin.origin);
        break;
    case LIBBGP_PATTR_AS_PATH:
    case LIBBGP_PATTR_AS4_PATH:
        err = pattr_format_as_path(attr, buf, buf_len, &pos);
        break;
    case LIBBGP_PATTR_NEXT_HOP:
        err = pattr_format_append(buf, buf_len, &pos, " next_hop=0x%08x", attr->data.next_hop.next_hop);
        break;
    case LIBBGP_PATTR_MED:
        err = pattr_format_append(buf, buf_len, &pos, " med=%u", attr->data.med.value);
        break;
    case LIBBGP_PATTR_LOCAL_PREF:
        err = pattr_format_append(buf, buf_len, &pos, " local_pref=%u", attr->data.local_pref.value);
        break;
    case LIBBGP_PATTR_ATOMIC_AGGREGATE:
        err = pattr_format_append(buf, buf_len, &pos, " atomic=1");
        break;
    case LIBBGP_PATTR_AGGREGATOR:
    case LIBBGP_PATTR_AS4_AGGREGATOR:
        err = pattr_format_append(
            buf,
            buf_len,
            &pos,
            " asn=%u router_id=0x%08x is_4b=%u",
            attr->data.aggregator.asn,
            attr->data.aggregator.router_id,
            attr->data.aggregator.is_4b ? 1u : 0u);
        break;
    case LIBBGP_PATTR_COMMUNITY:
        err = pattr_format_append(buf, buf_len, &pos, " count=%zu", attr->data.community.count);
        if (err == LIBBGP_OK) {
            err = pattr_format_u32_list(
                buf,
                buf_len,
                &pos,
                attr->data.community.values,
                attr->data.community.count);
        }
        break;
    case LIBBGP_PATTR_MP_REACH_IPV6:
        err = pattr_format_append(
            buf,
            buf_len,
            &pos,
            " nexthop_len=%zu nlri_count=%zu",
            attr->data.mp_reach_ipv6.nexthop_len,
            attr->data.mp_reach_ipv6.nlri_count);
        if (err == LIBBGP_OK &&
            attr->data.mp_reach_ipv6.nlri_count != 0u &&
            attr->data.mp_reach_ipv6.nlri == NULL) {
            err = pattr_format_append(buf, buf_len, &pos, " malformed");
        }
        break;
    case LIBBGP_PATTR_MP_UNREACH_IPV6:
        err = pattr_format_append(
            buf,
            buf_len,
            &pos,
            " withdrawn_count=%zu",
            attr->data.mp_unreach_ipv6.withdrawn_count);
        if (err == LIBBGP_OK &&
            attr->data.mp_unreach_ipv6.withdrawn_count != 0u &&
            attr->data.mp_unreach_ipv6.withdrawn == NULL) {
            err = pattr_format_append(buf, buf_len, &pos, " malformed");
        }
        break;
    case LIBBGP_PATTR_UNKNOWN:
        err = pattr_format_append(buf, buf_len, &pos, " len=%zu", attr->data.unknown.len);
        break;
    default:
        err = pattr_format_append(buf, buf_len, &pos, " invalid=1");
        break;
    }
    if (out_len != NULL) {
        *out_len = pos;
    }
    if (err != LIBBGP_OK) {
        return err;
    }
    if (buf == NULL || buf_len == 0u || pos >= buf_len) {
        return LIBBGP_ERR_BUFFER;
    }
    return LIBBGP_OK;
}
