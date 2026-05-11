#include "libbgp/update.h"

#include <string.h>

#include "internal.h"

void libbgp_update_init(libbgp_update_msg_t *msg)
{
    if (msg == NULL) {
        return;
    }
    memset(msg, 0, sizeof(*msg));
}

void libbgp_update_destroy(libbgp_update_msg_t *msg)
{
    size_t i;

    if (msg == NULL) {
        return;
    }
    bgp_free(msg->withdrawn);
    msg->withdrawn = NULL;
    msg->withdrawn_count = 0u;
    for (i = 0u; i < msg->attr_count; i++) {
        libbgp_pattr_unref(msg->attrs[i]);
    }
    bgp_free(msg->attrs);
    msg->attrs = NULL;
    msg->attr_count = 0u;
    bgp_free(msg->nlri);
    msg->nlri = NULL;
    msg->nlri_count = 0u;
}

static bool update_attrs_same_semantic(const libbgp_pattr_t *a, const libbgp_pattr_t *b)
{
    return a != NULL && b != NULL && a->type_code == b->type_code;
}

static bool update_find_attr_index(
    const libbgp_update_msg_t *msg,
    libbgp_pattr_type_t type,
    size_t *index)
{
    size_t i;

    if (msg == NULL) {
        return false;
    }
    for (i = 0u; i < msg->attr_count; i++) {
        if (msg->attrs[i] != NULL && msg->attrs[i]->type == type) {
            if (index != NULL) {
                *index = i;
            }
            return true;
        }
    }
    return false;
}

static void update_remove_attr_at(libbgp_update_msg_t *msg, size_t index)
{
    if (msg == NULL || index >= msg->attr_count) {
        return;
    }
    libbgp_pattr_unref(msg->attrs[index]);
    if (index + 1u < msg->attr_count) {
        memmove(
            &msg->attrs[index],
            &msg->attrs[index + 1u],
            (msg->attr_count - index - 1u) * sizeof(msg->attrs[0]));
    }
    msg->attr_count--;
    if (msg->attr_count == 0u) {
        bgp_free(msg->attrs);
        msg->attrs = NULL;
    }
}

static bool update_remove_attr_type(libbgp_update_msg_t *msg, libbgp_pattr_type_t type)
{
    size_t index;

    if (!update_find_attr_index(msg, type, &index)) {
        return false;
    }
    update_remove_attr_at(msg, index);
    return true;
}

static libbgp_err_t update_add_prefix(
    libbgp_prefix4_t **array,
    size_t *count,
    const libbgp_prefix4_t *p)
{
    libbgp_prefix4_t *next;

    if (array == NULL || count == NULL || p == NULL || p->len > 32u) {
        return LIBBGP_ERR_BAD_LEN;
    }
    if (*count > (SIZE_MAX / sizeof((*array)[0])) - 1u) {
        return LIBBGP_ERR_BAD_LEN;
    }
    next = (libbgp_prefix4_t *)bgp_realloc(*array, (*count + 1u) * sizeof((*array)[0]));
    if (next == NULL) {
        return LIBBGP_ERR_NOMEM;
    }
    *array = next;
    (*array)[*count] = *p;
    (*count)++;
    return LIBBGP_OK;
}

libbgp_err_t libbgp_update_add_withdrawn(libbgp_update_msg_t *msg, const libbgp_prefix4_t *p)
{
    if (msg == NULL) {
        return LIBBGP_ERR_BAD_LEN;
    }
    return update_add_prefix(&msg->withdrawn, &msg->withdrawn_count, p);
}

libbgp_err_t libbgp_update_add_attr(libbgp_update_msg_t *msg, libbgp_pattr_t *attr)
{
    libbgp_pattr_t **next;
    size_t i;

    if (msg == NULL || attr == NULL) {
        return LIBBGP_ERR_BAD_LEN;
    }
    if (msg->attr_count != 0u && msg->attrs == NULL) {
        return LIBBGP_ERR_BAD_LEN;
    }
    for (i = 0u; i < msg->attr_count; i++) {
        if (update_attrs_same_semantic(msg->attrs[i], attr)) {
            return LIBBGP_ERR_EXISTS;
        }
    }
    if (msg->attr_count > (SIZE_MAX / sizeof(msg->attrs[0])) - 1u) {
        return LIBBGP_ERR_BAD_LEN;
    }
    next = (libbgp_pattr_t **)bgp_realloc(
        msg->attrs,
        (msg->attr_count + 1u) * sizeof(msg->attrs[0]));
    if (next == NULL) {
        return LIBBGP_ERR_NOMEM;
    }
    msg->attrs = next;
    msg->attrs[msg->attr_count] = libbgp_pattr_ref(attr);
    msg->attr_count++;
    return LIBBGP_OK;
}

libbgp_err_t libbgp_update_add_nlri(libbgp_update_msg_t *msg, const libbgp_prefix4_t *p)
{
    if (msg == NULL) {
        return LIBBGP_ERR_BAD_LEN;
    }
    return update_add_prefix(&msg->nlri, &msg->nlri_count, p);
}

libbgp_pattr_t *libbgp_update_find_attr(const libbgp_update_msg_t *msg, libbgp_pattr_type_t type)
{
    size_t index;

    if (!update_find_attr_index(msg, type, &index)) {
        return NULL;
    }
    return msg->attrs[index];
}

static bool update_mp_reach_has_nlri(const libbgp_pattr_t *attr)
{
    return attr != NULL &&
        attr->type == LIBBGP_PATTR_MP_REACH_IPV6 &&
        attr->data.mp_reach_ipv6.nlri_count != 0u;
}

libbgp_err_t libbgp_update_validate(const libbgp_update_msg_t *msg)
{
    bool has_origin = false;
    bool has_as_path = false;
    bool has_next_hop = false;
    bool has_mp_reach_nlri = false;
    size_t i;
    size_t j;

    if (msg == NULL) {
        return LIBBGP_ERR_BAD_LEN;
    }
    if ((msg->withdrawn_count != 0u && msg->withdrawn == NULL) ||
        (msg->attr_count != 0u && msg->attrs == NULL) ||
        (msg->nlri_count != 0u && msg->nlri == NULL)) {
        return LIBBGP_ERR_BAD_LEN;
    }

    for (i = 0u; i < msg->attr_count; i++) {
        libbgp_pattr_t *attr = msg->attrs[i];

        if (attr == NULL) {
            return LIBBGP_ERR_BAD_LEN;
        }
        for (j = i + 1u; j < msg->attr_count; j++) {
            if (update_attrs_same_semantic(attr, msg->attrs[j])) {
                return LIBBGP_ERR_INVALID;
            }
        }
        if (attr->type == LIBBGP_PATTR_ORIGIN) {
            has_origin = true;
        } else if (attr->type == LIBBGP_PATTR_AS_PATH) {
            has_as_path = true;
        } else if (attr->type == LIBBGP_PATTR_NEXT_HOP) {
            has_next_hop = true;
        } else if (update_mp_reach_has_nlri(attr)) {
            has_mp_reach_nlri = true;
        }
    }

    if (msg->nlri_count != 0u && (!has_origin || !has_as_path || !has_next_hop)) {
        return LIBBGP_ERR_INVALID;
    }
    if (has_mp_reach_nlri && (!has_origin || !has_as_path)) {
        return LIBBGP_ERR_INVALID;
    }
    return LIBBGP_OK;
}

static libbgp_err_t update_set_attr(libbgp_update_msg_t *msg, libbgp_pattr_t *attr)
{
    size_t index;

    if (msg == NULL || attr == NULL) {
        return LIBBGP_ERR_BAD_LEN;
    }
    if (update_find_attr_index(msg, attr->type, &index)) {
        libbgp_pattr_t *ref = libbgp_pattr_ref(attr);

        libbgp_pattr_unref(msg->attrs[index]);
        msg->attrs[index] = ref;
        return LIBBGP_OK;
    }
    return libbgp_update_add_attr(msg, attr);
}

static libbgp_err_t update_copy_as_path_data(libbgp_pattr_t *dst, const libbgp_pattr_t *src, bool is_4b)
{
    size_t i;

    if (dst == NULL || src == NULL ||
        (src->type != LIBBGP_PATTR_AS_PATH && src->type != LIBBGP_PATTR_AS4_PATH)) {
        return LIBBGP_ERR_BAD_LEN;
    }
    if (src->data.as_path.segment_count != 0u && src->data.as_path.segments == NULL) {
        return LIBBGP_ERR_BAD_LEN;
    }
    dst->data.as_path.is_4b = is_4b;
    dst->data.as_path.segment_count = src->data.as_path.segment_count;
    if (src->data.as_path.segment_count == 0u) {
        return LIBBGP_OK;
    }
    if (src->data.as_path.segment_count > SIZE_MAX / sizeof(dst->data.as_path.segments[0])) {
        return LIBBGP_ERR_BAD_LEN;
    }
    dst->data.as_path.segments = (libbgp_as_path_segment_t *)bgp_calloc(
        src->data.as_path.segment_count,
        sizeof(dst->data.as_path.segments[0]));
    if (dst->data.as_path.segments == NULL) {
        return LIBBGP_ERR_NOMEM;
    }
    for (i = 0u; i < src->data.as_path.segment_count; i++) {
        const libbgp_as_path_segment_t *src_seg = &src->data.as_path.segments[i];
        libbgp_as_path_segment_t *dst_seg = &dst->data.as_path.segments[i];

        if (src_seg->asn_count != 0u && src_seg->asns == NULL) {
            return LIBBGP_ERR_BAD_LEN;
        }
        dst_seg->type = src_seg->type;
        dst_seg->asn_count = src_seg->asn_count;
        if (src_seg->asn_count == 0u) {
            continue;
        }
        if (src_seg->asn_count > SIZE_MAX / sizeof(dst_seg->asns[0])) {
            return LIBBGP_ERR_BAD_LEN;
        }
        dst_seg->asns = (uint32_t *)bgp_malloc(src_seg->asn_count * sizeof(dst_seg->asns[0]));
        if (dst_seg->asns == NULL) {
            return LIBBGP_ERR_NOMEM;
        }
        memcpy(dst_seg->asns, src_seg->asns, src_seg->asn_count * sizeof(dst_seg->asns[0]));
    }
    return LIBBGP_OK;
}

static libbgp_err_t update_prepend_to_path(libbgp_pattr_t *path, uint32_t asn)
{
    libbgp_as_path_segment_t *seg;

    if (path == NULL ||
        (path->type != LIBBGP_PATTR_AS_PATH && path->type != LIBBGP_PATTR_AS4_PATH)) {
        return LIBBGP_ERR_BAD_LEN;
    }
    if (path->data.as_path.segment_count != 0u && path->data.as_path.segments == NULL) {
        return LIBBGP_ERR_BAD_LEN;
    }
    if (path->data.as_path.segment_count != 0u) {
        seg = &path->data.as_path.segments[0];
        if (seg->type == 2u && seg->asn_count < 255u) {
            uint32_t *next;

            if (seg->asn_count != 0u && seg->asns == NULL) {
                return LIBBGP_ERR_BAD_LEN;
            }
            if (seg->asn_count > (SIZE_MAX / sizeof(seg->asns[0])) - 1u) {
                return LIBBGP_ERR_BAD_LEN;
            }
            next = (uint32_t *)bgp_realloc(seg->asns, (seg->asn_count + 1u) * sizeof(seg->asns[0]));
            if (next == NULL) {
                return LIBBGP_ERR_NOMEM;
            }
            if (seg->asn_count != 0u) {
                memmove(&next[1], &next[0], seg->asn_count * sizeof(next[0]));
            }
            next[0] = asn;
            seg->asns = next;
            seg->asn_count++;
            return LIBBGP_OK;
        }
    }

    if (path->data.as_path.segment_count > (SIZE_MAX / sizeof(path->data.as_path.segments[0])) - 1u) {
        return LIBBGP_ERR_BAD_LEN;
    }
    {
        uint32_t *asns = (uint32_t *)bgp_malloc(sizeof(asns[0]));
        libbgp_as_path_segment_t *next;

        if (asns == NULL) {
            return LIBBGP_ERR_NOMEM;
        }
        asns[0] = asn;
        next = (libbgp_as_path_segment_t *)bgp_realloc(
            path->data.as_path.segments,
            (path->data.as_path.segment_count + 1u) * sizeof(path->data.as_path.segments[0]));
        if (next == NULL) {
            bgp_free(asns);
            return LIBBGP_ERR_NOMEM;
        }
        if (path->data.as_path.segment_count != 0u) {
            memmove(
                &next[1],
                &next[0],
                path->data.as_path.segment_count * sizeof(next[0]));
        }
        next[0].type = 2u;
        next[0].asn_count = 1u;
        next[0].asns = asns;
        path->data.as_path.segments = next;
        path->data.as_path.segment_count++;
    }
    return LIBBGP_OK;
}

libbgp_err_t libbgp_update_prepend_asn(libbgp_update_msg_t *msg, uint32_t asn, bool use_4b_asn)
{
    libbgp_pattr_t *as_path;
    libbgp_err_t err;
    uint32_t prep_asn = use_4b_asn || asn <= 65535u ? asn : LIBBGP_AS_TRANS;

    if (msg == NULL) {
        return LIBBGP_ERR_BAD_LEN;
    }
    if (use_4b_asn && libbgp_update_find_attr(msg, LIBBGP_PATTR_AS4_PATH) != NULL) {
        return LIBBGP_ERR_INVALID;
    }
    as_path = libbgp_update_find_attr(msg, LIBBGP_PATTR_AS_PATH);
    if (as_path != NULL && as_path->data.as_path.is_4b != use_4b_asn) {
        return LIBBGP_ERR_INVALID;
    }
    if (as_path == NULL) {
        libbgp_pattr_t *created = libbgp_pattr_new(LIBBGP_PATTR_AS_PATH);

        if (created == NULL) {
            return LIBBGP_ERR_NOMEM;
        }
        created->data.as_path.is_4b = use_4b_asn;
        err = update_prepend_to_path(created, prep_asn);
        if (err == LIBBGP_OK) {
            err = update_set_attr(msg, created);
        }
        libbgp_pattr_unref(created);
        if (err != LIBBGP_OK) {
            return err;
        }
        as_path = libbgp_update_find_attr(msg, LIBBGP_PATTR_AS_PATH);
    } else {
        err = update_prepend_to_path(as_path, prep_asn);
        if (err != LIBBGP_OK) {
            return err;
        }
    }

    if (!use_4b_asn) {
        libbgp_pattr_t *as4_path = libbgp_update_find_attr(msg, LIBBGP_PATTR_AS4_PATH);

        if (as4_path != NULL) {
            err = update_prepend_to_path(as4_path, prep_asn);
            if (err != LIBBGP_OK) {
                return err;
            }
        }
    }
    return LIBBGP_OK;
}

static libbgp_err_t update_flatten_path_asns(const libbgp_pattr_t *path, uint32_t **out_asns, size_t *out_count)
{
    uint32_t *flat = NULL;
    size_t total = 0u;
    size_t pos = 0u;
    size_t i;

    if (path == NULL || out_asns == NULL || out_count == NULL ||
        (path->type != LIBBGP_PATTR_AS_PATH && path->type != LIBBGP_PATTR_AS4_PATH)) {
        return LIBBGP_ERR_BAD_LEN;
    }
    if (path->data.as_path.segment_count != 0u && path->data.as_path.segments == NULL) {
        return LIBBGP_ERR_BAD_LEN;
    }
    for (i = 0u; i < path->data.as_path.segment_count; i++) {
        const libbgp_as_path_segment_t *seg = &path->data.as_path.segments[i];

        if (seg->asn_count != 0u && seg->asns == NULL) {
            return LIBBGP_ERR_BAD_LEN;
        }
        if (total > SIZE_MAX - seg->asn_count) {
            return LIBBGP_ERR_BAD_LEN;
        }
        total += seg->asn_count;
    }
    if (total != 0u) {
        if (total > SIZE_MAX / sizeof(flat[0])) {
            return LIBBGP_ERR_BAD_LEN;
        }
        flat = (uint32_t *)bgp_malloc(total * sizeof(flat[0]));
        if (flat == NULL) {
            return LIBBGP_ERR_NOMEM;
        }
    }
    for (i = 0u; i < path->data.as_path.segment_count; i++) {
        const libbgp_as_path_segment_t *seg = &path->data.as_path.segments[i];

        if (seg->asn_count != 0u) {
            memcpy(&flat[pos], seg->asns, seg->asn_count * sizeof(flat[0]));
            pos += seg->asn_count;
        }
    }
    *out_asns = flat;
    *out_count = total;
    return LIBBGP_OK;
}

libbgp_err_t libbgp_update_restore_as_path(libbgp_update_msg_t *msg)
{
    libbgp_pattr_t *as_path;
    libbgp_pattr_t *as4_path;
    uint32_t *as4_asns = NULL;
    size_t as4_count = 0u;
    size_t as4_pos = 0u;
    size_t as_path_count = 0u;
    bool positional_as4 = false;
    size_t i;
    libbgp_err_t err;

    if (msg == NULL) {
        return LIBBGP_ERR_BAD_LEN;
    }
    as_path = libbgp_update_find_attr(msg, LIBBGP_PATTR_AS_PATH);
    as4_path = libbgp_update_find_attr(msg, LIBBGP_PATTR_AS4_PATH);
    if (as_path == NULL) {
        return LIBBGP_OK;
    }
    if (as4_path == NULL) {
        as_path->data.as_path.is_4b = true;
        return LIBBGP_OK;
    }
    err = update_flatten_path_asns(as4_path, &as4_asns, &as4_count);
    if (err != LIBBGP_OK) {
        return err;
    }
    if (as_path->data.as_path.segment_count != 0u && as_path->data.as_path.segments == NULL) {
        bgp_free(as4_asns);
        return LIBBGP_ERR_BAD_LEN;
    }
    for (i = 0u; i < as_path->data.as_path.segment_count; i++) {
        libbgp_as_path_segment_t *seg = &as_path->data.as_path.segments[i];

        if (seg->asn_count != 0u && seg->asns == NULL) {
            bgp_free(as4_asns);
            return LIBBGP_ERR_BAD_LEN;
        }
        if (as_path_count > SIZE_MAX - seg->asn_count) {
            bgp_free(as4_asns);
            return LIBBGP_ERR_BAD_LEN;
        }
        as_path_count += seg->asn_count;
    }
    positional_as4 = as4_count == as_path_count;
    for (i = 0u; i < as_path->data.as_path.segment_count; i++) {
        libbgp_as_path_segment_t *seg = &as_path->data.as_path.segments[i];
        size_t j;

        for (j = 0u; j < seg->asn_count; j++) {
            if (positional_as4) {
                if (seg->asns[j] == LIBBGP_AS_TRANS) {
                    seg->asns[j] = as4_asns[as4_pos];
                }
                as4_pos++;
            } else if (seg->asns[j] == LIBBGP_AS_TRANS && as4_pos < as4_count) {
                seg->asns[j] = as4_asns[as4_pos++];
            }
        }
    }
    as_path->data.as_path.is_4b = true;
    update_remove_attr_type(msg, LIBBGP_PATTR_AS4_PATH);
    bgp_free(as4_asns);
    return LIBBGP_OK;
}

libbgp_err_t libbgp_update_downgrade_as_path(libbgp_update_msg_t *msg)
{
    libbgp_pattr_t *as_path;
    libbgp_pattr_t *as4_path;
    size_t i;
    libbgp_err_t err;

    if (msg == NULL) {
        return LIBBGP_ERR_BAD_LEN;
    }
    as_path = libbgp_update_find_attr(msg, LIBBGP_PATTR_AS_PATH);
    if (as_path == NULL || !as_path->data.as_path.is_4b) {
        return LIBBGP_OK;
    }
    as4_path = libbgp_pattr_new(LIBBGP_PATTR_AS4_PATH);
    if (as4_path == NULL) {
        return LIBBGP_ERR_NOMEM;
    }
    err = update_copy_as_path_data(as4_path, as_path, true);
    if (err == LIBBGP_OK) {
        err = update_set_attr(msg, as4_path);
    }
    libbgp_pattr_unref(as4_path);
    if (err != LIBBGP_OK) {
        return err;
    }
    if (as_path->data.as_path.segment_count != 0u && as_path->data.as_path.segments == NULL) {
        return LIBBGP_ERR_BAD_LEN;
    }
    for (i = 0u; i < as_path->data.as_path.segment_count; i++) {
        libbgp_as_path_segment_t *seg = &as_path->data.as_path.segments[i];
        size_t j;

        if (seg->asn_count != 0u && seg->asns == NULL) {
            return LIBBGP_ERR_BAD_LEN;
        }
        for (j = 0u; j < seg->asn_count; j++) {
            if (seg->asns[j] > 65535u) {
                seg->asns[j] = LIBBGP_AS_TRANS;
            }
        }
    }
    as_path->data.as_path.is_4b = false;
    return LIBBGP_OK;
}

libbgp_err_t libbgp_update_restore_aggregator(libbgp_update_msg_t *msg)
{
    libbgp_pattr_t *aggregator;
    libbgp_pattr_t *as4_aggregator;

    if (msg == NULL) {
        return LIBBGP_ERR_BAD_LEN;
    }
    aggregator = libbgp_update_find_attr(msg, LIBBGP_PATTR_AGGREGATOR);
    as4_aggregator = libbgp_update_find_attr(msg, LIBBGP_PATTR_AS4_AGGREGATOR);
    if (aggregator == NULL) {
        if (as4_aggregator == NULL) {
            return LIBBGP_OK;
        }
        aggregator = libbgp_pattr_new(LIBBGP_PATTR_AGGREGATOR);
        if (aggregator == NULL) {
            return LIBBGP_ERR_NOMEM;
        }
        aggregator->data.aggregator.asn = as4_aggregator->data.aggregator.asn;
        aggregator->data.aggregator.router_id = as4_aggregator->data.aggregator.router_id;
        aggregator->data.aggregator.is_4b = true;
        {
            libbgp_err_t err = update_set_attr(msg, aggregator);

            if (err != LIBBGP_OK) {
                libbgp_pattr_unref(aggregator);
                return err;
            }
        }
        libbgp_pattr_unref(aggregator);
        update_remove_attr_type(msg, LIBBGP_PATTR_AS4_AGGREGATOR);
        return LIBBGP_OK;
    }
    if (as4_aggregator != NULL) {
        aggregator->data.aggregator.asn = as4_aggregator->data.aggregator.asn;
        aggregator->data.aggregator.router_id = as4_aggregator->data.aggregator.router_id;
        update_remove_attr_type(msg, LIBBGP_PATTR_AS4_AGGREGATOR);
    }
    aggregator->data.aggregator.is_4b = true;
    return LIBBGP_OK;
}

libbgp_err_t libbgp_update_downgrade_aggregator(libbgp_update_msg_t *msg)
{
    libbgp_pattr_t *aggregator;
    libbgp_pattr_t *as4_aggregator;
    uint32_t original_asn;
    uint32_t original_router_id;
    libbgp_err_t err = LIBBGP_OK;

    if (msg == NULL) {
        return LIBBGP_ERR_BAD_LEN;
    }
    aggregator = libbgp_update_find_attr(msg, LIBBGP_PATTR_AGGREGATOR);
    if (aggregator == NULL) {
        return LIBBGP_OK;
    }
    original_asn = aggregator->data.aggregator.asn;
    original_router_id = aggregator->data.aggregator.router_id;
    if (aggregator->data.aggregator.is_4b || original_asn > 65535u) {
        as4_aggregator = libbgp_pattr_new(LIBBGP_PATTR_AS4_AGGREGATOR);
        if (as4_aggregator == NULL) {
            return LIBBGP_ERR_NOMEM;
        }
        as4_aggregator->data.aggregator.asn = original_asn;
        as4_aggregator->data.aggregator.router_id = original_router_id;
        as4_aggregator->data.aggregator.is_4b = true;
        err = update_set_attr(msg, as4_aggregator);
        libbgp_pattr_unref(as4_aggregator);
        if (err != LIBBGP_OK) {
            return err;
        }
    }
    aggregator->data.aggregator.asn = original_asn > 65535u ? LIBBGP_AS_TRANS : original_asn;
    aggregator->data.aggregator.router_id = original_router_id;
    aggregator->data.aggregator.is_4b = false;
    return LIBBGP_OK;
}

static libbgp_err_t update_parse_prefixes(
    libbgp_prefix4_t **array,
    size_t *count,
    const uint8_t *buf,
    size_t len)
{
    size_t pos = 0u;

    while (pos < len) {
        libbgp_prefix4_t p;
        size_t used = 0u;
        libbgp_err_t err;

        err = libbgp_prefix4_parse(&p, buf + pos, len - pos, &used);
        if (err != LIBBGP_OK) {
            return err;
        }
        err = update_add_prefix(array, count, &p);
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

static libbgp_err_t update_parse_attrs(
    libbgp_update_msg_t *tmp,
    const uint8_t *buf,
    size_t len,
    bool use_4b_asn)
{
    size_t pos = 0u;

    while (pos < len) {
        libbgp_pattr_t *attr;
        size_t used = 0u;
        libbgp_err_t err;

        attr = libbgp_pattr_new(LIBBGP_PATTR_UNKNOWN);
        if (attr == NULL) {
            return LIBBGP_ERR_NOMEM;
        }
        err = libbgp_pattr_parse_as4(attr, buf + pos, len - pos, use_4b_asn, &used);
        if (err == LIBBGP_OK) {
            err = libbgp_update_add_attr(tmp, attr);
        }
        libbgp_pattr_unref(attr);
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

libbgp_err_t libbgp_update_parse_as4(
    libbgp_update_msg_t *msg,
    const uint8_t *buf,
    size_t len,
    bool use_4b_asn,
    size_t *consumed)
{
    libbgp_update_msg_t tmp;
    size_t withdrawn_len;
    size_t attr_len;
    size_t pos;
    libbgp_err_t err;

    if (msg == NULL || buf == NULL || len < 4u) {
        return LIBBGP_ERR_BAD_LEN;
    }
    withdrawn_len = bgp_get_be16(buf);
    pos = 2u;
    if (len - pos < withdrawn_len) {
        return LIBBGP_ERR_BAD_LEN;
    }

    libbgp_update_init(&tmp);
    err = update_parse_prefixes(&tmp.withdrawn, &tmp.withdrawn_count, buf + pos, withdrawn_len);
    if (err != LIBBGP_OK) {
        libbgp_update_destroy(&tmp);
        return err;
    }
    pos += withdrawn_len;
    if (len - pos < 2u) {
        libbgp_update_destroy(&tmp);
        return LIBBGP_ERR_BAD_LEN;
    }
    attr_len = bgp_get_be16(buf + pos);
    pos += 2u;
    if (len - pos < attr_len) {
        libbgp_update_destroy(&tmp);
        return LIBBGP_ERR_BAD_LEN;
    }
    err = update_parse_attrs(&tmp, buf + pos, attr_len, use_4b_asn);
    if (err != LIBBGP_OK) {
        libbgp_update_destroy(&tmp);
        return err;
    }
    pos += attr_len;
    err = update_parse_prefixes(&tmp.nlri, &tmp.nlri_count, buf + pos, len - pos);
    if (err != LIBBGP_OK) {
        libbgp_update_destroy(&tmp);
        return err;
    }
    err = libbgp_update_validate(&tmp);
    if (err != LIBBGP_OK) {
        libbgp_update_destroy(&tmp);
        return err;
    }

    libbgp_update_destroy(msg);
    *msg = tmp;
    if (consumed != NULL) {
        *consumed = len;
    }
    return LIBBGP_OK;
}

libbgp_err_t libbgp_update_parse(
    libbgp_update_msg_t *msg,
    const uint8_t *buf,
    size_t len,
    size_t *consumed)
{
    return libbgp_update_parse_as4(msg, buf, len, false, consumed);
}

static libbgp_err_t update_prefixes_len(
    const libbgp_prefix4_t *prefixes,
    size_t count,
    size_t *out)
{
    size_t i;
    size_t total = 0u;

    if (count != 0u && prefixes == NULL) {
        return LIBBGP_ERR_BAD_LEN;
    }
    for (i = 0u; i < count; i++) {
        size_t one = 1u + ((size_t)prefixes[i].len + 7u) / 8u;
        if (prefixes[i].len > 32u || total > SIZE_MAX - one) {
            return LIBBGP_ERR_BAD_LEN;
        }
        total += one;
    }
    *out = total;
    return LIBBGP_OK;
}

static libbgp_err_t update_attrs_len(const libbgp_update_msg_t *msg, size_t *out)
{
    uint8_t scratch[4096];
    size_t i;
    size_t total = 0u;

    if (msg->attr_count != 0u && msg->attrs == NULL) {
        return LIBBGP_ERR_BAD_LEN;
    }
    for (i = 0u; i < msg->attr_count; i++) {
        size_t one = 0u;
        libbgp_err_t err = libbgp_pattr_write(msg->attrs[i], scratch, sizeof(scratch), &one);
        if (err != LIBBGP_OK) {
            return err;
        }
        if (total > SIZE_MAX - one) {
            return LIBBGP_ERR_BAD_LEN;
        }
        total += one;
    }
    *out = total;
    return LIBBGP_OK;
}

static libbgp_err_t update_write_prefixes(
    const libbgp_prefix4_t *prefixes,
    size_t count,
    uint8_t *buf,
    size_t buf_len,
    size_t *written)
{
    size_t i;
    size_t pos = 0u;

    for (i = 0u; i < count; i++) {
        size_t one = 0u;
        libbgp_err_t err = libbgp_prefix4_write(&prefixes[i], buf + pos, buf_len - pos, &one);
        if (err != LIBBGP_OK) {
            return err;
        }
        pos += one;
    }
    *written = pos;
    return LIBBGP_OK;
}

libbgp_err_t libbgp_update_write(
    const libbgp_update_msg_t *msg,
    uint8_t *buf,
    size_t buf_len,
    size_t *out_len)
{
    size_t withdrawn_len = 0u;
    size_t attrs_len = 0u;
    size_t nlri_len = 0u;
    size_t total_len;
    size_t pos;
    size_t written;
    size_t i;
    libbgp_err_t err;

    if (msg == NULL || buf == NULL) {
        return LIBBGP_ERR_BAD_LEN;
    }
    err = libbgp_update_validate(msg);
    if (err != LIBBGP_OK) {
        return err;
    }
    err = update_prefixes_len(msg->withdrawn, msg->withdrawn_count, &withdrawn_len);
    if (err != LIBBGP_OK) {
        return err;
    }
    err = update_attrs_len(msg, &attrs_len);
    if (err != LIBBGP_OK) {
        return err;
    }
    err = update_prefixes_len(msg->nlri, msg->nlri_count, &nlri_len);
    if (err != LIBBGP_OK) {
        return err;
    }
    if (withdrawn_len > 65535u || attrs_len > 65535u ||
        withdrawn_len > SIZE_MAX - 4u ||
        attrs_len > SIZE_MAX - 4u - withdrawn_len ||
        nlri_len > SIZE_MAX - 4u - withdrawn_len - attrs_len) {
        return LIBBGP_ERR_BAD_LEN;
    }
    total_len = 4u + withdrawn_len + attrs_len + nlri_len;
    if (buf_len < total_len) {
        return LIBBGP_ERR_BUFFER;
    }

    bgp_put_be16(buf, (uint16_t)withdrawn_len);
    pos = 2u;
    err = update_write_prefixes(msg->withdrawn, msg->withdrawn_count, buf + pos, total_len - pos, &written);
    if (err != LIBBGP_OK) {
        return err;
    }
    pos += written;
    bgp_put_be16(buf + pos, (uint16_t)attrs_len);
    pos += 2u;
    for (i = 0u; i < msg->attr_count; i++) {
        size_t one = 0u;
        err = libbgp_pattr_write(msg->attrs[i], buf + pos, total_len - pos, &one);
        if (err != LIBBGP_OK) {
            return err;
        }
        pos += one;
    }
    err = update_write_prefixes(msg->nlri, msg->nlri_count, buf + pos, total_len - pos, &written);
    if (err != LIBBGP_OK) {
        return err;
    }
    if (out_len != NULL) {
        *out_len = total_len;
    }
    return LIBBGP_OK;
}
