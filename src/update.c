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
    if (msg->attrs != NULL) {
        for (i = 0u; i < msg->attr_count; i++) {
            libbgp_pattr_unref(msg->attrs[i]);
        }
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

static libbgp_err_t update_validate_as_path_data(
    const libbgp_pattr_t *path,
    bool enforce_asn_width,
    size_t *out_count);

static libbgp_err_t update_add_prefix(
    libbgp_prefix4_t **array,
    size_t *count,
    size_t *cap,
    const libbgp_prefix4_t *p)
{
    libbgp_prefix4_t *next;
    size_t new_cap;

    if (array == NULL || count == NULL || cap == NULL || p == NULL || p->len > 32u) {
        return LIBBGP_ERR_BAD_LEN;
    }
    if (*count >= *cap) {
        new_cap = *cap == 0u ? 8u : *cap * 2u;
        if (new_cap <= *cap || new_cap > SIZE_MAX / sizeof((*array)[0])) {
            return LIBBGP_ERR_BAD_LEN;
        }
        next = (libbgp_prefix4_t *)bgp_realloc(*array, new_cap * sizeof((*array)[0]));
        if (next == NULL) {
            return LIBBGP_ERR_NOMEM;
        }
        *array = next;
        *cap = new_cap;
    }
    (*array)[*count] = *p;
    (*count)++;
    return LIBBGP_OK;
}

static libbgp_err_t update_add_attr_with_cap(
    libbgp_update_msg_t *msg,
    libbgp_pattr_t *attr,
    size_t *cap)
{
    libbgp_pattr_t **next;
    size_t i;
    size_t new_cap;

    if (msg == NULL || attr == NULL || cap == NULL) {
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
    if (msg->attr_count >= *cap) {
        new_cap = *cap == 0u ? 8u : *cap * 2u;
        if (new_cap <= *cap || new_cap > SIZE_MAX / sizeof(msg->attrs[0])) {
            return LIBBGP_ERR_BAD_LEN;
        }
        next = (libbgp_pattr_t **)bgp_realloc(msg->attrs, new_cap * sizeof(msg->attrs[0]));
        if (next == NULL) {
            return LIBBGP_ERR_NOMEM;
        }
        msg->attrs = next;
        *cap = new_cap;
    }
    msg->attrs[msg->attr_count] = libbgp_pattr_ref(attr);
    msg->attr_count++;
    return LIBBGP_OK;
}

libbgp_err_t libbgp_update_add_withdrawn(libbgp_update_msg_t *msg, const libbgp_prefix4_t *p)
{
    size_t cap;

    if (msg == NULL) {
        return LIBBGP_ERR_BAD_LEN;
    }
    cap = msg->withdrawn_count;
    return update_add_prefix(&msg->withdrawn, &msg->withdrawn_count, &cap, p);
}

libbgp_err_t libbgp_update_add_attr(libbgp_update_msg_t *msg, libbgp_pattr_t *attr)
{
    size_t cap;

    if (msg == NULL || attr == NULL) {
        return LIBBGP_ERR_BAD_LEN;
    }
    cap = msg->attr_count;
    return update_add_attr_with_cap(msg, attr, &cap);
}

libbgp_err_t libbgp_update_add_nlri(libbgp_update_msg_t *msg, const libbgp_prefix4_t *p)
{
    size_t cap;

    if (msg == NULL) {
        return LIBBGP_ERR_BAD_LEN;
    }
    cap = msg->nlri_count;
    return update_add_prefix(&msg->nlri, &msg->nlri_count, &cap, p);
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
        if ((attr->type == LIBBGP_PATTR_AS_PATH || attr->type == LIBBGP_PATTR_AS4_PATH) &&
            update_validate_as_path_data(attr, true, NULL) != LIBBGP_OK) {
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

static libbgp_err_t update_set_attr_pair(
    libbgp_update_msg_t *msg,
    libbgp_pattr_t *first,
    libbgp_pattr_t *second)
{
    libbgp_pattr_t **next;
    size_t first_index;
    size_t second_index;
    bool has_first;
    bool has_second;
    size_t missing = 0u;

    if (msg == NULL || first == NULL || second == NULL || update_attrs_same_semantic(first, second)) {
        return LIBBGP_ERR_BAD_LEN;
    }
    has_first = update_find_attr_index(msg, first->type, &first_index);
    has_second = update_find_attr_index(msg, second->type, &second_index);
    missing += has_first ? 0u : 1u;
    missing += has_second ? 0u : 1u;
    if (missing != 0u) {
        if (msg->attr_count > SIZE_MAX - missing ||
            msg->attr_count + missing > SIZE_MAX / sizeof(msg->attrs[0])) {
            return LIBBGP_ERR_BAD_LEN;
        }
        next = (libbgp_pattr_t **)bgp_realloc(
            msg->attrs,
            (msg->attr_count + missing) * sizeof(msg->attrs[0]));
        if (next == NULL) {
            return LIBBGP_ERR_NOMEM;
        }
        msg->attrs = next;
    }
    if (has_first) {
        libbgp_pattr_unref(msg->attrs[first_index]);
        msg->attrs[first_index] = libbgp_pattr_ref(first);
    } else {
        msg->attrs[msg->attr_count] = libbgp_pattr_ref(first);
        msg->attr_count++;
    }
    if (has_second) {
        libbgp_pattr_unref(msg->attrs[second_index]);
        msg->attrs[second_index] = libbgp_pattr_ref(second);
    } else {
        msg->attrs[msg->attr_count] = libbgp_pattr_ref(second);
        msg->attr_count++;
    }
    return LIBBGP_OK;
}

static void update_free_as_path_segments(libbgp_as_path_segment_t *segments, size_t segment_count)
{
    size_t i;

    if (segments == NULL) {
        return;
    }
    for (i = 0u; i < segment_count; i++) {
        bgp_free(segments[i].asns);
    }
    bgp_free(segments);
}

static libbgp_err_t update_validate_as_path_data(
    const libbgp_pattr_t *path,
    bool enforce_asn_width,
    size_t *out_count)
{
    size_t total = 0u;
    size_t i;

    if (path == NULL ||
        (path->type != LIBBGP_PATTR_AS_PATH && path->type != LIBBGP_PATTR_AS4_PATH)) {
        return LIBBGP_ERR_BAD_LEN;
    }
    if (path->type == LIBBGP_PATTR_AS4_PATH && !path->data.as_path.is_4b) {
        return LIBBGP_ERR_BAD_LEN;
    }
    if (path->data.as_path.segment_count != 0u && path->data.as_path.segments == NULL) {
        return LIBBGP_ERR_BAD_LEN;
    }
    for (i = 0u; i < path->data.as_path.segment_count; i++) {
        const libbgp_as_path_segment_t *seg = &path->data.as_path.segments[i];
        size_t j;

        if (seg->type < 1u || seg->type > 2u || seg->asn_count > 255u ||
            (seg->asn_count != 0u && seg->asns == NULL)) {
            return LIBBGP_ERR_BAD_LEN;
        }
        if (total > SIZE_MAX - seg->asn_count) {
            return LIBBGP_ERR_BAD_LEN;
        }
        if (enforce_asn_width && !path->data.as_path.is_4b) {
            for (j = 0u; j < seg->asn_count; j++) {
                if (seg->asns[j] > 65535u) {
                    return LIBBGP_ERR_BAD_LEN;
                }
            }
        }
        total += seg->asn_count;
    }
    if (out_count != NULL) {
        *out_count = total;
    }
    return LIBBGP_OK;
}

static libbgp_err_t update_copy_as_path_data(libbgp_pattr_t *dst, const libbgp_pattr_t *src, bool is_4b)
{
    size_t i;
    libbgp_err_t err;

    if (dst == NULL || (dst->type != LIBBGP_PATTR_AS_PATH && dst->type != LIBBGP_PATTR_AS4_PATH)) {
        return LIBBGP_ERR_BAD_LEN;
    }
    err = update_validate_as_path_data(src, false, NULL);
    if (err != LIBBGP_OK) {
        return err;
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

        dst_seg->type = src_seg->type;
        dst_seg->asn_count = src_seg->asn_count;
        if (src_seg->asn_count == 0u) {
            continue;
        }
        if (src_seg->asn_count > SIZE_MAX / sizeof(dst_seg->asns[0])) {
            update_free_as_path_segments(dst->data.as_path.segments, dst->data.as_path.segment_count);
            dst->data.as_path.segments = NULL;
            dst->data.as_path.segment_count = 0u;
            return LIBBGP_ERR_BAD_LEN;
        }
        dst_seg->asns = (uint32_t *)bgp_malloc(src_seg->asn_count * sizeof(dst_seg->asns[0]));
        if (dst_seg->asns == NULL) {
            update_free_as_path_segments(dst->data.as_path.segments, dst->data.as_path.segment_count);
            dst->data.as_path.segments = NULL;
            dst->data.as_path.segment_count = 0u;
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

static libbgp_err_t update_clone_path_as_type(
    libbgp_pattr_t **out,
    libbgp_pattr_type_t type,
    const libbgp_pattr_t *src,
    bool is_4b)
{
    libbgp_pattr_t *clone;
    libbgp_err_t err;

    if (out == NULL || src == NULL) {
        return LIBBGP_ERR_BAD_LEN;
    }
    *out = NULL;
    clone = libbgp_pattr_new(type);
    if (clone == NULL) {
        return LIBBGP_ERR_NOMEM;
    }
    err = update_copy_as_path_data(clone, src, is_4b);
    if (err != LIBBGP_OK) {
        libbgp_pattr_unref(clone);
        return err;
    }
    *out = clone;
    return LIBBGP_OK;
}

static libbgp_err_t update_count_path_asns(const libbgp_pattr_t *path, size_t *out_count)
{
    if (out_count == NULL) {
        return LIBBGP_ERR_BAD_LEN;
    }
    return update_validate_as_path_data(path, false, out_count);
}

static libbgp_err_t update_rebuild_as_path_from_as4_suffix(
    libbgp_pattr_t *as_path,
    const libbgp_pattr_t *as4_path,
    size_t replace_start);
static bool update_as_path_has_as_trans_count(const libbgp_pattr_t *as_path, size_t expected_count);
static bool update_as_path_suffix_matches_as4(
    const libbgp_pattr_t *as_path,
    const libbgp_pattr_t *as4_path,
    size_t start);
static libbgp_err_t update_restore_as_path_sparse(libbgp_pattr_t *as_path, const libbgp_pattr_t *as4_path);

libbgp_err_t libbgp_update_prepend_asn(libbgp_update_msg_t *msg, uint32_t asn, bool use_4b_asn)
{
    libbgp_pattr_t *as_path;
    libbgp_pattr_t *next_as_path = NULL;
    libbgp_pattr_t *next_as4_path = NULL;
    size_t original_as_path_count = 0u;
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
    if (as_path != NULL) {
        err = update_count_path_asns(as_path, &original_as_path_count);
        if (err != LIBBGP_OK) {
            return err;
        }
    }
    if (as_path == NULL) {
        next_as_path = libbgp_pattr_new(LIBBGP_PATTR_AS_PATH);
        if (next_as_path == NULL) {
            return LIBBGP_ERR_NOMEM;
        }
        next_as_path->data.as_path.is_4b = use_4b_asn;
    } else {
        err = update_clone_path_as_type(&next_as_path, LIBBGP_PATTR_AS_PATH, as_path, use_4b_asn);
        if (err != LIBBGP_OK) {
            return err;
        }
    }
    err = update_prepend_to_path(next_as_path, prep_asn);
    if (err != LIBBGP_OK) {
        libbgp_pattr_unref(next_as_path);
        return err;
    }

    if (!use_4b_asn && asn > 65535u) {
        libbgp_pattr_t *as4_path = libbgp_update_find_attr(msg, LIBBGP_PATTR_AS4_PATH);
        size_t as_path_count = 0u;
        size_t as4_count = 0u;

        err = update_count_path_asns(next_as_path, &as_path_count);
        if (err != LIBBGP_OK) {
            libbgp_pattr_unref(next_as_path);
            return err;
        }
        if (as4_path == NULL) {
            err = update_clone_path_as_type(&next_as4_path, LIBBGP_PATTR_AS4_PATH, next_as_path, true);
        } else {
            err = update_count_path_asns(as4_path, &as4_count);
            if (err == LIBBGP_OK && as4_count > original_as_path_count) {
                err = LIBBGP_ERR_INVALID;
            }
            if (err == LIBBGP_OK) {
                err = update_clone_path_as_type(&next_as4_path, LIBBGP_PATTR_AS4_PATH, next_as_path, true);
            }
            if (err == LIBBGP_OK) {
                err = update_rebuild_as_path_from_as4_suffix(next_as4_path, as4_path, as_path_count - as4_count);
            }
        }
        if (err != LIBBGP_OK) {
            libbgp_pattr_unref(next_as4_path);
            libbgp_pattr_unref(next_as_path);
            return err;
        }
        if (next_as4_path->data.as_path.segment_count != 0u &&
            next_as4_path->data.as_path.segments[0].asn_count != 0u) {
            next_as4_path->data.as_path.segments[0].asns[0] = asn;
        }
    }

    if (next_as4_path != NULL) {
        err = update_set_attr_pair(msg, next_as_path, next_as4_path);
    } else {
        err = update_set_attr(msg, next_as_path);
    }
    libbgp_pattr_unref(next_as4_path);
    libbgp_pattr_unref(next_as_path);
    return err;
}

static bool update_path_needs_as4_shadow(const libbgp_pattr_t *path)
{
    size_t i;

    if (path == NULL || path->data.as_path.segment_count == 0u) {
        return false;
    }
    for (i = 0u; i < path->data.as_path.segment_count; i++) {
        const libbgp_as_path_segment_t *seg = &path->data.as_path.segments[i];
        size_t j;

        for (j = 0u; j < seg->asn_count; j++) {
            if (seg->asns[j] > 65535u) {
                return true;
            }
        }
    }
    return false;
}

static libbgp_err_t update_first_as4_shadow_index(const libbgp_pattr_t *path, size_t *out_index)
{
    size_t pos = 0u;
    size_t i;

    if (path == NULL || out_index == NULL) {
        return LIBBGP_ERR_BAD_LEN;
    }
    for (i = 0u; i < path->data.as_path.segment_count; i++) {
        const libbgp_as_path_segment_t *seg = &path->data.as_path.segments[i];
        size_t j;

        if (seg->type < 1u || seg->type > 2u || seg->asn_count > 255u ||
            (seg->asn_count != 0u && seg->asns == NULL)) {
            return LIBBGP_ERR_BAD_LEN;
        }
        for (j = 0u; j < seg->asn_count; j++) {
            if (seg->asns[j] > 65535u) {
                *out_index = pos + j;
                return LIBBGP_OK;
            }
        }
        if (pos > SIZE_MAX - seg->asn_count) {
            return LIBBGP_ERR_BAD_LEN;
        }
        pos += seg->asn_count;
    }
    *out_index = pos;
    return LIBBGP_OK;
}

static libbgp_err_t update_copy_segment_prefix(
    libbgp_as_path_segment_t *dst,
    const libbgp_as_path_segment_t *src,
    size_t asn_count)
{
    if (dst == NULL || src == NULL || asn_count > src->asn_count || asn_count > 255u ||
        src->type < 1u || src->type > 2u || src->asn_count > 255u ||
        (asn_count != 0u && src->asns == NULL)) {
        return LIBBGP_ERR_BAD_LEN;
    }
    dst->type = src->type;
    dst->asn_count = asn_count;
    if (asn_count == 0u) {
        return LIBBGP_OK;
    }
    if (asn_count > SIZE_MAX / sizeof(dst->asns[0])) {
        return LIBBGP_ERR_BAD_LEN;
    }
    dst->asns = (uint32_t *)bgp_malloc(asn_count * sizeof(dst->asns[0]));
    if (dst->asns == NULL) {
        return LIBBGP_ERR_NOMEM;
    }
    memcpy(dst->asns, src->asns, asn_count * sizeof(dst->asns[0]));
    return LIBBGP_OK;
}

static libbgp_err_t update_clone_path_suffix_as_type(
    libbgp_pattr_t **out,
    libbgp_pattr_type_t type,
    const libbgp_pattr_t *src,
    bool is_4b,
    size_t start)
{
    libbgp_pattr_t *attr;
    libbgp_as_path_segment_t *segments = NULL;
    size_t src_count = 0u;
    size_t pos = 0u;
    size_t out_count = 0u;
    size_t out_pos = 0u;
    size_t i;
    libbgp_err_t err;

    if (out == NULL || src == NULL ||
        (type != LIBBGP_PATTR_AS_PATH && type != LIBBGP_PATTR_AS4_PATH)) {
        return LIBBGP_ERR_BAD_LEN;
    }
    *out = NULL;
    err = update_validate_as_path_data(src, false, &src_count);
    if (err != LIBBGP_OK) {
        return err;
    }
    if (start >= src_count) {
        return LIBBGP_ERR_INVALID;
    }
    for (i = 0u; i < src->data.as_path.segment_count; i++) {
        const libbgp_as_path_segment_t *seg = &src->data.as_path.segments[i];

        if (pos + seg->asn_count > start) {
            if (start > pos && seg->type == 1u) {
                return LIBBGP_ERR_INVALID;
            }
            out_count++;
        }
        pos += seg->asn_count;
    }
    attr = libbgp_pattr_new(type);
    if (attr == NULL) {
        return LIBBGP_ERR_NOMEM;
    }
    attr->data.as_path.is_4b = is_4b;
    attr->data.as_path.segment_count = out_count;
    if (out_count != 0u) {
        if (out_count > SIZE_MAX / sizeof(segments[0])) {
            libbgp_pattr_unref(attr);
            return LIBBGP_ERR_BAD_LEN;
        }
        segments = (libbgp_as_path_segment_t *)bgp_calloc(out_count, sizeof(segments[0]));
        if (segments == NULL) {
            libbgp_pattr_unref(attr);
            return LIBBGP_ERR_NOMEM;
        }
    }
    pos = 0u;
    for (i = 0u; i < src->data.as_path.segment_count; i++) {
        const libbgp_as_path_segment_t *seg = &src->data.as_path.segments[i];
        libbgp_as_path_segment_t tmp = *seg;
        size_t skip = start > pos ? start - pos : 0u;

        if (pos + seg->asn_count <= start) {
            pos += seg->asn_count;
            continue;
        }
        tmp.asn_count = seg->asn_count - skip;
        tmp.asns = seg->asns + skip;
        err = update_copy_segment_prefix(&segments[out_pos], &tmp, tmp.asn_count);
        if (err != LIBBGP_OK) {
            update_free_as_path_segments(segments, out_count);
            libbgp_pattr_unref(attr);
            return err;
        }
        out_pos++;
        pos += seg->asn_count;
    }
    attr->data.as_path.segments = segments;
    *out = attr;
    return LIBBGP_OK;
}

static bool update_as_path_has_as_trans_count(const libbgp_pattr_t *as_path, size_t expected_count)
{
    size_t trans_count = 0u;
    size_t i;

    if (as_path == NULL) {
        return false;
    }
    for (i = 0u; i < as_path->data.as_path.segment_count; i++) {
        const libbgp_as_path_segment_t *seg = &as_path->data.as_path.segments[i];
        size_t j;

        for (j = 0u; j < seg->asn_count; j++) {
            if (seg->asns[j] == LIBBGP_AS_TRANS) {
                trans_count++;
            }
        }
    }
    return trans_count == expected_count;
}

static bool update_as_path_suffix_matches_as4(
    const libbgp_pattr_t *as_path,
    const libbgp_pattr_t *as4_path,
    size_t start)
{
    size_t pos = 0u;
    size_t as4_seg_pos = 0u;
    size_t as4_asn_pos = 0u;
    size_t i;

    if (as_path == NULL || as4_path == NULL) {
        return false;
    }
    for (i = 0u; i < as_path->data.as_path.segment_count; i++) {
        const libbgp_as_path_segment_t *seg = &as_path->data.as_path.segments[i];
        size_t j;

        for (j = 0u; j < seg->asn_count; j++) {
            uint32_t as4_asn;

            if (pos < start) {
                pos++;
                continue;
            }
            while (as4_seg_pos < as4_path->data.as_path.segment_count &&
                   as4_asn_pos >= as4_path->data.as_path.segments[as4_seg_pos].asn_count) {
                as4_seg_pos++;
                as4_asn_pos = 0u;
            }
            if (as4_seg_pos >= as4_path->data.as_path.segment_count) {
                return false;
            }
            as4_asn = as4_path->data.as_path.segments[as4_seg_pos].asns[as4_asn_pos];
            if (seg->asns[j] != LIBBGP_AS_TRANS && seg->asns[j] != as4_asn) {
                return false;
            }
            as4_asn_pos++;
            pos++;
        }
    }
    while (as4_seg_pos < as4_path->data.as_path.segment_count &&
           as4_asn_pos >= as4_path->data.as_path.segments[as4_seg_pos].asn_count) {
        as4_seg_pos++;
        as4_asn_pos = 0u;
    }
    return as4_seg_pos == as4_path->data.as_path.segment_count;
}

static libbgp_err_t update_restore_as_path_sparse(libbgp_pattr_t *as_path, const libbgp_pattr_t *as4_path)
{
    size_t trans_count = 0u;
    size_t as4_count = 0u;
    size_t as4_seg_pos = 0u;
    size_t as4_asn_pos = 0u;
    size_t i;
    libbgp_err_t err;

    err = update_validate_as_path_data(as_path, false, NULL);
    if (err != LIBBGP_OK) {
        return err;
    }
    err = update_validate_as_path_data(as4_path, false, &as4_count);
    if (err != LIBBGP_OK) {
        return err;
    }
    for (i = 0u; i < as_path->data.as_path.segment_count; i++) {
        const libbgp_as_path_segment_t *seg = &as_path->data.as_path.segments[i];
        size_t j;

        for (j = 0u; j < seg->asn_count; j++) {
            if (seg->asns[j] == LIBBGP_AS_TRANS) {
                trans_count++;
            }
        }
    }
    if (trans_count != as4_count) {
        return LIBBGP_ERR_INVALID;
    }
    for (i = 0u; i < as_path->data.as_path.segment_count; i++) {
        libbgp_as_path_segment_t *seg = &as_path->data.as_path.segments[i];
        size_t j;

        for (j = 0u; j < seg->asn_count; j++) {
            if (seg->asns[j] == LIBBGP_AS_TRANS) {
                while (as4_seg_pos < as4_path->data.as_path.segment_count &&
                       as4_asn_pos >= as4_path->data.as_path.segments[as4_seg_pos].asn_count) {
                    as4_seg_pos++;
                    as4_asn_pos = 0u;
                }
                if (as4_seg_pos >= as4_path->data.as_path.segment_count) {
                    return LIBBGP_ERR_INVALID;
                }
                seg->asns[j] = as4_path->data.as_path.segments[as4_seg_pos].asns[as4_asn_pos];
                as4_asn_pos++;
            }
        }
    }
    as_path->data.as_path.is_4b = true;
    return LIBBGP_OK;
}

static libbgp_err_t update_rebuild_as_path_from_as4_suffix(
    libbgp_pattr_t *as_path,
    const libbgp_pattr_t *as4_path,
    size_t replace_start)
{
    libbgp_as_path_segment_t *segments = NULL;
    size_t prefix_segments = 0u;
    size_t prefix_count = 0u;
    size_t out_count;
    size_t pos = 0u;
    size_t out = 0u;
    size_t i;
    libbgp_err_t err;

    if (as_path == NULL || as4_path == NULL ||
        (as_path->type != LIBBGP_PATTR_AS_PATH && as_path->type != LIBBGP_PATTR_AS4_PATH) ||
        as4_path->type != LIBBGP_PATTR_AS4_PATH ||
        (as_path->data.as_path.segment_count != 0u && as_path->data.as_path.segments == NULL) ||
        (as4_path->data.as_path.segment_count != 0u && as4_path->data.as_path.segments == NULL)) {
        return LIBBGP_ERR_BAD_LEN;
    }
    for (i = 0u; i < as_path->data.as_path.segment_count; i++) {
        const libbgp_as_path_segment_t *seg = &as_path->data.as_path.segments[i];

        if (prefix_count >= replace_start) {
            break;
        }
        if (seg->type < 1u || seg->type > 2u ||
            (seg->asn_count != 0u && seg->asns == NULL)) {
            return LIBBGP_ERR_BAD_LEN;
        }
        if (prefix_count + seg->asn_count > replace_start && seg->type == 1u) {
            return LIBBGP_ERR_INVALID;
        }
        prefix_segments++;
        if (prefix_count > SIZE_MAX - seg->asn_count) {
            return LIBBGP_ERR_BAD_LEN;
        }
        prefix_count += seg->asn_count;
    }
    if (prefix_count != replace_start && prefix_segments == 0u) {
        return LIBBGP_ERR_BAD_LEN;
    }
    if (prefix_segments > SIZE_MAX - as4_path->data.as_path.segment_count) {
        return LIBBGP_ERR_BAD_LEN;
    }
    out_count = prefix_segments + as4_path->data.as_path.segment_count;
    if (out_count != 0u) {
        if (out_count > SIZE_MAX / sizeof(segments[0])) {
            return LIBBGP_ERR_BAD_LEN;
        }
        segments = (libbgp_as_path_segment_t *)bgp_calloc(out_count, sizeof(segments[0]));
        if (segments == NULL) {
            return LIBBGP_ERR_NOMEM;
        }
    }
    for (i = 0u; i < as_path->data.as_path.segment_count && pos < replace_start; i++) {
        const libbgp_as_path_segment_t *seg = &as_path->data.as_path.segments[i];
        size_t keep = seg->asn_count;

        if (pos + keep > replace_start) {
            keep = replace_start - pos;
        }
        if (keep != 0u) {
            err = update_copy_segment_prefix(&segments[out], seg, keep);
            if (err != LIBBGP_OK) {
                update_free_as_path_segments(segments, out_count);
                return err;
            }
            out++;
        }
        pos += seg->asn_count;
    }
    for (i = 0u; i < as4_path->data.as_path.segment_count; i++) {
        err = update_copy_segment_prefix(
            &segments[out],
            &as4_path->data.as_path.segments[i],
            as4_path->data.as_path.segments[i].asn_count);
        if (err != LIBBGP_OK) {
            update_free_as_path_segments(segments, out_count);
            return err;
        }
        out++;
    }
    update_free_as_path_segments(as_path->data.as_path.segments, as_path->data.as_path.segment_count);
    as_path->data.as_path.segments = segments;
    as_path->data.as_path.segment_count = out;
    as_path->data.as_path.is_4b = true;
    return LIBBGP_OK;
}

libbgp_err_t libbgp_update_restore_as_path(libbgp_update_msg_t *msg)
{
    libbgp_pattr_t *as_path;
    libbgp_pattr_t *as4_path;
    size_t as4_count = 0u;
    size_t as_path_count = 0u;
    size_t replace_start = 0u;
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
        err = update_validate_as_path_data(as_path, false, NULL);
        if (err != LIBBGP_OK) {
            return err;
        }
        as_path->data.as_path.is_4b = true;
        return LIBBGP_OK;
    }
    err = update_count_path_asns(as4_path, &as4_count);
    if (err != LIBBGP_OK) {
        return err;
    }
    err = update_count_path_asns(as_path, &as_path_count);
    if (err != LIBBGP_OK) {
        return err;
    }
    if (as4_count > as_path_count) {
        return LIBBGP_ERR_INVALID;
    }
    replace_start = as_path_count - as4_count;
    if (as4_count != as_path_count &&
        update_as_path_has_as_trans_count(as_path, as4_count) &&
        !update_as_path_suffix_matches_as4(as_path, as4_path, replace_start)) {
        err = update_restore_as_path_sparse(as_path, as4_path);
    } else {
        err = update_rebuild_as_path_from_as4_suffix(as_path, as4_path, replace_start);
    }
    if (err != LIBBGP_OK) {
        return err;
    }
    update_remove_attr_type(msg, LIBBGP_PATTR_AS4_PATH);
    return LIBBGP_OK;
}

libbgp_err_t libbgp_update_downgrade_as_path(libbgp_update_msg_t *msg)
{
    libbgp_pattr_t *as_path;
    libbgp_pattr_t *next_as_path = NULL;
    libbgp_pattr_t *next_as4_path = NULL;
    size_t i;
    libbgp_err_t err;

    if (msg == NULL) {
        return LIBBGP_ERR_BAD_LEN;
    }
    as_path = libbgp_update_find_attr(msg, LIBBGP_PATTR_AS_PATH);
    if (as_path == NULL || !as_path->data.as_path.is_4b) {
        return LIBBGP_OK;
    }
    err = update_validate_as_path_data(as_path, false, NULL);
    if (err != LIBBGP_OK) {
        return err;
    }
    err = update_clone_path_as_type(&next_as_path, LIBBGP_PATTR_AS_PATH, as_path, false);
    if (err != LIBBGP_OK) {
        return err;
    }
    if (update_path_needs_as4_shadow(as_path)) {
        size_t first_as4_index = 0u;
        size_t as_path_count = 0u;

        err = update_first_as4_shadow_index(as_path, &first_as4_index);
        if (err == LIBBGP_OK) {
            err = update_count_path_asns(as_path, &as_path_count);
        }
        if (err == LIBBGP_OK) {
            err = update_clone_path_suffix_as_type(
                &next_as4_path,
                LIBBGP_PATTR_AS4_PATH,
                as_path,
                true,
                first_as4_index);
        }
        if (err != LIBBGP_OK || first_as4_index >= as_path_count) {
            libbgp_pattr_unref(next_as4_path);
            libbgp_pattr_unref(next_as_path);
            return err == LIBBGP_OK ? LIBBGP_ERR_INVALID : err;
        }
    }
    for (i = 0u; i < next_as_path->data.as_path.segment_count; i++) {
        libbgp_as_path_segment_t *seg = &next_as_path->data.as_path.segments[i];
        size_t j;

        for (j = 0u; j < seg->asn_count; j++) {
            if (seg->asns[j] > 65535u) {
                seg->asns[j] = LIBBGP_AS_TRANS;
            }
        }
    }
    if (next_as4_path != NULL) {
        err = update_set_attr_pair(msg, next_as_path, next_as4_path);
    } else {
        err = update_set_attr(msg, next_as_path);
        if (err == LIBBGP_OK) {
            update_remove_attr_type(msg, LIBBGP_PATTR_AS4_PATH);
        }
    }
    libbgp_pattr_unref(next_as4_path);
    libbgp_pattr_unref(next_as_path);
    return err;
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
    size_t cap;

    if (count == NULL) {
        return LIBBGP_ERR_BAD_LEN;
    }
    cap = *count;

    while (pos < len) {
        libbgp_prefix4_t p;
        size_t used = 0u;
        libbgp_err_t err;

        err = libbgp_prefix4_parse(&p, buf + pos, len - pos, &used);
        if (err != LIBBGP_OK) {
            return err;
        }
        err = update_add_prefix(array, count, &cap, &p);
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
    size_t cap;

    if (tmp == NULL) {
        return LIBBGP_ERR_BAD_LEN;
    }
    cap = tmp->attr_count;

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
            err = update_add_attr_with_cap(tmp, attr, &cap);
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
    size_t i;
    size_t total = 0u;

    if (msg->attr_count != 0u && msg->attrs == NULL) {
        return LIBBGP_ERR_BAD_LEN;
    }
    for (i = 0u; i < msg->attr_count; i++) {
        size_t one = 0u;
        libbgp_err_t err = libbgp_pattr_wire_len(msg->attrs[i], &one);
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
