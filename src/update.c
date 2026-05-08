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

    if (msg == NULL || attr == NULL) {
        return LIBBGP_ERR_BAD_LEN;
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
    size_t i;

    if (msg == NULL) {
        return NULL;
    }
    for (i = 0u; i < msg->attr_count; i++) {
        if (msg->attrs[i] != NULL && msg->attrs[i]->type == type) {
            return msg->attrs[i];
        }
    }
    return NULL;
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
    size_t len)
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
        err = libbgp_pattr_parse(attr, buf + pos, len - pos, &used);
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

libbgp_err_t libbgp_update_parse(
    libbgp_update_msg_t *msg,
    const uint8_t *buf,
    size_t len,
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
    err = update_parse_attrs(&tmp, buf + pos, attr_len);
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

    libbgp_update_destroy(msg);
    *msg = tmp;
    if (consumed != NULL) {
        *consumed = len;
    }
    return LIBBGP_OK;
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
