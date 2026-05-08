#ifndef LIBBGP_UPDATE_H
#define LIBBGP_UPDATE_H

#include <stddef.h>
#include <stdint.h>

#include "libbgp/pattr.h"
#include "libbgp/prefix4.h"
#include "libbgp/types.h"

struct libbgp_update_msg {
    libbgp_prefix4_t *withdrawn;
    size_t withdrawn_count;
    libbgp_pattr_t **attrs;
    size_t attr_count;
    libbgp_prefix4_t *nlri;
    size_t nlri_count;
};

LIBBGP_API void libbgp_update_init(libbgp_update_msg_t *msg);
LIBBGP_API void libbgp_update_destroy(libbgp_update_msg_t *msg);
LIBBGP_API libbgp_err_t libbgp_update_add_withdrawn(libbgp_update_msg_t *msg, const libbgp_prefix4_t *p);
LIBBGP_API libbgp_err_t libbgp_update_add_attr(libbgp_update_msg_t *msg, libbgp_pattr_t *attr);
LIBBGP_API libbgp_err_t libbgp_update_add_nlri(libbgp_update_msg_t *msg, const libbgp_prefix4_t *p);
LIBBGP_API libbgp_pattr_t *libbgp_update_find_attr(const libbgp_update_msg_t *msg, libbgp_pattr_type_t type);

LIBBGP_API libbgp_err_t libbgp_update_parse(
    libbgp_update_msg_t *msg,
    const uint8_t *buf,
    size_t len,
    size_t *consumed);

LIBBGP_API libbgp_err_t libbgp_update_write(
    const libbgp_update_msg_t *msg,
    uint8_t *buf,
    size_t buf_len,
    size_t *out_len);

#endif
