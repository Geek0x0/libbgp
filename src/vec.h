#ifndef LIBBGP_VEC_H
#define LIBBGP_VEC_H

#include <stddef.h>
#include "internal.h"

#define bgp_vec_t(T) struct { T *data; size_t len; size_t cap; }

#define bgp_vec_init(v) do { \
    (v)->data = NULL; \
    (v)->len = 0; \
    (v)->cap = 0; \
} while (0)

#define bgp_vec_free(v) do { \
    bgp_free((v)->data); \
    (v)->data = NULL; \
    (v)->len = 0; \
    (v)->cap = 0; \
} while (0)

#define bgp_vec_reserve(v, n, out_err) do { \
    void *bgp_vec_reserve_data__; \
    size_t bgp_vec_reserve_cap__; \
    libbgp_err_t bgp_vec_reserve_err__; \
    bgp_vec_reserve_err__ = bgp_vec_reserve_impl( \
        (v)->data, (v)->cap, sizeof(*(v)->data), (n), \
        &bgp_vec_reserve_data__, &bgp_vec_reserve_cap__); \
    if (bgp_vec_reserve_err__ == LIBBGP_OK) { \
        (v)->data = bgp_vec_reserve_data__; \
        (v)->cap = bgp_vec_reserve_cap__; \
    } \
    *(out_err) = bgp_vec_reserve_err__; \
} while (0)

#define bgp_vec_push(v, value, out_err) do { \
    libbgp_err_t bgp_vec_push_err__; \
    bgp_vec_reserve((v), (v)->len + 1, &bgp_vec_push_err__); \
    if (bgp_vec_push_err__ == LIBBGP_OK) { \
        (v)->data[(v)->len++] = (value); \
    } \
    *(out_err) = bgp_vec_push_err__; \
} while (0)

static inline libbgp_err_t bgp_vec_reserve_impl(
    void *old_data,
    size_t old_cap,
    size_t elem_size,
    size_t need,
    void **new_data_out,
    size_t *new_cap_out)
{
    size_t new_cap;
    void *new_data;

    if (need <= old_cap) {
        *new_data_out = old_data;
        *new_cap_out = old_cap;
        return LIBBGP_OK;
    }

    new_cap = old_cap == 0 ? 4u : old_cap;

    while (new_cap < need) {
        if (new_cap > ((size_t)-1) / 2u) {
            return LIBBGP_ERR_NOMEM;
        }
        new_cap *= 2u;
    }

    if (elem_size != 0 && new_cap > ((size_t)-1) / elem_size) {
        return LIBBGP_ERR_NOMEM;
    }

    new_data = bgp_realloc(old_data, new_cap * elem_size);
    if (new_data == NULL) {
        return LIBBGP_ERR_NOMEM;
    }

    *new_data_out = new_data;
    *new_cap_out = new_cap;
    return LIBBGP_OK;
}

#endif
