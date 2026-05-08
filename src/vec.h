#ifndef LIBBGP_VEC_H
#define LIBBGP_VEC_H

#include <stddef.h>
#include "internal.h"

#define bgp_vec_t(T) struct { T *data; size_t len; size_t cap; }

typedef struct bgp_vec_reserve_result {
    libbgp_err_t err;
    void *data;
    size_t cap;
} bgp_vec_reserve_result_t;

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
    bgp_vec_reserve_result_t bgp_vec_reserve_result__; \
    bgp_vec_reserve_result__ = bgp_vec_reserve_impl( \
        (v)->data, (v)->cap, sizeof(*(v)->data), (n)); \
    if (bgp_vec_reserve_result__.err == LIBBGP_OK) { \
        (v)->data = bgp_vec_reserve_result__.data; \
        (v)->cap = bgp_vec_reserve_result__.cap; \
    } \
    *(out_err) = bgp_vec_reserve_result__.err; \
} while (0)

#define bgp_vec_push(v, value, out_err) do { \
    libbgp_err_t bgp_vec_push_err__; \
    bgp_vec_reserve((v), (v)->len + 1, &bgp_vec_push_err__); \
    if (bgp_vec_push_err__ == LIBBGP_OK) { \
        (v)->data[(v)->len++] = (value); \
    } \
    *(out_err) = bgp_vec_push_err__; \
} while (0)

static inline bgp_vec_reserve_result_t bgp_vec_reserve_impl(
    void *old_data,
    size_t old_cap,
    size_t elem_size,
    size_t need)
{
    bgp_vec_reserve_result_t result;
    size_t new_cap;
    void *new_data;

    result.err = LIBBGP_ERR_NOMEM;
    result.data = old_data;
    result.cap = old_cap;

    if (need <= old_cap) {
        result.err = LIBBGP_OK;
        return result;
    }

    new_cap = old_cap == 0 ? 4u : old_cap;

    while (new_cap < need) {
        if (new_cap > ((size_t)-1) / 2u) {
            return result;
        }
        new_cap *= 2u;
    }

    if (elem_size != 0 && new_cap > ((size_t)-1) / elem_size) {
        return result;
    }

    new_data = bgp_realloc(old_data, new_cap * elem_size);
    if (new_data == NULL) {
        return result;
    }

    result.err = LIBBGP_OK;
    result.data = new_data;
    result.cap = new_cap;
    return result;
}

#endif
