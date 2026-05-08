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

#define bgp_vec_reserve(v, n) \
    (((n) <= (v)->cap || \
        ((v)->data = bgp_vec_reserve_impl((v)->data, &((v)->cap), \
            sizeof(*(v)->data), (n))) != NULL) ? \
        LIBBGP_OK : LIBBGP_ERR_NOMEM)

#define bgp_vec_push(v, value) \
    (bgp_vec_reserve((v), (v)->len + 1) == LIBBGP_OK ? \
        ((v)->data[(v)->len++] = (value), LIBBGP_OK) : LIBBGP_ERR_NOMEM)

static inline void *bgp_vec_reserve_impl(
    void *data,
    size_t *cap,
    size_t elem_size,
    size_t need)
{
    size_t new_cap;
    void *new_data;

    if (need <= *cap) {
        return data;
    }

    new_cap = *cap == 0 ? 4u : *cap;

    while (new_cap < need) {
        if (new_cap > ((size_t)-1) / 2u) {
            return NULL;
        }
        new_cap *= 2u;
    }

    if (elem_size != 0 && new_cap > ((size_t)-1) / elem_size) {
        return NULL;
    }

    new_data = bgp_realloc(data, new_cap * elem_size);
    if (new_data == NULL) {
        return NULL;
    }

    *cap = new_cap;
    return new_data;
}

#endif
