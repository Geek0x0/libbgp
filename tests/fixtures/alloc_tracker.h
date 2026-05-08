#ifndef LIBBGP_TEST_ALLOC_TRACKER_H
#define LIBBGP_TEST_ALLOC_TRACKER_H

#include <stddef.h>
#include "libbgp/alloc.h"

typedef struct libbgp_alloc_tracker {
    size_t malloc_calls;
    size_t calloc_calls;
    size_t realloc_calls;
    size_t free_calls;
    size_t bytes_requested;
    void *last_ctx;
} libbgp_alloc_tracker_t;

void libbgp_alloc_tracker_init(libbgp_alloc_tracker_t *tracker);
libbgp_alloc_t libbgp_alloc_tracker_make(libbgp_alloc_tracker_t *tracker);

#endif
