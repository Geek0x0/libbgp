#include "alloc_tracker.h"

#include <stdlib.h>

static void *tracker_malloc(size_t size, void *ctx)
{
    libbgp_alloc_tracker_t *tracker = (libbgp_alloc_tracker_t *)ctx;

    tracker->malloc_calls++;
    tracker->bytes_requested += size;
    tracker->last_ctx = ctx;
    return malloc(size);
}

static void *tracker_calloc(size_t nmemb, size_t size, void *ctx)
{
    libbgp_alloc_tracker_t *tracker = (libbgp_alloc_tracker_t *)ctx;

    tracker->calloc_calls++;
    tracker->bytes_requested += nmemb * size;
    tracker->last_ctx = ctx;
    return calloc(nmemb, size);
}

static void *tracker_realloc(void *ptr, size_t size, void *ctx)
{
    libbgp_alloc_tracker_t *tracker = (libbgp_alloc_tracker_t *)ctx;

    tracker->realloc_calls++;
    tracker->bytes_requested += size;
    tracker->last_ctx = ctx;
    return realloc(ptr, size);
}

static void tracker_free(void *ptr, void *ctx)
{
    libbgp_alloc_tracker_t *tracker = (libbgp_alloc_tracker_t *)ctx;

    tracker->free_calls++;
    tracker->last_ctx = ctx;
    free(ptr);
}

void libbgp_alloc_tracker_init(libbgp_alloc_tracker_t *tracker)
{
    tracker->malloc_calls = 0;
    tracker->calloc_calls = 0;
    tracker->realloc_calls = 0;
    tracker->free_calls = 0;
    tracker->bytes_requested = 0;
    tracker->last_ctx = NULL;
}

libbgp_alloc_t libbgp_alloc_tracker_make(libbgp_alloc_tracker_t *tracker)
{
    libbgp_alloc_t alloc;

    alloc.malloc = tracker_malloc;
    alloc.calloc = tracker_calloc;
    alloc.realloc = tracker_realloc;
    alloc.free = tracker_free;
    alloc.ctx = tracker;
    return alloc;
}
