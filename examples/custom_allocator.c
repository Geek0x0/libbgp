#include <libbgp/libbgp.h>

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

typedef struct alloc_counts {
    size_t malloc_calls;
    size_t calloc_calls;
    size_t realloc_calls;
    size_t free_calls;
} alloc_counts_t;

static void *count_malloc(size_t size, void *ctx)
{
    alloc_counts_t *counts = (alloc_counts_t *)ctx;

    counts->malloc_calls++;
    return malloc(size);
}

static void *count_calloc(size_t nmemb, size_t size, void *ctx)
{
    alloc_counts_t *counts = (alloc_counts_t *)ctx;

    counts->calloc_calls++;
    return calloc(nmemb, size);
}

static void *count_realloc(void *ptr, size_t size, void *ctx)
{
    alloc_counts_t *counts = (alloc_counts_t *)ctx;

    counts->realloc_calls++;
    return realloc(ptr, size);
}

static void count_free(void *ptr, void *ctx)
{
    alloc_counts_t *counts = (alloc_counts_t *)ctx;

    counts->free_calls++;
    free(ptr);
}

int main(void)
{
    alloc_counts_t counts = { 0u, 0u, 0u, 0u };
    libbgp_alloc_t alloc;
    libbgp_pattr_t *origin;
    libbgp_pattr_t *community;

    alloc.malloc = count_malloc;
    alloc.calloc = count_calloc;
    alloc.realloc = count_realloc;
    alloc.free = count_free;
    alloc.ctx = &counts;

    libbgp_set_alloc(&alloc);
    origin = libbgp_pattr_new(LIBBGP_PATTR_ORIGIN);
    community = libbgp_pattr_new(LIBBGP_PATTR_COMMUNITY);
    if (origin == NULL || community == NULL) {
        libbgp_pattr_unref(origin);
        libbgp_pattr_unref(community);
        libbgp_set_alloc(&libbgp_default_alloc);
        fprintf(stderr, "allocation failed\n");
        return 1;
    }
    origin->data.origin.origin = 0u;
    community->data.community.values =
        (uint32_t *)libbgp_calloc(1u, sizeof(*community->data.community.values));
    if (community->data.community.values == NULL) {
        libbgp_pattr_unref(origin);
        libbgp_pattr_unref(community);
        libbgp_set_alloc(&libbgp_default_alloc);
        fprintf(stderr, "community allocation failed\n");
        return 1;
    }
    community->data.community.values[0] = (64512u << 16u) | 100u;
    community->data.community.count = 1u;

    libbgp_pattr_unref(origin);
    libbgp_pattr_unref(community);
    libbgp_set_alloc(&libbgp_default_alloc);

    printf("allocator calls: malloc=%zu calloc=%zu realloc=%zu free=%zu\n",
        counts.malloc_calls,
        counts.calloc_calls,
        counts.realloc_calls,
        counts.free_calls);
    return 0;
}
