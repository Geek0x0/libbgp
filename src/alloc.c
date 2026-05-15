/**
 * @file alloc.c
 * @brief Global allocator hook implementation.
 */
#include <stdatomic.h>
#include <stdlib.h>
#include "libbgp/alloc.h"

static void *def_malloc(size_t size, void *ctx)
{
    (void)ctx;
    return malloc(size);
}

static void *def_calloc(size_t nmemb, size_t size, void *ctx)
{
    (void)ctx;
    return calloc(nmemb, size);
}

static void *def_realloc(void *ptr, size_t size, void *ctx)
{
    (void)ctx;
    return realloc(ptr, size);
}

static void def_free(void *ptr, void *ctx)
{
    (void)ctx;
    free(ptr);
}

const libbgp_alloc_t libbgp_default_alloc = {
    def_malloc,
    def_calloc,
    def_realloc,
    def_free,
    NULL
};

static _Atomic(const libbgp_alloc_t *) g_alloc = &libbgp_default_alloc;

void libbgp_set_alloc(const libbgp_alloc_t *alloc)
{
    atomic_store_explicit(
        &g_alloc,
        alloc ? alloc : &libbgp_default_alloc,
        memory_order_release);
}

const libbgp_alloc_t *libbgp_get_alloc(void)
{
    return atomic_load_explicit(&g_alloc, memory_order_acquire);
}

void *libbgp_malloc(size_t size)
{
    const libbgp_alloc_t *a = libbgp_get_alloc();
    return a->malloc(size, a->ctx);
}

void *libbgp_calloc(size_t nmemb, size_t size)
{
    const libbgp_alloc_t *a = libbgp_get_alloc();
    return a->calloc(nmemb, size, a->ctx);
}

void *libbgp_realloc(void *ptr, size_t size)
{
    const libbgp_alloc_t *a = libbgp_get_alloc();
    return a->realloc(ptr, size, a->ctx);
}

void libbgp_free(void *ptr)
{
    const libbgp_alloc_t *a = libbgp_get_alloc();
    a->free(ptr, a->ctx);
}
