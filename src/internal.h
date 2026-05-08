#ifndef LIBBGP_INTERNAL_H
#define LIBBGP_INTERNAL_H

#include <stdint.h>
#include <string.h>
#include "libbgp/types.h"
#include "libbgp/alloc.h"

#define BGP_UNUSED(x) ((void)(x))

#define bgp_malloc(sz)      libbgp_malloc((sz))
#define bgp_calloc(n, sz)   libbgp_calloc((n), (sz))
#define bgp_realloc(p, sz)  libbgp_realloc((p), (sz))
#define bgp_free(p)         libbgp_free((p))

#ifdef BGP_THREADSAFE
#include <pthread.h>

typedef pthread_mutex_t bgp_lock_t;

static inline void bgp_lock_init(bgp_lock_t *lock)
{
    pthread_mutex_init(lock, NULL);
}

#define bgp_lock(lock) pthread_mutex_lock((lock))
#define bgp_unlock(lock) pthread_mutex_unlock((lock))
#define bgp_lock_destroy(lock) pthread_mutex_destroy((lock))

#else

typedef int bgp_lock_t;

#define bgp_lock_init(lock) ((void)(lock))
#define bgp_lock(lock) ((void)(lock))
#define bgp_unlock(lock) ((void)(lock))
#define bgp_lock_destroy(lock) ((void)(lock))

#endif

static inline uint16_t bgp_get_be16(const uint8_t *p)
{
    return (uint16_t)(((uint16_t)p[0] << 8) | p[1]);
}

static inline uint32_t bgp_get_be32(const uint8_t *p)
{
    return ((uint32_t)p[0] << 24) |
           ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8) |
           (uint32_t)p[3];
}

static inline void bgp_put_be16(uint8_t *p, uint16_t v)
{
    p[0] = (uint8_t)(v >> 8);
    p[1] = (uint8_t)v;
}

static inline void bgp_put_be32(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)(v >> 24);
    p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >> 8);
    p[3] = (uint8_t)v;
}

#endif
