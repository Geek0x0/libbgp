#ifndef LIBBGP_INTERNAL_H
#define LIBBGP_INTERNAL_H


/**
 * @file internal.h
 * @brief Internal allocation, locking, byte-order, and parser detail helpers.
 */
#include <stdint.h>
#include <string.h>
#include "libbgp/types.h"
#include "libbgp/alloc.h"
#include "libbgp/event.h"
#include "libbgp/packet.h"

#define BGP_UNUSED(x) ((void)(x))

typedef bool (*bgp_event_ctx_retain_fn)(void *ctx);
typedef void (*bgp_event_ctx_release_fn)(void *ctx);

typedef struct bgp_parse_error_detail {
    libbgp_err_t err;
    uint8_t notify_code;
    uint8_t notify_subcode;
} bgp_parse_error_detail_t;

libbgp_err_t bgp_event_bus_subscribe_retained(
    libbgp_event_bus_t *bus,
    libbgp_event_type_t type,
    libbgp_event_cb cb,
    void *ctx,
    bgp_event_ctx_retain_fn retain,
    bgp_event_ctx_release_fn release,
    uint64_t *out_id);

libbgp_err_t bgp_packet_parse_as4_detail(
    libbgp_packet_t *pkt,
    const uint8_t *buf,
    size_t len,
    bool use_4b_asn,
    size_t *consumed,
    bgp_parse_error_detail_t *detail);

void bgp_as_path_segments_free(
    libbgp_as_path_segment_t *segments,
    size_t segment_count);

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
