#ifndef LIBBGP_RIB6_H
#define LIBBGP_RIB6_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "libbgp/types.h"
#include "libbgp/prefix6.h"
#include "libbgp/pattr.h"

/*
 * Route objects returned by lookup functions are borrowed internal pointers.
 * They remain valid until the next mutating operation on the same RIB
 * (insert, insert_local, withdraw, discard, destroy) or until destroy.
 * With THREADSAFE=1, callers that need pointer stability across concurrent
 * mutation must provide external synchronization; the internal lock protects
 * only the lookup operation itself.
 */
typedef struct libbgp_rib6_route {
    libbgp_prefix6_t prefix;
    /* BGP router ID stored as 4 network-byte-order bytes in a uint32_t. */
    uint32_t source_router_id;
    /* IPv6 next hop stored as 16 network-byte-order bytes. */
    uint8_t next_hop[16];
    /* Optional IPv6 link-local next hop; all zero when absent. */
    uint8_t next_hop_linklocal[16];
    int32_t weight;
    bool is_ibgp;
    uint32_t local_pref;
    uint32_t med;
    uint8_t origin;
    size_t as_path_len;
    uint32_t origin_as;
    uint64_t update_id;
    libbgp_pattr_t **attrs;
    size_t attr_count;
} libbgp_rib6_route_t;

struct libbgp_rib6 {
    void *impl;
};

LIBBGP_API libbgp_err_t libbgp_rib6_init(libbgp_rib6_t *rib);
LIBBGP_API void libbgp_rib6_destroy(libbgp_rib6_t *rib);
/* next_hop is an IPv6 address stored as 16 network-byte-order bytes. */
LIBBGP_API libbgp_err_t libbgp_rib6_insert_local(libbgp_rib6_t *rib, const libbgp_prefix6_t *prefix, const uint8_t next_hop[16], int32_t weight);
LIBBGP_API libbgp_err_t libbgp_rib6_insert(libbgp_rib6_t *rib, const libbgp_rib6_route_t *route);
/* source_router_id is a BGP router ID stored as 4 network-byte-order bytes in a uint32_t. */
LIBBGP_API libbgp_err_t libbgp_rib6_withdraw(libbgp_rib6_t *rib, uint32_t source_router_id, const libbgp_prefix6_t *prefix);
/* source_router_id is a BGP router ID stored as 4 network-byte-order bytes in a uint32_t. */
LIBBGP_API libbgp_err_t libbgp_rib6_discard(libbgp_rib6_t *rib, uint32_t source_router_id);
/*
 * On success, out_route receives a borrowed internal route pointer. The pointer
 * is invalidated by the next mutating operation on the same RIB or by destroy.
 * With THREADSAFE=1, external synchronization is required if another thread may
 * mutate the RIB while the caller still uses the borrowed pointer.
 * dest_addr is an IPv6 address stored as 16 network-byte-order bytes.
 */
LIBBGP_API libbgp_err_t libbgp_rib6_lookup(const libbgp_rib6_t *rib, const uint8_t dest_addr[16], const libbgp_rib6_route_t **out_route);
/*
 * Same borrowed-pointer lifetime and THREADSAFE=1 synchronization contract as
 * libbgp_rib6_lookup.
 * source_router_id is stored as 4 network-byte-order bytes; dest_addr is stored
 * as 16 network-byte-order bytes.
 */
LIBBGP_API libbgp_err_t libbgp_rib6_lookup_scoped(const libbgp_rib6_t *rib, uint32_t source_router_id, const uint8_t dest_addr[16], const libbgp_rib6_route_t **out_route);
LIBBGP_API size_t libbgp_rib6_route_count(const libbgp_rib6_t *rib);

#endif
