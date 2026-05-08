#ifndef LIBBGP_RIB6_H
#define LIBBGP_RIB6_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "libbgp/types.h"
#include "libbgp/prefix6.h"
#include "libbgp/pattr.h"

typedef struct libbgp_rib6_route {
    libbgp_prefix6_t prefix;
    uint32_t source_router_id;
    uint8_t next_hop[16];
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
LIBBGP_API libbgp_err_t libbgp_rib6_insert_local(libbgp_rib6_t *rib, const libbgp_prefix6_t *prefix, const uint8_t next_hop[16], int32_t weight);
LIBBGP_API libbgp_err_t libbgp_rib6_insert(libbgp_rib6_t *rib, const libbgp_rib6_route_t *route);
LIBBGP_API libbgp_err_t libbgp_rib6_withdraw(libbgp_rib6_t *rib, uint32_t source_router_id, const libbgp_prefix6_t *prefix);
LIBBGP_API libbgp_err_t libbgp_rib6_discard(libbgp_rib6_t *rib, uint32_t source_router_id);
LIBBGP_API libbgp_err_t libbgp_rib6_lookup(const libbgp_rib6_t *rib, const uint8_t dest_addr[16], const libbgp_rib6_route_t **out_route);
LIBBGP_API libbgp_err_t libbgp_rib6_lookup_scoped(const libbgp_rib6_t *rib, uint32_t source_router_id, const uint8_t dest_addr[16], const libbgp_rib6_route_t **out_route);
LIBBGP_API size_t libbgp_rib6_route_count(const libbgp_rib6_t *rib);

#endif
