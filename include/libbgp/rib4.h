#ifndef LIBBGP_RIB4_H
#define LIBBGP_RIB4_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "libbgp/types.h"
#include "libbgp/prefix4.h"
#include "libbgp/pattr.h"

typedef struct libbgp_rib4_route {
    libbgp_prefix4_t prefix;
    uint32_t source_router_id;
    uint32_t next_hop;
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
} libbgp_rib4_route_t;

struct libbgp_rib4 {
    void *impl;
};

LIBBGP_API libbgp_err_t libbgp_rib4_init(libbgp_rib4_t *rib);
LIBBGP_API void libbgp_rib4_destroy(libbgp_rib4_t *rib);
LIBBGP_API libbgp_err_t libbgp_rib4_insert_local(libbgp_rib4_t *rib, const libbgp_prefix4_t *prefix, uint32_t next_hop, int32_t weight);
LIBBGP_API libbgp_err_t libbgp_rib4_insert(libbgp_rib4_t *rib, const libbgp_rib4_route_t *route);
LIBBGP_API libbgp_err_t libbgp_rib4_withdraw(libbgp_rib4_t *rib, uint32_t source_router_id, const libbgp_prefix4_t *prefix);
LIBBGP_API libbgp_err_t libbgp_rib4_discard(libbgp_rib4_t *rib, uint32_t source_router_id);
LIBBGP_API libbgp_err_t libbgp_rib4_lookup(const libbgp_rib4_t *rib, uint32_t dest_addr, const libbgp_rib4_route_t **out_route);
LIBBGP_API libbgp_err_t libbgp_rib4_lookup_scoped(const libbgp_rib4_t *rib, uint32_t source_router_id, uint32_t dest_addr, const libbgp_rib4_route_t **out_route);
LIBBGP_API size_t libbgp_rib4_route_count(const libbgp_rib4_t *rib);

#endif
