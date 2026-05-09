#ifndef LIBBGP_RIB_INTERNAL_H
#define LIBBGP_RIB_INTERNAL_H

#include <stdbool.h>
#include <stdint.h>

#include "libbgp/rib4.h"
#include "libbgp/rib6.h"

typedef struct libbgp_rib4_saved_route {
    void *entry;
} libbgp_rib4_saved_route_t;

typedef struct libbgp_rib6_saved_route {
    void *entry;
} libbgp_rib6_saved_route_t;

void libbgp_rib4_saved_route_destroy(libbgp_rib4_saved_route_t *saved);
void libbgp_rib6_saved_route_destroy(libbgp_rib6_saved_route_t *saved);

libbgp_err_t libbgp_rib4_exact_update_id(
    libbgp_rib4_t *rib,
    uint32_t source_router_id,
    const libbgp_prefix4_t *prefix,
    uint64_t *update_id);
libbgp_err_t libbgp_rib6_exact_update_id(
    libbgp_rib6_t *rib,
    uint32_t source_router_id,
    const libbgp_prefix6_t *prefix,
    uint64_t *update_id);

libbgp_err_t libbgp_rib4_insert_save_replaced(
    libbgp_rib4_t *rib,
    const libbgp_rib4_route_t *route,
    libbgp_rib4_saved_route_t *replaced,
    bool *had_replaced,
    uint64_t *update_id);
libbgp_err_t libbgp_rib6_insert_save_replaced(
    libbgp_rib6_t *rib,
    const libbgp_rib6_route_t *route,
    libbgp_rib6_saved_route_t *replaced,
    bool *had_replaced,
    uint64_t *update_id);

libbgp_err_t libbgp_rib4_withdraw_exact_if_update_id(
    libbgp_rib4_t *rib,
    uint32_t source_router_id,
    const libbgp_prefix4_t *prefix,
    uint64_t update_id);
libbgp_err_t libbgp_rib6_withdraw_exact_if_update_id(
    libbgp_rib6_t *rib,
    uint32_t source_router_id,
    const libbgp_prefix6_t *prefix,
    uint64_t update_id);

libbgp_err_t libbgp_rib4_withdraw_exact_save(
    libbgp_rib4_t *rib,
    uint32_t source_router_id,
    const libbgp_prefix4_t *prefix,
    libbgp_rib4_saved_route_t *saved,
    bool *had_route);
libbgp_err_t libbgp_rib6_withdraw_exact_save(
    libbgp_rib6_t *rib,
    uint32_t source_router_id,
    const libbgp_prefix6_t *prefix,
    libbgp_rib6_saved_route_t *saved,
    bool *had_route);

libbgp_err_t libbgp_rib4_restore_saved_if_absent(
    libbgp_rib4_t *rib,
    uint32_t source_router_id,
    libbgp_rib4_saved_route_t *saved);
libbgp_err_t libbgp_rib6_restore_saved_if_absent(
    libbgp_rib6_t *rib,
    uint32_t source_router_id,
    libbgp_rib6_saved_route_t *saved);

#endif
