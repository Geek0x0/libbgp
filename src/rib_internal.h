#ifndef LIBBGP_RIB_INTERNAL_H
#define LIBBGP_RIB_INTERNAL_H

#include <stdbool.h>
#include <stdint.h>

#include "libbgp/rib4.h"
#include "libbgp/rib6.h"

typedef struct bgp_rib4_saved_route {
    void *entry;
} bgp_rib4_saved_route_t;

typedef struct bgp_rib6_saved_route {
    void *entry;
} bgp_rib6_saved_route_t;

typedef bool (*bgp_rib4_route_iter_fn)(const libbgp_rib4_route_t *route, void *ctx);
typedef bool (*bgp_rib6_route_iter_fn)(const libbgp_rib6_route_t *route, void *ctx);

typedef enum bgp_rib_change_kind {
    BGP_RIB_CHANGE_NO_BEST_CHANGE = 0,
    BGP_RIB_CHANGE_NEW_BEST,
    BGP_RIB_CHANGE_REPLACEMENT_BEST,
    BGP_RIB_CHANGE_UNREACHABLE
} bgp_rib_change_kind_t;

typedef struct bgp_rib4_change {
    bgp_rib_change_kind_t kind;
    /* Borrowed from the RIB; follows public lookup/iterator lifetime and thread-safety rules. */
    const libbgp_rib4_route_t *best;
} bgp_rib4_change_t;

typedef struct bgp_rib6_change {
    bgp_rib_change_kind_t kind;
    /* Borrowed from the RIB; follows public lookup/iterator lifetime and thread-safety rules. */
    const libbgp_rib6_route_t *best;
} bgp_rib6_change_t;

libbgp_err_t bgp_rib4_insert_track_best(
    libbgp_rib4_t *rib,
    const libbgp_rib4_route_t *route,
    bgp_rib4_change_t *change,
    uint64_t *update_id);
libbgp_err_t bgp_rib4_insert_track_best_save_replaced(
    libbgp_rib4_t *rib,
    const libbgp_rib4_route_t *route,
    bgp_rib4_change_t *change,
    uint64_t *update_id,
    bgp_rib4_saved_route_t *replaced,
    bool *had_replaced,
    libbgp_rib4_route_t *best_snapshot);
libbgp_err_t bgp_rib6_insert_track_best(
    libbgp_rib6_t *rib,
    const libbgp_rib6_route_t *route,
    bgp_rib6_change_t *change,
    uint64_t *update_id);
libbgp_err_t bgp_rib6_insert_track_best_save_replaced(
    libbgp_rib6_t *rib,
    const libbgp_rib6_route_t *route,
    bgp_rib6_change_t *change,
    uint64_t *update_id,
    bgp_rib6_saved_route_t *replaced,
    bool *had_replaced,
    libbgp_rib6_route_t *best_snapshot);

libbgp_err_t bgp_rib4_withdraw_track_best(
    libbgp_rib4_t *rib,
    uint32_t source_router_id,
    const libbgp_prefix4_t *prefix,
    bgp_rib4_change_t *change);
libbgp_err_t bgp_rib4_withdraw_track_best_save(
    libbgp_rib4_t *rib,
    uint32_t source_router_id,
    const libbgp_prefix4_t *prefix,
    bgp_rib4_change_t *change,
    bgp_rib4_saved_route_t *saved,
    bool *had_route,
    libbgp_rib4_route_t *best_snapshot);
libbgp_err_t bgp_rib6_withdraw_track_best(
    libbgp_rib6_t *rib,
    uint32_t source_router_id,
    const libbgp_prefix6_t *prefix,
    bgp_rib6_change_t *change);
libbgp_err_t bgp_rib6_withdraw_track_best_save(
    libbgp_rib6_t *rib,
    uint32_t source_router_id,
    const libbgp_prefix6_t *prefix,
    bgp_rib6_change_t *change,
    bgp_rib6_saved_route_t *saved,
    bool *had_route,
    libbgp_rib6_route_t *best_snapshot);

typedef struct bgp_rib4_discard_result {
    libbgp_prefix4_t *withdrawn;
    size_t withdrawn_count;
    libbgp_rib4_route_t *replacements;
    size_t replacement_count;
} bgp_rib4_discard_result_t;

typedef struct bgp_rib6_discard_result {
    libbgp_prefix6_t *withdrawn;
    size_t withdrawn_count;
    libbgp_rib6_route_t *replacements;
    size_t replacement_count;
} bgp_rib6_discard_result_t;

libbgp_err_t bgp_rib4_route_snapshot_clone(
    const libbgp_rib4_route_t *src,
    libbgp_rib4_route_t *dst);
libbgp_err_t bgp_rib6_route_snapshot_clone(
    const libbgp_rib6_route_t *src,
    libbgp_rib6_route_t *dst);
void bgp_rib4_route_snapshot_destroy(libbgp_rib4_route_t *route);
void bgp_rib6_route_snapshot_destroy(libbgp_rib6_route_t *route);
void bgp_rib4_saved_route_destroy(bgp_rib4_saved_route_t *saved);
void bgp_rib6_saved_route_destroy(bgp_rib6_saved_route_t *saved);
void bgp_rib4_discard_result_destroy(bgp_rib4_discard_result_t *result);
void bgp_rib6_discard_result_destroy(bgp_rib6_discard_result_t *result);

libbgp_err_t bgp_rib4_best_exact_clone(
    libbgp_rib4_t *rib,
    const libbgp_prefix4_t *prefix,
    libbgp_rib4_route_t *out_route,
    bool *found);
libbgp_err_t bgp_rib6_best_exact_clone(
    libbgp_rib6_t *rib,
    const libbgp_prefix6_t *prefix,
    libbgp_rib6_route_t *out_route,
    bool *found);

libbgp_err_t bgp_rib4_saved_route_update_id(
    const bgp_rib4_saved_route_t *saved,
    uint64_t *update_id);
libbgp_err_t bgp_rib6_saved_route_update_id(
    const bgp_rib6_saved_route_t *saved,
    uint64_t *update_id);

libbgp_err_t bgp_rib4_exact_update_id(
    libbgp_rib4_t *rib,
    uint32_t source_router_id,
    const libbgp_prefix4_t *prefix,
    uint64_t *update_id);
libbgp_err_t bgp_rib6_exact_update_id(
    libbgp_rib6_t *rib,
    uint32_t source_router_id,
    const libbgp_prefix6_t *prefix,
    uint64_t *update_id);

libbgp_err_t bgp_rib4_insert_save_replaced(
    libbgp_rib4_t *rib,
    const libbgp_rib4_route_t *route,
    bgp_rib4_saved_route_t *replaced,
    bool *had_replaced,
    uint64_t *update_id);
libbgp_err_t bgp_rib6_insert_save_replaced(
    libbgp_rib6_t *rib,
    const libbgp_rib6_route_t *route,
    bgp_rib6_saved_route_t *replaced,
    bool *had_replaced,
    uint64_t *update_id);

libbgp_err_t bgp_rib4_withdraw_exact_if_update_id(
    libbgp_rib4_t *rib,
    uint32_t source_router_id,
    const libbgp_prefix4_t *prefix,
    uint64_t update_id);
libbgp_err_t bgp_rib6_withdraw_exact_if_update_id(
    libbgp_rib6_t *rib,
    uint32_t source_router_id,
    const libbgp_prefix6_t *prefix,
    uint64_t update_id);

libbgp_err_t bgp_rib4_withdraw_exact_save(
    libbgp_rib4_t *rib,
    uint32_t source_router_id,
    const libbgp_prefix4_t *prefix,
    bgp_rib4_saved_route_t *saved,
    bool *had_route);
libbgp_err_t bgp_rib6_withdraw_exact_save(
    libbgp_rib6_t *rib,
    uint32_t source_router_id,
    const libbgp_prefix6_t *prefix,
    bgp_rib6_saved_route_t *saved,
    bool *had_route);

libbgp_err_t bgp_rib4_restore_saved_if_absent(
    libbgp_rib4_t *rib,
    uint32_t source_router_id,
    bgp_rib4_saved_route_t *saved);
libbgp_err_t bgp_rib6_restore_saved_if_absent(
    libbgp_rib6_t *rib,
    uint32_t source_router_id,
    bgp_rib6_saved_route_t *saved);

libbgp_err_t bgp_rib4_foreach_route(
    const libbgp_rib4_t *rib,
    bgp_rib4_route_iter_fn fn,
    void *ctx);
libbgp_err_t bgp_rib6_foreach_route(
    const libbgp_rib6_t *rib,
    bgp_rib6_route_iter_fn fn,
    void *ctx);
libbgp_err_t bgp_rib4_foreach_best_route(
    const libbgp_rib4_t *rib,
    bgp_rib4_route_iter_fn fn,
    void *ctx);
libbgp_err_t bgp_rib6_foreach_best_route(
    const libbgp_rib6_t *rib,
    bgp_rib6_route_iter_fn fn,
    void *ctx);

libbgp_err_t bgp_rib4_discard_collect(
    libbgp_rib4_t *rib,
    uint32_t source_router_id,
    bgp_rib4_discard_result_t *result);
libbgp_err_t bgp_rib6_discard_collect(
    libbgp_rib6_t *rib,
    uint32_t source_router_id,
    bgp_rib6_discard_result_t *result);

#endif
