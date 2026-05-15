/**
 * @file rib6.h
 * @brief IPv6 routing information base with insert, withdraw, discard, and best-route lookup.
 * @ingroup libbgp_rib
 */

#ifndef LIBBGP_RIB6_H
#define LIBBGP_RIB6_H


/**
 * @file rib6.h
 * @brief IPv6 routing information base with insert, withdraw, discard, and best-route lookup.
 * @ingroup libbgp_rib
 */
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "libbgp/types.h"
#include "libbgp/prefix6.h"
#include "libbgp/pattr.h"

/**
 * @brief IPv6 route returned by lookup operations.
 */
typedef struct libbgp_rib6_route {
    libbgp_prefix6_t prefix;                ///< Destination prefix for this route.
    uint32_t source_router_id;              ///< BGP identifier of the peer that supplied this route.
    uint8_t next_hop[16];                   ///< Next-hop address for forwarding.
    uint8_t next_hop_linklocal[16];         ///< Optional link-local next-hop for forwarding.
    int32_t weight;                         ///< Local weight used before other best-path comparisons.
    bool is_ibgp;                           ///< True if route was learned via iBGP.
    uint32_t local_pref;                    ///< LOCAL_PREF value used for best-path selection.
    uint32_t med;                           ///< MULTI_EXIT_DISC (MED) attribute value.
    uint8_t origin;                         ///< ORIGIN attribute.
    size_t as_path_len;                     ///< Length of the retained AS_PATH attribute.
    uint32_t origin_as;                     ///< Origin AS if present.
    uint64_t update_id;                     ///< Internal update identifier for ordering.
    libbgp_pattr_t **attrs;                 ///< Optional path attributes (may include AS_PATH, COMMUNITY, etc.).
    size_t attr_count;                      ///< Number of entries in attrs.
} libbgp_rib6_route_t;

/**
 * @brief Opaque handle for an IPv6 RIB instance.
 *
 * @note Not thread-safe unless libbgp is built with `THREADSAFE=1`. In
 *       `THREADSAFE=1` builds, callers still need external synchronization if
 *       borrowed route pointers are kept while another thread may mutate the RIB.
 */
struct libbgp_rib6 {
    void *impl;
};

/**
 * @brief Initialize an empty IPv6 RIB.
 * @param[out] rib Pointer to an uninitialized libbgp_rib6_t to initialize.
 * @return `LIBBGP_OK` on success, `LIBBGP_ERR_INVALID` for invalid arguments,
 *         or `LIBBGP_ERR_NOMEM` if allocation fails.
 */
LIBBGP_API libbgp_err_t libbgp_rib6_init(libbgp_rib6_t *rib);

/**
 * @brief Destroy an IPv6 RIB and free all associated resources.
 * @param[in,out] rib Pointer to the RIB to destroy.
 */
LIBBGP_API void libbgp_rib6_destroy(libbgp_rib6_t *rib);

/**
 * @brief Insert a locally originated IPv6 route into the RIB.
 * @param[in,out] rib RIB handle.
 * @param[in] prefix Destination prefix to insert.
 * @param[in] next_hop IPv6 next-hop (network byte order).
 * @param[in] weight Local weight for the route.
 * @return `LIBBGP_OK` on success, `LIBBGP_ERR_INVALID` for invalid arguments,
 *         or `LIBBGP_ERR_NOMEM` if allocation fails.
 */
/* next_hop is an IPv6 address stored as 16 network-byte-order bytes. */
LIBBGP_API libbgp_err_t libbgp_rib6_insert_local(libbgp_rib6_t *rib, const libbgp_prefix6_t *prefix, const uint8_t next_hop[16], int32_t weight);

/**
 * @brief Insert or update an IPv6 route in the RIB.
 * @param[in,out] rib RIB handle.
 * @param[in] route Route object describing the route to insert.
 * @return `LIBBGP_OK` on success, `LIBBGP_ERR_INVALID` for invalid arguments,
 *         or `LIBBGP_ERR_NOMEM` if allocation fails.
 */
LIBBGP_API libbgp_err_t libbgp_rib6_insert(libbgp_rib6_t *rib, const libbgp_rib6_route_t *route);

/**
 * @brief Withdraw an IPv6 route originating from a particular peer.
 * @param[in,out] rib RIB handle.
 * @param[in] source_router_id BGP identifier of the peer (network byte order).
 * @param[in] prefix Destination prefix to withdraw.
 * @return `LIBBGP_OK` on success, `LIBBGP_ERR_INVALID` for invalid arguments,
 *         or `LIBBGP_ERR_NOMEM` if allocation fails.
 */
/* source_router_id is a BGP router ID stored as 4 network-byte-order bytes in a uint32_t. */
LIBBGP_API libbgp_err_t libbgp_rib6_withdraw(libbgp_rib6_t *rib, uint32_t source_router_id, const libbgp_prefix6_t *prefix);

/**
 * @brief Discard all IPv6 routes learned from a particular peer.
 * @param[in,out] rib RIB handle.
 * @param[in] source_router_id BGP identifier of the peer (network byte order).
 * @return `LIBBGP_OK` on success, `LIBBGP_ERR_INVALID` for invalid arguments,
 *         or `LIBBGP_ERR_NOMEM` if allocation fails.
 */
/* source_router_id is a BGP router ID stored as 4 network-byte-order bytes in a uint32_t. */
LIBBGP_API libbgp_err_t libbgp_rib6_discard(libbgp_rib6_t *rib, uint32_t source_router_id);

/**
 * @brief Find the best route for an IPv6 destination address.
 * @param[in] rib RIB handle.
 * @param[in] dest_addr Destination IPv6 address (network byte order).
 * @param[out] out_route On success receives a borrowed pointer to the matching route.
 * @note `out_route` receives a borrowed pointer owned by the RIB. The pointer
 *       remains valid only until the next mutating operation on the same RIB
 *       or until `libbgp_rib6_destroy()`.
 * @return `LIBBGP_OK` and a non-`NULL` route on match, `LIBBGP_ERR_NOT_FOUND`
 *         when no route matches, or `LIBBGP_ERR_INVALID` for invalid arguments.
 */
/*
 * dest_addr is an IPv6 address stored as 16 network-byte-order bytes.
 */
LIBBGP_API libbgp_err_t libbgp_rib6_lookup(const libbgp_rib6_t *rib, const uint8_t dest_addr[16], const libbgp_rib6_route_t **out_route);

/**
 * @brief Find the best route for an IPv6 destination address limited to routes
 *        from a specific source.
 * @param[in] rib RIB handle.
 * @param[in] source_router_id BGP identifier of the peer (network byte order).
 * @param[in] dest_addr Destination IPv6 address (network byte order).
 * @param[out] out_route On success receives a borrowed pointer to the matching route.
 * @note `out_route` receives a borrowed pointer owned by the RIB. The pointer
 *       remains valid only until the next mutating operation on the same RIB
 *       or until `libbgp_rib6_destroy()`.
 * @return `LIBBGP_OK` and a non-`NULL` route on match, `LIBBGP_ERR_NOT_FOUND`
 *         when no route matches, or `LIBBGP_ERR_INVALID` for invalid arguments.
 */
/*
 * source_router_id is stored as 4 network-byte-order bytes; dest_addr is stored
 * as 16 network-byte-order bytes.
 */
LIBBGP_API libbgp_err_t libbgp_rib6_lookup_scoped(const libbgp_rib6_t *rib, uint32_t source_router_id, const uint8_t dest_addr[16], const libbgp_rib6_route_t **out_route);

/**
 * @brief Return the number of routes stored in the RIB.
 * @param[in] rib RIB handle.
 * @return Number of routes.
 */
LIBBGP_API size_t libbgp_rib6_route_count(const libbgp_rib6_t *rib);

#endif
