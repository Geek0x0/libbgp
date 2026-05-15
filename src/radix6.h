#ifndef LIBBGP_RADIX6_H
#define LIBBGP_RADIX6_H


/**
 * @file radix6.h
 * @brief Internal IPv6 radix tree for longest-prefix match lookups.
 */
#include <stddef.h>
#include <stdint.h>

#include "libbgp/types.h"

typedef struct bgp_radix6_node bgp_radix6_node_t;

typedef struct bgp_radix6 {
    bgp_radix6_node_t *root;
    size_t len;
} bgp_radix6_t;

libbgp_err_t bgp_radix6_init(bgp_radix6_t *tree);
void bgp_radix6_destroy(bgp_radix6_t *tree);
libbgp_err_t bgp_radix6_insert(
    bgp_radix6_t *tree,
    const uint8_t addr[16],
    uint8_t prefix_len,
    void *value);
libbgp_err_t bgp_radix6_remove(bgp_radix6_t *tree, const uint8_t addr[16], uint8_t prefix_len);
void *bgp_radix6_lookup_lpm(const bgp_radix6_t *tree, const uint8_t addr[16]);

#endif
