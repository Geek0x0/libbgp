#ifndef LIBBGP_RADIX4_H
#define LIBBGP_RADIX4_H

#include <stddef.h>
#include <stdint.h>

#include "libbgp/types.h"

typedef struct bgp_radix4_node bgp_radix4_node_t;

typedef struct bgp_radix4 {
    bgp_radix4_node_t *root;
    size_t len;
} bgp_radix4_t;

libbgp_err_t bgp_radix4_init(bgp_radix4_t *tree);
void bgp_radix4_destroy(bgp_radix4_t *tree);
libbgp_err_t bgp_radix4_insert(bgp_radix4_t *tree, uint32_t addr, uint8_t prefix_len, void *value);
libbgp_err_t bgp_radix4_remove(bgp_radix4_t *tree, uint32_t addr, uint8_t prefix_len);
void *bgp_radix4_lookup_lpm(const bgp_radix4_t *tree, uint32_t addr);

#endif
