/**
 * @file radix6.c
 * @brief Internal IPv6 radix tree implementation.
 */
#include "radix6.h"

#include <stdbool.h>
#include <string.h>

#include "internal.h"

struct bgp_radix6_node {
    struct bgp_radix6_node *child[2];
    void *value;
    bool has_value;
};

static bgp_radix6_node_t *bgp_radix6_node_new(void)
{
    return (bgp_radix6_node_t *)bgp_calloc(1u, sizeof(bgp_radix6_node_t));
}

static void bgp_radix6_node_destroy(bgp_radix6_node_t *node)
{
    if (node == NULL) {
        return;
    }

    bgp_radix6_node_destroy(node->child[0]);
    bgp_radix6_node_destroy(node->child[1]);
    bgp_free(node);
}

static unsigned int bgp_radix6_bit(const uint8_t addr[16], uint8_t bit)
{
    return (unsigned int)((addr[bit / 8u] >> (7u - (bit % 8u))) & 1u);
}

static bool bgp_radix6_node_empty(const bgp_radix6_node_t *node)
{
    return node != NULL && !node->has_value && node->child[0] == NULL && node->child[1] == NULL;
}

libbgp_err_t bgp_radix6_init(bgp_radix6_t *tree)
{
    if (tree == NULL) {
        return LIBBGP_ERR_INVALID;
    }

    memset(tree, 0, sizeof(*tree));
    return LIBBGP_OK;
}

void bgp_radix6_destroy(bgp_radix6_t *tree)
{
    if (tree == NULL) {
        return;
    }

    bgp_radix6_node_destroy(tree->root);
    memset(tree, 0, sizeof(*tree));
}

libbgp_err_t bgp_radix6_insert(
    bgp_radix6_t *tree,
    const uint8_t addr[16],
    uint8_t prefix_len,
    void *value)
{
    bgp_radix6_node_t *path[129];
    unsigned int direction[128];
    bgp_radix6_node_t *node;
    uint8_t bit;

    if (tree == NULL || addr == NULL || prefix_len > 128u) {
        return LIBBGP_ERR_INVALID;
    }

    if (tree->root == NULL) {
        tree->root = bgp_radix6_node_new();
        if (tree->root == NULL) {
            return LIBBGP_ERR_NOMEM;
        }
    }

    node = tree->root;
    path[0] = node;
    for (bit = 0u; bit < prefix_len; bit++) {
        direction[bit] = bgp_radix6_bit(addr, bit);
        if (node->child[direction[bit]] == NULL) {
            node->child[direction[bit]] = bgp_radix6_node_new();
            if (node->child[direction[bit]] == NULL) {
                while (bit > 0u && bgp_radix6_node_empty(path[bit])) {
                    bgp_radix6_node_t *child = path[bit];
                    bgp_radix6_node_t *parent = path[(size_t)bit - 1u];
                    parent->child[direction[(size_t)bit - 1u]] = NULL;
                    bgp_free(child);
                    bit--;
                }
                if (bgp_radix6_node_empty(tree->root)) {
                    bgp_free(tree->root);
                    tree->root = NULL;
                }
                return LIBBGP_ERR_NOMEM;
            }
        }
        node = node->child[direction[bit]];
        path[(size_t)bit + 1u] = node;
    }

    if (!node->has_value) {
        tree->len++;
    }
    node->value = value;
    node->has_value = true;
    return LIBBGP_OK;
}

libbgp_err_t bgp_radix6_remove(bgp_radix6_t *tree, const uint8_t addr[16], uint8_t prefix_len)
{
    bgp_radix6_node_t *path[129];
    unsigned int direction[128];
    bgp_radix6_node_t *node;
    uint8_t bit;

    if (tree == NULL || addr == NULL || prefix_len > 128u) {
        return LIBBGP_ERR_INVALID;
    }
    if (tree->root == NULL) {
        return LIBBGP_ERR_NOT_FOUND;
    }

    node = tree->root;
    path[0] = node;
    for (bit = 0u; bit < prefix_len; bit++) {
        direction[bit] = bgp_radix6_bit(addr, bit);
        node = node->child[direction[bit]];
        if (node == NULL) {
            return LIBBGP_ERR_NOT_FOUND;
        }
        path[(size_t)bit + 1u] = node;
    }

    if (!node->has_value) {
        return LIBBGP_ERR_NOT_FOUND;
    }

    node->value = NULL;
    node->has_value = false;
    tree->len--;

    for (bit = prefix_len; bit > 0u; bit--) {
        bgp_radix6_node_t *child = path[bit];
        bgp_radix6_node_t *parent = path[(size_t)bit - 1u];
        if (!bgp_radix6_node_empty(child)) {
            break;
        }
        parent->child[direction[(size_t)bit - 1u]] = NULL;
        bgp_free(child);
    }

    if (bgp_radix6_node_empty(tree->root)) {
        bgp_free(tree->root);
        tree->root = NULL;
    }

    return LIBBGP_OK;
}

void *bgp_radix6_lookup_lpm(const bgp_radix6_t *tree, const uint8_t addr[16])
{
    const bgp_radix6_node_t *node;
    void *best = NULL;
    uint8_t bit;

    if (tree == NULL || tree->root == NULL || addr == NULL) {
        return NULL;
    }

    node = tree->root;
    if (node->has_value) {
        best = node->value;
    }

    for (bit = 0u; bit < 128u; bit++) {
        node = node->child[bgp_radix6_bit(addr, bit)];
        if (node == NULL) {
            break;
        }
        if (node->has_value) {
            best = node->value;
        }
    }

    return best;
}
