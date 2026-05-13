#include "radix4.h"

#include <stdbool.h>
#include <string.h>

#include "internal.h"

struct bgp_radix4_node {
    struct bgp_radix4_node *child[2];
    void *value;
    bool has_value;
};

static bgp_radix4_node_t *bgp_radix4_node_new(void)
{
    return (bgp_radix4_node_t *)bgp_calloc(1u, sizeof(bgp_radix4_node_t));
}

static void bgp_radix4_node_destroy(bgp_radix4_node_t *node)
{
    if (node == NULL) {
        return;
    }

    bgp_radix4_node_destroy(node->child[0]);
    bgp_radix4_node_destroy(node->child[1]);
    bgp_free(node);
}

static unsigned int bgp_radix4_bit(uint32_t addr, uint8_t bit)
{
    const uint8_t *bytes = (const uint8_t *)&addr;

    return (unsigned int)((bytes[bit / 8u] >> (7u - (bit % 8u))) & 1u);
}

static bool bgp_radix4_node_empty(const bgp_radix4_node_t *node)
{
    return node != NULL && !node->has_value && node->child[0] == NULL && node->child[1] == NULL;
}

libbgp_err_t bgp_radix4_init(bgp_radix4_t *tree)
{
    if (tree == NULL) {
        return LIBBGP_ERR_INVALID;
    }

    memset(tree, 0, sizeof(*tree));
    return LIBBGP_OK;
}

void bgp_radix4_destroy(bgp_radix4_t *tree)
{
    if (tree == NULL) {
        return;
    }

    bgp_radix4_node_destroy(tree->root);
    memset(tree, 0, sizeof(*tree));
}

libbgp_err_t bgp_radix4_insert(bgp_radix4_t *tree, uint32_t addr, uint8_t prefix_len, void *value)
{
    bgp_radix4_node_t *path[33];
    unsigned int direction[32];
    bgp_radix4_node_t *node;
    uint8_t bit;

    if (tree == NULL || prefix_len > 32u) {
        return LIBBGP_ERR_INVALID;
    }

    if (tree->root == NULL) {
        tree->root = bgp_radix4_node_new();
        if (tree->root == NULL) {
            return LIBBGP_ERR_NOMEM;
        }
    }

    node = tree->root;
    path[0] = node;
    for (bit = 0u; bit < prefix_len; bit++) {
        direction[bit] = bgp_radix4_bit(addr, bit);
        if (node->child[direction[bit]] == NULL) {
            node->child[direction[bit]] = bgp_radix4_node_new();
            if (node->child[direction[bit]] == NULL) {
                while (bit > 0u && bgp_radix4_node_empty(path[bit])) {
                    bgp_radix4_node_t *child = path[bit];
                    bgp_radix4_node_t *parent = path[(size_t)bit - 1u];
                    parent->child[direction[(size_t)bit - 1u]] = NULL;
                    bgp_free(child);
                    bit--;
                }
                if (bgp_radix4_node_empty(tree->root)) {
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

libbgp_err_t bgp_radix4_remove(bgp_radix4_t *tree, uint32_t addr, uint8_t prefix_len)
{
    bgp_radix4_node_t *path[33];
    unsigned int direction[32];
    bgp_radix4_node_t *node;
    uint8_t bit;

    if (tree == NULL || prefix_len > 32u) {
        return LIBBGP_ERR_INVALID;
    }
    if (tree->root == NULL) {
        return LIBBGP_ERR_NOT_FOUND;
    }

    node = tree->root;
    path[0] = node;
    for (bit = 0u; bit < prefix_len; bit++) {
        direction[bit] = bgp_radix4_bit(addr, bit);
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
        bgp_radix4_node_t *child = path[bit];
        bgp_radix4_node_t *parent = path[(size_t)bit - 1u];
        if (!bgp_radix4_node_empty(child)) {
            break;
        }
        parent->child[direction[(size_t)bit - 1u]] = NULL;
        bgp_free(child);
    }

    if (bgp_radix4_node_empty(tree->root)) {
        bgp_free(tree->root);
        tree->root = NULL;
    }

    return LIBBGP_OK;
}

void *bgp_radix4_lookup_lpm(const bgp_radix4_t *tree, uint32_t addr)
{
    const bgp_radix4_node_t *node;
    void *best = NULL;
    uint8_t bit;

    if (tree == NULL || tree->root == NULL) {
        return NULL;
    }

    node = tree->root;
    if (node->has_value) {
        best = node->value;
    }

    for (bit = 0u; bit < 32u; bit++) {
        node = node->child[bgp_radix4_bit(addr, bit)];
        if (node == NULL) {
            break;
        }
        if (node->has_value) {
            best = node->value;
        }
    }

    return best;
}
