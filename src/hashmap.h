#ifndef LIBBGP_HASHMAP_H
#define LIBBGP_HASHMAP_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "libbgp/types.h"

typedef uint64_t (*bgp_hash_fn)(const void *key, void *ctx);
typedef bool (*bgp_key_eq_fn)(const void *a, const void *b, void *ctx);
typedef void (*bgp_entry_free_fn)(void *key, void *value, void *ctx);
typedef bool (*bgp_hashmap_iter_fn)(void *key, void *value, void *ctx);

typedef struct bgp_hashmap_entry {
    void *key;
    void *value;
    uint64_t hash;
    struct bgp_hashmap_entry *next;
} bgp_hashmap_entry_t;

typedef struct bgp_hashmap {
    bgp_hashmap_entry_t **buckets;
    /* bucket_count is always a power of two (starts at 16, doubles on resize) */
    size_t bucket_count;
    size_t len;
    bgp_hash_fn hash;
    bgp_key_eq_fn eq;
    bgp_entry_free_fn free_entry;
    void *ctx;
} bgp_hashmap_t;

libbgp_err_t bgp_hashmap_init(
    bgp_hashmap_t *map,
    bgp_hash_fn hash,
    bgp_key_eq_fn eq,
    bgp_entry_free_fn free_entry,
    void *ctx);
void bgp_hashmap_destroy(bgp_hashmap_t *map);
libbgp_err_t bgp_hashmap_reserve(bgp_hashmap_t *map, size_t count);
libbgp_err_t bgp_hashmap_insert(bgp_hashmap_t *map, void *key, void *value);
libbgp_err_t bgp_hashmap_remove_one(bgp_hashmap_t *map, const void *key, const void *value);
void *bgp_hashmap_find_first(const bgp_hashmap_t *map, const void *key);
size_t bgp_hashmap_count_key(const bgp_hashmap_t *map, const void *key);
size_t bgp_hashmap_len(const bgp_hashmap_t *map);
void bgp_hashmap_foreach(const bgp_hashmap_t *map, bgp_hashmap_iter_fn fn, void *ctx);

#endif
