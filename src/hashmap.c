/**
 * @file hashmap.c
 * @brief Internal chained hashmap implementation.
 */
#include "hashmap.h"

#include <assert.h>
#include <limits.h>
#include <string.h>

#include "internal.h"

#define BGP_HASHMAP_INITIAL_BUCKETS 16u

static bool hashmap_is_power_of_two(size_t value)
{
    return value != 0u && (value & (value - 1u)) == 0u;
}

static size_t bucket_index(uint64_t hash, size_t bucket_count)
{
    /* bucket_count is always a power of two; bitmask is faster than modulo */
    assert(hashmap_is_power_of_two(bucket_count));
    return (size_t)(hash & (uint64_t)(bucket_count - 1u));
}

static size_t hashmap_resize_threshold(size_t bucket_count)
{
    return bucket_count - bucket_count / 4u;
}

static libbgp_err_t hashmap_alloc_buckets(bgp_hashmap_entry_t ***out, size_t count)
{
    if (count > SIZE_MAX / sizeof(**out)) {
        return LIBBGP_ERR_NOMEM;
    }
    *out = (bgp_hashmap_entry_t **)bgp_calloc(count, sizeof(**out));
    return *out == NULL ? LIBBGP_ERR_NOMEM : LIBBGP_OK;
}

static libbgp_err_t hashmap_resize(bgp_hashmap_t *map, size_t new_count)
{
    bgp_hashmap_entry_t **new_buckets;
    size_t i;

    if (!hashmap_is_power_of_two(new_count)) {
        return LIBBGP_ERR_INVALID;
    }
    if (hashmap_alloc_buckets(&new_buckets, new_count) != LIBBGP_OK) {
        return LIBBGP_ERR_NOMEM;
    }

    for (i = 0u; i < map->bucket_count; i++) {
        bgp_hashmap_entry_t *entry = map->buckets[i];
        while (entry != NULL) {
            bgp_hashmap_entry_t *next = entry->next;
            size_t idx = bucket_index(entry->hash, new_count);
            entry->next = new_buckets[idx];
            new_buckets[idx] = entry;
            entry = next;
        }
    }

    bgp_free(map->buckets);
    map->buckets = new_buckets;
    map->bucket_count = new_count;
    return LIBBGP_OK;
}

libbgp_err_t bgp_hashmap_init(
    bgp_hashmap_t *map,
    bgp_hash_fn hash,
    bgp_key_eq_fn eq,
    bgp_entry_free_fn free_entry,
    void *ctx)
{
    if (map == NULL || hash == NULL || eq == NULL) {
        return LIBBGP_ERR_INVALID;
    }

    memset(map, 0, sizeof(*map));
    if (!hashmap_is_power_of_two(BGP_HASHMAP_INITIAL_BUCKETS)) {
        return LIBBGP_ERR_INVALID;
    }
    if (hashmap_alloc_buckets(&map->buckets, BGP_HASHMAP_INITIAL_BUCKETS) != LIBBGP_OK) {
        return LIBBGP_ERR_NOMEM;
    }

    map->bucket_count = BGP_HASHMAP_INITIAL_BUCKETS;
    map->hash = hash;
    map->eq = eq;
    map->free_entry = free_entry;
    map->ctx = ctx;
    return LIBBGP_OK;
}

void bgp_hashmap_destroy(bgp_hashmap_t *map)
{
    size_t i;

    if (map == NULL || map->buckets == NULL) {
        return;
    }

    for (i = 0u; i < map->bucket_count; i++) {
        bgp_hashmap_entry_t *entry = map->buckets[i];
        while (entry != NULL) {
            bgp_hashmap_entry_t *next = entry->next;
            if (map->free_entry != NULL) {
                map->free_entry(entry->key, entry->value, map->ctx);
            }
            bgp_free(entry);
            entry = next;
        }
    }

    bgp_free(map->buckets);
    memset(map, 0, sizeof(*map));
}

libbgp_err_t bgp_hashmap_reserve(bgp_hashmap_t *map, size_t count)
{
    size_t target;

    if (map == NULL || map->buckets == NULL || !hashmap_is_power_of_two(map->bucket_count)) {
        return LIBBGP_ERR_INVALID;
    }
    if (count <= hashmap_resize_threshold(map->bucket_count)) {
        return LIBBGP_OK;
    }

    target = map->bucket_count;
    while (hashmap_resize_threshold(target) < count) {
        if (target > SIZE_MAX / 2u) {
            return LIBBGP_ERR_NOMEM;
        }
        target *= 2u;
    }

    return hashmap_resize(map, target);
}

libbgp_err_t bgp_hashmap_insert(bgp_hashmap_t *map, void *key, void *value)
{
    bgp_hashmap_entry_t *entry;
    uint64_t hash;
    size_t idx;

    if (map == NULL || map->buckets == NULL || map->hash == NULL) {
        return LIBBGP_ERR_INVALID;
    }

    if (map->len >= hashmap_resize_threshold(map->bucket_count)) {
        libbgp_err_t err;
        if (map->bucket_count > SIZE_MAX / 2u) {
            return LIBBGP_ERR_NOMEM;
        }
        err = hashmap_resize(map, map->bucket_count * 2u);
        if (err != LIBBGP_OK) {
            return err;
        }
    }

    entry = (bgp_hashmap_entry_t *)bgp_malloc(sizeof(*entry));
    if (entry == NULL) {
        return LIBBGP_ERR_NOMEM;
    }

    hash = map->hash(key, map->ctx);
    idx = bucket_index(hash, map->bucket_count);
    entry->key = key;
    entry->value = value;
    entry->hash = hash;
    entry->next = map->buckets[idx];
    map->buckets[idx] = entry;
    map->len++;
    return LIBBGP_OK;
}

libbgp_err_t bgp_hashmap_remove_one(bgp_hashmap_t *map, const void *key, const void *value)
{
    uint64_t hash;
    size_t idx;
    bgp_hashmap_entry_t **link;

    if (map == NULL || map->buckets == NULL || map->hash == NULL || map->eq == NULL) {
        return LIBBGP_ERR_INVALID;
    }

    hash = map->hash(key, map->ctx);
    idx = bucket_index(hash, map->bucket_count);
    link = &map->buckets[idx];
    while (*link != NULL) {
        bgp_hashmap_entry_t *entry = *link;
        if (entry->hash == hash && map->eq(entry->key, key, map->ctx) &&
            (value == NULL || entry->value == value)) {
            *link = entry->next;
            if (map->free_entry != NULL) {
                map->free_entry(entry->key, entry->value, map->ctx);
            }
            bgp_free(entry);
            map->len--;
            return LIBBGP_OK;
        }
        link = &entry->next;
    }

    return LIBBGP_ERR_NOT_FOUND;
}

void *bgp_hashmap_find_first(const bgp_hashmap_t *map, const void *key)
{
    uint64_t hash;
    size_t idx;
    bgp_hashmap_entry_t *entry;

    if (map == NULL || map->buckets == NULL || map->hash == NULL || map->eq == NULL) {
        return NULL;
    }

    hash = map->hash(key, map->ctx);
    idx = bucket_index(hash, map->bucket_count);
    for (entry = map->buckets[idx]; entry != NULL; entry = entry->next) {
        if (entry->hash == hash && map->eq(entry->key, key, map->ctx)) {
            return entry->value;
        }
    }
    return NULL;
}

size_t bgp_hashmap_count_key(const bgp_hashmap_t *map, const void *key)
{
    uint64_t hash;
    size_t idx;
    size_t count = 0u;
    bgp_hashmap_entry_t *entry;

    if (map == NULL || map->buckets == NULL || map->hash == NULL || map->eq == NULL) {
        return 0u;
    }

    hash = map->hash(key, map->ctx);
    idx = bucket_index(hash, map->bucket_count);
    for (entry = map->buckets[idx]; entry != NULL; entry = entry->next) {
        if (entry->hash == hash && map->eq(entry->key, key, map->ctx)) {
            count++;
        }
    }
    return count;
}

size_t bgp_hashmap_len(const bgp_hashmap_t *map)
{
    return map == NULL ? 0u : map->len;
}

void bgp_hashmap_foreach(const bgp_hashmap_t *map, bgp_hashmap_iter_fn fn, void *ctx)
{
    size_t i;

    if (map == NULL || map->buckets == NULL || fn == NULL) {
        return;
    }

    for (i = 0u; i < map->bucket_count; i++) {
        bgp_hashmap_entry_t *entry = map->buckets[i];
        while (entry != NULL) {
            if (!fn(entry->key, entry->value, ctx)) {
                return;
            }
            entry = entry->next;
        }
    }
}
