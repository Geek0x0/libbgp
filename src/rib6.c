#include "libbgp/rib6.h"

#include <string.h>

#include "hashmap.h"
#include "internal.h"
#include "rib_internal.h"

typedef struct rib6_key {
    libbgp_prefix6_t prefix;
} rib6_key_t;

typedef struct rib6_source_key {
    uint32_t source_router_id;
} rib6_source_key_t;

typedef struct rib6_source_entry {
    uint32_t source_router_id;
    bgp_hashmap_entry_t **entries;
    size_t count;
    size_t cap;
} rib6_source_entry_t;

typedef struct rib6_impl {
    bgp_hashmap_t routes;
    bgp_hashmap_t sources;
    bgp_lock_t lock;
    uint64_t next_update_id;
} rib6_impl_t;

static uint64_t rib6_hash_mix(uint64_t x)
{
    x ^= x >> 33;
    x *= 0xff51afd7ed558ccdull;
    x ^= x >> 33;
    x *= 0xc4ceb9fe1a85ec53ull;
    x ^= x >> 33;
    return x;
}

static uint64_t rib6_hash(const void *key, void *ctx)
{
    const rib6_key_t *k = (const rib6_key_t *)key;
    uint64_t h = k->prefix.len;
    size_t i;

    BGP_UNUSED(ctx);
    for (i = 0u; i < sizeof(k->prefix.addr); i++) {
        h = (h ^ k->prefix.addr[i]) * 1099511628211ull;
    }
    return rib6_hash_mix(h);
}

static bool rib6_key_eq(const void *a, const void *b, void *ctx)
{
    const rib6_key_t *ka = (const rib6_key_t *)a;
    const rib6_key_t *kb = (const rib6_key_t *)b;

    BGP_UNUSED(ctx);
    return libbgp_prefix6_eq(&ka->prefix, &kb->prefix);
}

static uint64_t rib6_source_hash(const void *key, void *ctx)
{
    const rib6_source_key_t *k = (const rib6_source_key_t *)key;

    BGP_UNUSED(ctx);
    return rib6_hash_mix((uint64_t)k->source_router_id);
}

static bool rib6_source_key_eq(const void *a, const void *b, void *ctx)
{
    BGP_UNUSED(ctx);
    return ((const rib6_source_key_t *)a)->source_router_id ==
           ((const rib6_source_key_t *)b)->source_router_id;
}

static int bgp_router_id_cmp(uint32_t a, uint32_t b)
{
    /*
     * source_router_id values are stored as NBO bytes in a uint32_t (see rib6.h).
     * Compare byte-by-byte in memory order so that the comparison reflects
     * dotted-decimal (first-octet-first) ordering per RFC 4271 §9.1.2.2.
     */
    uint8_t buf_a[4];
    uint8_t buf_b[4];

    memcpy(buf_a, &a, sizeof(buf_a));
    memcpy(buf_b, &b, sizeof(buf_b));
    return memcmp(buf_a, buf_b, sizeof(buf_a));
}

static void rib6_route_free(libbgp_rib6_route_t *route)
{
    size_t i;

    if (route == NULL) {
        return;
    }
    for (i = 0u; i < route->attr_count; i++) {
        libbgp_pattr_unref(route->attrs[i]);
    }
    bgp_free(route->attrs);
    bgp_free(route);
}

static void rib6_route_snapshot_clear(libbgp_rib6_route_t *route)
{
    size_t i;

    if (route == NULL) {
        return;
    }
    for (i = 0u; i < route->attr_count; i++) {
        libbgp_pattr_unref(route->attrs[i]);
    }
    bgp_free(route->attrs);
    memset(route, 0, sizeof(*route));
}

libbgp_err_t bgp_rib6_route_snapshot_clone(
    const libbgp_rib6_route_t *src,
    libbgp_rib6_route_t *dst)
{
    size_t i;

    if (src == NULL || dst == NULL || (src->attr_count != 0u && src->attrs == NULL)) {
        return LIBBGP_ERR_INVALID;
    }
    memset(dst, 0, sizeof(*dst));
    *dst = *src;
    dst->attrs = NULL;
    if (src->attr_count == 0u) {
        return LIBBGP_OK;
    }
    if (src->attr_count > SIZE_MAX / sizeof(*dst->attrs)) {
        memset(dst, 0, sizeof(*dst));
        return LIBBGP_ERR_NOMEM;
    }
    dst->attrs = (libbgp_pattr_t **)bgp_calloc(src->attr_count, sizeof(*dst->attrs));
    if (dst->attrs == NULL) {
        memset(dst, 0, sizeof(*dst));
        return LIBBGP_ERR_NOMEM;
    }
    for (i = 0u; i < src->attr_count; i++) {
        dst->attrs[i] = libbgp_pattr_ref(src->attrs[i]);
    }
    return LIBBGP_OK;
}

static void rib6_entry_free(void *key, void *value, void *ctx)
{
    BGP_UNUSED(ctx);
    bgp_free(key);
    rib6_route_free((libbgp_rib6_route_t *)value);
}

static void rib6_source_entry_free(void *key, void *value, void *ctx)
{
    rib6_source_entry_t *entry = (rib6_source_entry_t *)value;

    BGP_UNUSED(ctx);
    bgp_free(key);
    if (entry != NULL) {
        bgp_free(entry->entries);
        bgp_free(entry);
    }
}

static rib6_impl_t *rib6_impl_get(const libbgp_rib6_t *rib)
{
    return rib == NULL ? NULL : (rib6_impl_t *)rib->impl;
}

static uint64_t rib6_next_update_id(rib6_impl_t *impl)
{
    impl->next_update_id++;
    if (impl->next_update_id == 0u) {
        impl->next_update_id++;
    }
    return impl->next_update_id;
}

static rib6_source_entry_t *rib6_source_index_find(
    rib6_impl_t *impl,
    uint32_t source_router_id)
{
    rib6_source_key_t find_key;

    find_key.source_router_id = source_router_id;
    return (rib6_source_entry_t *)bgp_hashmap_find_first(&impl->sources, &find_key);
}

static libbgp_err_t rib6_source_index_add(
    rib6_impl_t *impl,
    bgp_hashmap_entry_t *route_entry)
{
    libbgp_rib6_route_t *route;
    rib6_source_entry_t *source;

    if (impl == NULL || route_entry == NULL || route_entry->value == NULL) {
        return LIBBGP_ERR_INVALID;
    }
    route = (libbgp_rib6_route_t *)route_entry->value;
    source = rib6_source_index_find(impl, route->source_router_id);
    if (source == NULL) {
        rib6_source_key_t *key;

        key = (rib6_source_key_t *)bgp_malloc(sizeof(*key));
        if (key == NULL) {
            return LIBBGP_ERR_NOMEM;
        }
        source = (rib6_source_entry_t *)bgp_calloc(1u, sizeof(*source));
        if (source == NULL) {
            bgp_free(key);
            return LIBBGP_ERR_NOMEM;
        }
        source->entries = (bgp_hashmap_entry_t **)bgp_malloc(sizeof(*source->entries));
        if (source->entries == NULL) {
            bgp_free(source);
            bgp_free(key);
            return LIBBGP_ERR_NOMEM;
        }
        key->source_router_id = route->source_router_id;
        source->source_router_id = route->source_router_id;
        source->entries[0] = route_entry;
        source->count = 1u;
        source->cap = 1u;
        if (bgp_hashmap_insert(&impl->sources, key, source) != LIBBGP_OK) {
            bgp_free(source->entries);
            bgp_free(source);
            bgp_free(key);
            return LIBBGP_ERR_NOMEM;
        }
        return LIBBGP_OK;
    }

    if (source->count >= source->cap) {
        bgp_hashmap_entry_t **next;
        size_t next_cap = source->cap == 0u ? 1u : source->cap * 2u;

        if (source->cap > SIZE_MAX / 2u ||
            next_cap > SIZE_MAX / sizeof(*source->entries)) {
            return LIBBGP_ERR_NOMEM;
        }
        next = (bgp_hashmap_entry_t **)bgp_realloc(
            source->entries,
            next_cap * sizeof(*source->entries));
        if (next == NULL) {
            return LIBBGP_ERR_NOMEM;
        }
        source->entries = next;
        source->cap = next_cap;
    }
    source->entries[source->count] = route_entry;
    source->count++;
    return LIBBGP_OK;
}

static void rib6_source_index_remove(rib6_impl_t *impl, bgp_hashmap_entry_t *route_entry)
{
    libbgp_rib6_route_t *route;
    rib6_source_entry_t *source;
    size_t i;

    if (impl == NULL || route_entry == NULL || route_entry->value == NULL) {
        return;
    }
    route = (libbgp_rib6_route_t *)route_entry->value;
    source = rib6_source_index_find(impl, route->source_router_id);
    if (source == NULL) {
        return;
    }
    for (i = 0u; i < source->count; i++) {
        if (source->entries[i] == route_entry) {
            source->count--;
            source->entries[i] = source->entries[source->count];
            if (source->count == 0u) {
                rib6_source_key_t find_key;

                find_key.source_router_id = route->source_router_id;
                (void)bgp_hashmap_remove_one(&impl->sources, &find_key, source);
            }
            return;
        }
    }
}

static libbgp_err_t rib6_route_clone(
    rib6_impl_t *impl,
    const libbgp_rib6_route_t *src,
    libbgp_rib6_route_t **out_route,
    rib6_key_t **out_key)
{
    libbgp_rib6_route_t *route;
    rib6_key_t *key;
    size_t i;

    if (src->prefix.len > 128u || (src->attr_count != 0u && src->attrs == NULL)) {
        return LIBBGP_ERR_INVALID;
    }

    route = (libbgp_rib6_route_t *)bgp_calloc(1u, sizeof(*route));
    if (route == NULL) {
        return LIBBGP_ERR_NOMEM;
    }
    *route = *src;
    if (route->local_pref == 0u) {
        route->local_pref = 100u;
    }
    if (route->update_id == 0u) {
        route->update_id = rib6_next_update_id(impl);
    }
    route->attrs = NULL;

    if (src->attr_count != 0u) {
        if (src->attr_count > SIZE_MAX / sizeof(*route->attrs)) {
            bgp_free(route);
            return LIBBGP_ERR_NOMEM;
        }
        route->attrs = (libbgp_pattr_t **)bgp_calloc(src->attr_count, sizeof(*route->attrs));
        if (route->attrs == NULL) {
            bgp_free(route);
            return LIBBGP_ERR_NOMEM;
        }
        for (i = 0u; i < src->attr_count; i++) {
            route->attrs[i] = libbgp_pattr_ref(src->attrs[i]);
        }
    }

    key = (rib6_key_t *)bgp_malloc(sizeof(*key));
    if (key == NULL) {
        rib6_route_free(route);
        return LIBBGP_ERR_NOMEM;
    }
    key->prefix = route->prefix;
    *out_route = route;
    *out_key = key;
    return LIBBGP_OK;
}

static bool rib6_neighbor_as(const libbgp_rib6_route_t *route, uint32_t *neighbor_as)
{
    size_t i;

    if (neighbor_as != NULL) {
        *neighbor_as = 0u;
    }
    if (route == NULL || route->attrs == NULL) {
        return false;
    }
    for (i = 0u; i < route->attr_count; i++) {
        const libbgp_pattr_t *attr = route->attrs[i];
        size_t j;

        if (attr == NULL || attr->type != LIBBGP_PATTR_AS_PATH) {
            continue;
        }
        if (attr->data.as_path.segment_count != 0u && attr->data.as_path.segments == NULL) {
            return false;
        }
        for (j = 0u; j < attr->data.as_path.segment_count; j++) {
            const libbgp_as_path_segment_t *segment = &attr->data.as_path.segments[j];

            if (segment->type == 2u && segment->asn_count != 0u && segment->asns != NULL) {
                if (neighbor_as != NULL) {
                    *neighbor_as = segment->asns[0];
                }
                return true;
            }
        }
        return false;
    }
    return false;
}

static bool rib6_better(const libbgp_rib6_route_t *a, const libbgp_rib6_route_t *b)
{
    uint32_t a_lp;
    uint32_t b_lp;
    uint32_t a_neighbor_as;
    uint32_t b_neighbor_as;

    if (b == NULL) {
        return true;
    }
    if (a->weight != b->weight) {
        return a->weight > b->weight;
    }
    a_lp = a->local_pref == 0u ? 100u : a->local_pref;
    b_lp = b->local_pref == 0u ? 100u : b->local_pref;
    if (a_lp != b_lp) {
        return a_lp > b_lp;
    }
    if (a->as_path_len != b->as_path_len) {
        return a->as_path_len < b->as_path_len;
    }
    if (a->origin != b->origin) {
        return a->origin < b->origin;
    }
    if (a->med != b->med && rib6_neighbor_as(a, &a_neighbor_as) &&
        rib6_neighbor_as(b, &b_neighbor_as) && a_neighbor_as == b_neighbor_as) {
        return a->med < b->med;
    }
    if (a->is_ibgp != b->is_ibgp) {
        return !a->is_ibgp;
    }
    if (a->update_id != b->update_id) {
        return a->update_id < b->update_id;
    }
    return bgp_router_id_cmp(a->source_router_id, b->source_router_id) < 0;
}

static bool rib6_addr_matches(const libbgp_prefix6_t *prefix, const uint8_t dest[16])
{
    uint8_t mask[16];
    size_t i;

    if (prefix == NULL || dest == NULL || prefix->len > 128u) {
        return false;
    }
    libbgp_cidr6_to_mask(prefix->len, mask);
    for (i = 0u; i < 16u; i++) {
        if ((prefix->addr[i] & mask[i]) != (dest[i] & mask[i])) {
            return false;
        }
    }
    return true;
}

static libbgp_rib6_route_t *rib6_find_locked(
    rib6_impl_t *impl,
    uint32_t source_router_id,
    const libbgp_prefix6_t *prefix);

static bool rib6_route_entry_unlink_locked(rib6_impl_t *impl, bgp_hashmap_entry_t *entry)
{
    bgp_hashmap_entry_t **link;
    size_t idx;

    if (impl == NULL || entry == NULL || impl->routes.bucket_count == 0u) {
        return false;
    }
    idx = (size_t)(entry->hash % (uint64_t)impl->routes.bucket_count);
    link = &impl->routes.buckets[idx];
    while (*link != NULL) {
        if (*link == entry) {
            *link = entry->next;
            entry->next = NULL;
            impl->routes.len--;
            return true;
        }
        link = &(*link)->next;
    }
    return false;
}

static bgp_hashmap_entry_t *rib6_entry_find_value_locked(
    rib6_impl_t *impl,
    const libbgp_prefix6_t *prefix,
    const libbgp_rib6_route_t *value)
{
    rib6_key_t find_key;
    bgp_hashmap_entry_t *entry;
    uint64_t hash;
    size_t idx;

    if (impl == NULL || prefix == NULL || value == NULL) {
        return NULL;
    }
    find_key.prefix = *prefix;
    hash = rib6_hash(&find_key, NULL);
    idx = (size_t)(hash % (uint64_t)impl->routes.bucket_count);
    for (entry = impl->routes.buckets[idx]; entry != NULL; entry = entry->next) {
        if (entry->hash == hash && entry->value == value &&
            rib6_key_eq(entry->key, &find_key, NULL)) {
            return entry;
        }
    }
    return NULL;
}

static size_t rib6_remove_source_locked(rib6_impl_t *impl, uint32_t source_router_id)
{
    rib6_source_key_t find_key;
    rib6_source_entry_t *source;
    size_t removed = 0u;
    size_t i;

    find_key.source_router_id = source_router_id;
    source = (rib6_source_entry_t *)bgp_hashmap_find_first(&impl->sources, &find_key);
    if (source == NULL) {
        return 0u;
    }
    for (i = 0u; i < source->count; i++) {
        bgp_hashmap_entry_t *entry = source->entries[i];

        if (rib6_route_entry_unlink_locked(impl, entry)) {
            if (impl->routes.free_entry != NULL) {
                impl->routes.free_entry(entry->key, entry->value, impl->routes.ctx);
            }
            bgp_free(entry);
            removed++;
        }
    }
    (void)bgp_hashmap_remove_one(&impl->sources, &find_key, source);
    return removed;
}

static libbgp_err_t rib6_withdraw_locked(
    rib6_impl_t *impl,
    uint32_t source_router_id,
    const libbgp_prefix6_t *prefix)
{
    rib6_key_t find_key;
    size_t idx;
    uint64_t hash;
    bgp_hashmap_entry_t *entry;
    libbgp_rib6_route_t *match = NULL;
    bgp_hashmap_entry_t *match_entry = NULL;

    find_key.prefix = *prefix;
    hash = rib6_hash(&find_key, NULL);
    idx = (size_t)(hash % (uint64_t)impl->routes.bucket_count);
    for (entry = impl->routes.buckets[idx]; entry != NULL; entry = entry->next) {
        libbgp_rib6_route_t *route = (libbgp_rib6_route_t *)entry->value;
        if (entry->hash == hash && rib6_key_eq(entry->key, &find_key, NULL) &&
            route->source_router_id == source_router_id) {
            match = route;
            match_entry = entry;
            break;
        }
    }
    if (match == NULL) {
        return LIBBGP_ERR_NOT_FOUND;
    }
    rib6_source_index_remove(impl, match_entry);
    return bgp_hashmap_remove_one(&impl->routes, &find_key, match);
}

static libbgp_err_t rib6_detach_locked(
    rib6_impl_t *impl,
    uint32_t source_router_id,
    const libbgp_prefix6_t *prefix,
    bgp_hashmap_entry_t **out_entry)
{
    rib6_key_t find_key;
    size_t idx;
    uint64_t hash;
    bgp_hashmap_entry_t **link;

    if (out_entry != NULL) {
        *out_entry = NULL;
    }
    if (impl == NULL || prefix == NULL || out_entry == NULL) {
        return LIBBGP_ERR_INVALID;
    }
    find_key.prefix = *prefix;
    hash = rib6_hash(&find_key, NULL);
    idx = (size_t)(hash % (uint64_t)impl->routes.bucket_count);
    link = &impl->routes.buckets[idx];
    while (*link != NULL) {
        bgp_hashmap_entry_t *entry = *link;
        libbgp_rib6_route_t *route = (libbgp_rib6_route_t *)entry->value;

        if (entry->hash == hash && rib6_key_eq(entry->key, &find_key, NULL) &&
            route->source_router_id == source_router_id) {
            *link = entry->next;
            entry->next = NULL;
            impl->routes.len--;
            rib6_source_index_remove(impl, entry);
            *out_entry = entry;
            return LIBBGP_OK;
        }
        link = &entry->next;
    }
    return LIBBGP_ERR_NOT_FOUND;
}

static libbgp_err_t rib6_detach_value_locked(
    rib6_impl_t *impl,
    const libbgp_prefix6_t *prefix,
    const libbgp_rib6_route_t *value,
    bgp_hashmap_entry_t **out_entry)
{
    rib6_key_t find_key;
    size_t idx;
    uint64_t hash;
    bgp_hashmap_entry_t **link;

    if (out_entry != NULL) {
        *out_entry = NULL;
    }
    if (impl == NULL || prefix == NULL || value == NULL || out_entry == NULL) {
        return LIBBGP_ERR_INVALID;
    }
    find_key.prefix = *prefix;
    hash = rib6_hash(&find_key, NULL);
    idx = (size_t)(hash % (uint64_t)impl->routes.bucket_count);
    link = &impl->routes.buckets[idx];
    while (*link != NULL) {
        bgp_hashmap_entry_t *entry = *link;

        if (entry->hash == hash && rib6_key_eq(entry->key, &find_key, NULL) &&
            entry->value == value) {
            *link = entry->next;
            entry->next = NULL;
            impl->routes.len--;
            rib6_source_index_remove(impl, entry);
            *out_entry = entry;
            return LIBBGP_OK;
        }
        link = &entry->next;
    }
    return LIBBGP_ERR_NOT_FOUND;
}

static libbgp_err_t rib6_attach_detached_locked(rib6_impl_t *impl, bgp_hashmap_entry_t *entry)
{
    libbgp_rib6_route_t *route;
    libbgp_rib6_route_t *old;
    size_t idx;

    if (impl == NULL || entry == NULL || entry->key == NULL || entry->value == NULL) {
        return LIBBGP_ERR_INVALID;
    }
    route = (libbgp_rib6_route_t *)entry->value;
    old = rib6_find_locked(impl, route->source_router_id, &route->prefix);
    if (old != NULL) {
        return LIBBGP_ERR_EXISTS;
    }
    entry->hash = rib6_hash(entry->key, NULL);
    if (rib6_source_index_add(impl, entry) != LIBBGP_OK) {
        return LIBBGP_ERR_NOMEM;
    }
    idx = (size_t)(entry->hash % (uint64_t)impl->routes.bucket_count);
    entry->next = impl->routes.buckets[idx];
    impl->routes.buckets[idx] = entry;
    impl->routes.len++;
    return LIBBGP_OK;
}

static void rib6_detached_entry_free(bgp_hashmap_entry_t *entry)
{
    if (entry == NULL) {
        return;
    }
    rib6_entry_free(entry->key, entry->value, NULL);
    bgp_free(entry);
}

static libbgp_rib6_route_t *rib6_find_locked(
    rib6_impl_t *impl,
    uint32_t source_router_id,
    const libbgp_prefix6_t *prefix)
{
    rib6_key_t find_key;
    size_t idx;
    uint64_t hash;
    bgp_hashmap_entry_t *entry;

    find_key.prefix = *prefix;
    hash = rib6_hash(&find_key, NULL);
    idx = (size_t)(hash % (uint64_t)impl->routes.bucket_count);
    for (entry = impl->routes.buckets[idx]; entry != NULL; entry = entry->next) {
        libbgp_rib6_route_t *route = (libbgp_rib6_route_t *)entry->value;
        if (entry->hash == hash && rib6_key_eq(entry->key, &find_key, NULL) &&
            route->source_router_id == source_router_id) {
            return route;
        }
    }
    return NULL;
}

static libbgp_rib6_route_t *rib6_best_exact_locked(
    rib6_impl_t *impl,
    const libbgp_prefix6_t *prefix)
{
    rib6_key_t find_key;
    size_t idx;
    uint64_t hash;
    bgp_hashmap_entry_t *entry;
    libbgp_rib6_route_t *best = NULL;

    if (impl == NULL || prefix == NULL) {
        return NULL;
    }
    find_key.prefix = *prefix;
    hash = rib6_hash(&find_key, NULL);
    idx = (size_t)(hash % (uint64_t)impl->routes.bucket_count);
    for (entry = impl->routes.buckets[idx]; entry != NULL; entry = entry->next) {
        libbgp_rib6_route_t *route = (libbgp_rib6_route_t *)entry->value;

        if (entry->hash == hash && rib6_key_eq(entry->key, &find_key, NULL) &&
            libbgp_prefix6_eq(&route->prefix, prefix) &&
            (best == NULL || rib6_better(route, best))) {
            best = route;
        }
    }
    return best;
}

static libbgp_err_t rib6_prefix_array_push(
    libbgp_prefix6_t **items,
    size_t *count,
    const libbgp_prefix6_t *prefix)
{
    libbgp_prefix6_t *next;

    if (items == NULL || count == NULL || prefix == NULL) {
        return LIBBGP_ERR_INVALID;
    }
    if (*count == SIZE_MAX || *count + 1u > SIZE_MAX / sizeof(**items)) {
        return LIBBGP_ERR_NOMEM;
    }
    next = (libbgp_prefix6_t *)bgp_realloc(*items, (*count + 1u) * sizeof(**items));
    if (next == NULL) {
        return LIBBGP_ERR_NOMEM;
    }
    *items = next;
    (*items)[*count] = *prefix;
    (*count)++;
    return LIBBGP_OK;
}

static libbgp_err_t rib6_result_add_replacement(
    bgp_rib6_discard_result_t *result,
    const libbgp_rib6_route_t *route)
{
    libbgp_rib6_route_t *next;
    libbgp_err_t err;

    if (result == NULL || route == NULL) {
        return LIBBGP_ERR_INVALID;
    }
    if (result->replacement_count == SIZE_MAX ||
        result->replacement_count + 1u > SIZE_MAX / sizeof(*result->replacements)) {
        return LIBBGP_ERR_NOMEM;
    }
    next = (libbgp_rib6_route_t *)bgp_realloc(
        result->replacements,
        (result->replacement_count + 1u) * sizeof(*result->replacements));
    if (next == NULL) {
        return LIBBGP_ERR_NOMEM;
    }
    result->replacements = next;
    memset(&result->replacements[result->replacement_count], 0, sizeof(result->replacements[result->replacement_count]));
    err = bgp_rib6_route_snapshot_clone(route, &result->replacements[result->replacement_count]);
    if (err != LIBBGP_OK) {
        return err;
    }
    result->replacement_count++;
    return LIBBGP_OK;
}

libbgp_err_t libbgp_rib6_init(libbgp_rib6_t *rib)
{
    rib6_impl_t *impl;
    libbgp_err_t err;

    if (rib == NULL) {
        return LIBBGP_ERR_INVALID;
    }
    rib->impl = NULL;
    impl = (rib6_impl_t *)bgp_calloc(1u, sizeof(*impl));
    if (impl == NULL) {
        return LIBBGP_ERR_NOMEM;
    }
    err = bgp_hashmap_init(&impl->routes, rib6_hash, rib6_key_eq, rib6_entry_free, NULL);
    if (err != LIBBGP_OK) {
        bgp_free(impl);
        return err;
    }
    err = bgp_hashmap_init(
        &impl->sources,
        rib6_source_hash,
        rib6_source_key_eq,
        rib6_source_entry_free,
        NULL);
    if (err != LIBBGP_OK) {
        bgp_hashmap_destroy(&impl->routes);
        bgp_free(impl);
        return err;
    }
    bgp_lock_init(&impl->lock);
    rib->impl = impl;
    return LIBBGP_OK;
}

void libbgp_rib6_destroy(libbgp_rib6_t *rib)
{
    rib6_impl_t *impl = rib6_impl_get(rib);

    if (impl == NULL) {
        return;
    }
    bgp_lock(&impl->lock);
    bgp_hashmap_destroy(&impl->sources);
    bgp_hashmap_destroy(&impl->routes);
    bgp_unlock(&impl->lock);
    bgp_lock_destroy(&impl->lock);
    bgp_free(impl);
    rib->impl = NULL;
}

libbgp_err_t libbgp_rib6_insert_local(
    libbgp_rib6_t *rib,
    const libbgp_prefix6_t *prefix,
    const uint8_t next_hop[16],
    int32_t weight)
{
    libbgp_rib6_route_t route;
    libbgp_pattr_t *attrs[2] = { NULL, NULL };
    libbgp_err_t err;

    if (prefix == NULL || next_hop == NULL) {
        return LIBBGP_ERR_INVALID;
    }
    attrs[0] = libbgp_pattr_new(LIBBGP_PATTR_ORIGIN);
    attrs[1] = libbgp_pattr_new(LIBBGP_PATTR_AS_PATH);
    if (attrs[0] == NULL || attrs[1] == NULL) {
        libbgp_pattr_unref(attrs[0]);
        libbgp_pattr_unref(attrs[1]);
        return LIBBGP_ERR_NOMEM;
    }
    attrs[0]->data.origin.origin = 0u;
    attrs[1]->data.as_path.is_4b = true;

    memset(&route, 0, sizeof(route));
    route.prefix = *prefix;
    memcpy(route.next_hop, next_hop, sizeof(route.next_hop));
    route.weight = weight;
    route.local_pref = 100u;
    route.origin = 0u;
    route.is_ibgp = false;
    route.attrs = attrs;
    route.attr_count = 2u;
    err = libbgp_rib6_insert(rib, &route);
    libbgp_pattr_unref(attrs[0]);
    libbgp_pattr_unref(attrs[1]);
    return err;
}

libbgp_err_t libbgp_rib6_insert(libbgp_rib6_t *rib, const libbgp_rib6_route_t *route)
{
    return bgp_rib6_insert_save_replaced(rib, route, NULL, NULL, NULL);
}

static void rib6_change_set(
    bgp_rib6_change_t *change,
    bgp_rib_change_kind_t kind,
    const libbgp_rib6_route_t *best)
{
    change->kind = kind;
    change->best = best;
}

static libbgp_err_t rib6_insert_save_replaced_locked(
    rib6_impl_t *impl,
    const libbgp_rib6_route_t *route,
    bgp_rib6_saved_route_t *replaced,
    bool *had_replaced,
    uint64_t *update_id,
    bgp_hashmap_entry_t **old_entry)
{
    libbgp_rib6_route_t *copy = NULL;
    libbgp_rib6_route_t *old = NULL;
    bgp_hashmap_entry_t *new_entry = NULL;
    rib6_key_t *key = NULL;
    libbgp_err_t err;

    if (old_entry != NULL) {
        *old_entry = NULL;
    }
    old = rib6_find_locked(impl, route->source_router_id, &route->prefix);
    if (route->source_router_id == 0u && old != NULL &&
        replaced == NULL && had_replaced == NULL && update_id == NULL) {
        err = LIBBGP_ERR_EXISTS;
    } else {
        err = rib6_route_clone(impl, route, &copy, &key);
    }
    if (err == LIBBGP_OK) {
        err = bgp_hashmap_insert(&impl->routes, key, copy);
        if (err != LIBBGP_OK) {
            bgp_free(key);
            rib6_route_free(copy);
        } else {
            new_entry = rib6_entry_find_value_locked(impl, &copy->prefix, copy);
            if (new_entry == NULL) {
                err = LIBBGP_ERR_NOT_FOUND;
            } else {
                err = rib6_source_index_add(impl, new_entry);
            }
            if (err != LIBBGP_OK) {
                if (new_entry != NULL && rib6_route_entry_unlink_locked(impl, new_entry)) {
                    rib6_entry_free(new_entry->key, new_entry->value, NULL);
                    bgp_free(new_entry);
                } else {
                    (void)bgp_hashmap_remove_one(&impl->routes, key, copy);
                }
            }
        }
        if (err == LIBBGP_OK && old != NULL) {
            err = rib6_detach_value_locked(impl, &copy->prefix, old, old_entry);
            if (err == LIBBGP_ERR_NOT_FOUND) {
                err = LIBBGP_OK;
            } else if (err == LIBBGP_OK) {
                if (replaced != NULL) {
                    replaced->entry = *old_entry;
                    *old_entry = NULL;
                }
                if (had_replaced != NULL) {
                    *had_replaced = true;
                }
            }
            if (err == LIBBGP_OK && update_id != NULL) {
                *update_id = copy->update_id;
            }
        } else if (err == LIBBGP_OK && update_id != NULL) {
            *update_id = copy->update_id;
        }
    }
    return err;
}

libbgp_err_t bgp_rib6_insert_track_best(
    libbgp_rib6_t *rib,
    const libbgp_rib6_route_t *route,
    bgp_rib6_change_t *change,
    uint64_t *update_id)
{
    rib6_impl_t *impl = rib6_impl_get(rib);
    const libbgp_rib6_route_t *before = NULL;
    const libbgp_rib6_route_t *after = NULL;
    bgp_hashmap_entry_t *old_entry = NULL;
    bgp_rib_change_kind_t kind;
    libbgp_err_t err;

    if (change != NULL) {
        rib6_change_set(change, BGP_RIB_CHANGE_NO_BEST_CHANGE, NULL);
    }
    if (impl == NULL || route == NULL || change == NULL) {
        return LIBBGP_ERR_INVALID;
    }

    bgp_lock(&impl->lock);
    before = rib6_best_exact_locked(impl, &route->prefix);
    err = rib6_insert_save_replaced_locked(impl, route, NULL, NULL, update_id, &old_entry);
    if (err == LIBBGP_OK) {
        after = rib6_best_exact_locked(impl, &route->prefix);
        if (after == NULL) {
            err = LIBBGP_ERR_NOT_FOUND;
        } else if (before == NULL) {
            kind = BGP_RIB_CHANGE_NEW_BEST;
        } else if (before == after) {
            kind = BGP_RIB_CHANGE_NO_BEST_CHANGE;
        } else {
            kind = BGP_RIB_CHANGE_REPLACEMENT_BEST;
        }
        if (err == LIBBGP_OK) {
            rib6_change_set(change, kind, after);
        }
    }
    bgp_unlock(&impl->lock);
    rib6_detached_entry_free(old_entry);
    return err;
}

libbgp_err_t bgp_rib6_withdraw_track_best(
    libbgp_rib6_t *rib,
    uint32_t source_router_id,
    const libbgp_prefix6_t *prefix,
    bgp_rib6_change_t *change)
{
    rib6_impl_t *impl = rib6_impl_get(rib);
    const libbgp_rib6_route_t *before = NULL;
    const libbgp_rib6_route_t *after = NULL;
    bool withdrew_best = false;
    libbgp_err_t err;

    if (change != NULL) {
        rib6_change_set(change, BGP_RIB_CHANGE_NO_BEST_CHANGE, NULL);
    }
    if (impl == NULL || prefix == NULL || change == NULL) {
        return LIBBGP_ERR_INVALID;
    }

    bgp_lock(&impl->lock);
    before = rib6_best_exact_locked(impl, prefix);
    withdrew_best = before != NULL && before->source_router_id == source_router_id;
    err = rib6_withdraw_locked(impl, source_router_id, prefix);
    if (err == LIBBGP_OK) {
        after = rib6_best_exact_locked(impl, prefix);
        if (!withdrew_best) {
            rib6_change_set(change, BGP_RIB_CHANGE_NO_BEST_CHANGE, after);
        } else if (after == NULL) {
            rib6_change_set(change, BGP_RIB_CHANGE_UNREACHABLE, NULL);
        } else {
            rib6_change_set(change, BGP_RIB_CHANGE_REPLACEMENT_BEST, after);
        }
    }
    bgp_unlock(&impl->lock);
    return err;
}

libbgp_err_t bgp_rib6_insert_save_replaced(
    libbgp_rib6_t *rib,
    const libbgp_rib6_route_t *route,
    bgp_rib6_saved_route_t *replaced,
    bool *had_replaced,
    uint64_t *update_id)
{
    rib6_impl_t *impl = rib6_impl_get(rib);
    bgp_hashmap_entry_t *old_entry = NULL;
    libbgp_err_t err;

    if (replaced != NULL) {
        replaced->entry = NULL;
    }
    if (had_replaced != NULL) {
        *had_replaced = false;
    }
    if (update_id != NULL) {
        *update_id = 0u;
    }
    if (impl == NULL || route == NULL) {
        return LIBBGP_ERR_INVALID;
    }

    bgp_lock(&impl->lock);
    err = rib6_insert_save_replaced_locked(impl, route, replaced, had_replaced, update_id, &old_entry);
    bgp_unlock(&impl->lock);
    rib6_detached_entry_free(old_entry);
    return err;
}

libbgp_err_t libbgp_rib6_withdraw(
    libbgp_rib6_t *rib,
    uint32_t source_router_id,
    const libbgp_prefix6_t *prefix)
{
    rib6_impl_t *impl = rib6_impl_get(rib);
    libbgp_err_t err;

    if (impl == NULL || prefix == NULL) {
        return LIBBGP_ERR_INVALID;
    }

    bgp_lock(&impl->lock);
    err = rib6_withdraw_locked(impl, source_router_id, prefix);
    bgp_unlock(&impl->lock);
    return err;
}

libbgp_err_t libbgp_rib6_discard(libbgp_rib6_t *rib, uint32_t source_router_id)
{
    rib6_impl_t *impl = rib6_impl_get(rib);

    if (impl == NULL) {
        return LIBBGP_ERR_INVALID;
    }

    bgp_lock(&impl->lock);
    (void)rib6_remove_source_locked(impl, source_router_id);
    bgp_unlock(&impl->lock);
    return LIBBGP_OK;
}

libbgp_err_t libbgp_rib6_lookup(
    const libbgp_rib6_t *rib,
    const uint8_t dest_addr[16],
    const libbgp_rib6_route_t **out_route)
{
    rib6_impl_t *impl = rib6_impl_get(rib);
    const libbgp_rib6_route_t *best = NULL;
    size_t i;

    if (impl == NULL || dest_addr == NULL || out_route == NULL) {
        return LIBBGP_ERR_INVALID;
    }

    bgp_lock(&impl->lock);
    for (i = 0u; i < impl->routes.bucket_count; i++) {
        bgp_hashmap_entry_t *entry;
        for (entry = impl->routes.buckets[i]; entry != NULL; entry = entry->next) {
            const libbgp_rib6_route_t *route = (const libbgp_rib6_route_t *)entry->value;
            if (!rib6_addr_matches(&route->prefix, dest_addr)) {
                continue;
            }
            if (best == NULL || route->prefix.len > best->prefix.len ||
                (route->prefix.len == best->prefix.len && rib6_better(route, best))) {
                best = route;
            }
        }
    }
    if (best == NULL) {
        bgp_unlock(&impl->lock);
        return LIBBGP_ERR_NOT_FOUND;
    }
    *out_route = best;
    bgp_unlock(&impl->lock);
    return LIBBGP_OK;
}

libbgp_err_t libbgp_rib6_lookup_scoped(
    const libbgp_rib6_t *rib,
    uint32_t source_router_id,
    const uint8_t dest_addr[16],
    const libbgp_rib6_route_t **out_route)
{
    rib6_impl_t *impl = rib6_impl_get(rib);
    const libbgp_rib6_route_t *best = NULL;
    size_t i;

    if (impl == NULL || dest_addr == NULL || out_route == NULL) {
        return LIBBGP_ERR_INVALID;
    }

    bgp_lock(&impl->lock);
    for (i = 0u; i < impl->routes.bucket_count; i++) {
        bgp_hashmap_entry_t *entry;
        for (entry = impl->routes.buckets[i]; entry != NULL; entry = entry->next) {
            const libbgp_rib6_route_t *route = (const libbgp_rib6_route_t *)entry->value;
            if (route->source_router_id != source_router_id || !rib6_addr_matches(&route->prefix, dest_addr)) {
                continue;
            }
            if (best == NULL || route->prefix.len > best->prefix.len ||
                (route->prefix.len == best->prefix.len && rib6_better(route, best))) {
                best = route;
            }
        }
    }
    if (best == NULL) {
        bgp_unlock(&impl->lock);
        return LIBBGP_ERR_NOT_FOUND;
    }
    *out_route = best;
    bgp_unlock(&impl->lock);
    return LIBBGP_OK;
}

size_t libbgp_rib6_route_count(const libbgp_rib6_t *rib)
{
    rib6_impl_t *impl = rib6_impl_get(rib);
    size_t count;

    if (impl == NULL) {
        return 0u;
    }
    bgp_lock(&impl->lock);
    count = bgp_hashmap_len(&impl->routes);
    bgp_unlock(&impl->lock);
    return count;
}

libbgp_err_t bgp_rib6_foreach_route(
    const libbgp_rib6_t *rib,
    bgp_rib6_route_iter_fn fn,
    void *ctx)
{
    rib6_impl_t *impl = rib6_impl_get(rib);
    bool keep_going = true;
    size_t i;

    if (impl == NULL || fn == NULL) {
        return LIBBGP_ERR_INVALID;
    }
    bgp_lock(&impl->lock);
    for (i = 0u; keep_going && i < impl->routes.bucket_count; i++) {
        bgp_hashmap_entry_t *entry;

        for (entry = impl->routes.buckets[i]; entry != NULL; entry = entry->next) {
            keep_going = fn((const libbgp_rib6_route_t *)entry->value, ctx);
            if (!keep_going) {
                break;
            }
        }
    }
    bgp_unlock(&impl->lock);
    return LIBBGP_OK;
}

libbgp_err_t bgp_rib6_foreach_best_route(
    const libbgp_rib6_t *rib,
    bgp_rib6_route_iter_fn fn,
    void *ctx)
{
    rib6_impl_t *impl = rib6_impl_get(rib);
    libbgp_rib6_route_t *routes = NULL;
    size_t route_count = 0u;
    size_t route_capacity = 0u;
    size_t i;
    libbgp_err_t err = LIBBGP_OK;
    bool keep_going = true;

    if (impl == NULL || fn == NULL) {
        return LIBBGP_ERR_INVALID;
    }

    bgp_lock(&impl->lock);
    for (i = 0u; i < impl->routes.bucket_count && err == LIBBGP_OK; i++) {
        bgp_hashmap_entry_t *entry;

        for (entry = impl->routes.buckets[i]; entry != NULL; entry = entry->next) {
            const libbgp_rib6_route_t *current = (const libbgp_rib6_route_t *)entry->value;
            const libbgp_rib6_route_t *best = rib6_best_exact_locked(impl, &current->prefix);

            if (best != current) {
                continue;
            }

            if (route_count == route_capacity) {
                libbgp_rib6_route_t *next;
                size_t next_capacity = route_capacity == 0u ? 8u : route_capacity * 2u;

                if (route_capacity > SIZE_MAX / 2u ||
                    next_capacity > SIZE_MAX / sizeof(*routes)) {
                    err = LIBBGP_ERR_NOMEM;
                    break;
                }
                next = (libbgp_rib6_route_t *)bgp_realloc(routes, next_capacity * sizeof(*routes));
                if (next == NULL) {
                    err = LIBBGP_ERR_NOMEM;
                    break;
                }
                routes = next;
                memset(&routes[route_capacity], 0, (next_capacity - route_capacity) * sizeof(*routes));
                route_capacity = next_capacity;
            }
            err = bgp_rib6_route_snapshot_clone(current, &routes[route_count]);
            if (err != LIBBGP_OK) {
                break;
            }
            route_count++;
        }
    }
    bgp_unlock(&impl->lock);

    for (i = 0u; i < route_count && keep_going; i++) {
        keep_going = fn(&routes[i], ctx);
    }
    for (i = 0u; i < route_count; i++) {
        rib6_route_snapshot_clear(&routes[i]);
    }
    bgp_free(routes);
    return err;
}

void bgp_rib6_route_snapshot_destroy(libbgp_rib6_route_t *route)
{
    rib6_route_snapshot_clear(route);
}

void bgp_rib6_discard_result_destroy(bgp_rib6_discard_result_t *result)
{
    size_t i;

    if (result == NULL) {
        return;
    }
    for (i = 0u; i < result->replacement_count; i++) {
        rib6_route_snapshot_clear(&result->replacements[i]);
    }
    bgp_free(result->withdrawn);
    bgp_free(result->replacements);
    memset(result, 0, sizeof(*result));
}

libbgp_err_t bgp_rib6_best_exact_clone(
    libbgp_rib6_t *rib,
    const libbgp_prefix6_t *prefix,
    libbgp_rib6_route_t *out_route,
    bool *found)
{
    rib6_impl_t *impl = rib6_impl_get(rib);
    libbgp_rib6_route_t *best;
    libbgp_err_t err = LIBBGP_OK;

    if (found != NULL) {
        *found = false;
    }
    if (out_route != NULL) {
        memset(out_route, 0, sizeof(*out_route));
    }
    if (impl == NULL || prefix == NULL || out_route == NULL) {
        return LIBBGP_ERR_INVALID;
    }
    bgp_lock(&impl->lock);
    best = rib6_best_exact_locked(impl, prefix);
    if (best != NULL) {
        err = bgp_rib6_route_snapshot_clone(best, out_route);
        if (err == LIBBGP_OK && found != NULL) {
            *found = true;
        }
    }
    bgp_unlock(&impl->lock);
    return err;
}

libbgp_err_t bgp_rib6_discard_collect(
    libbgp_rib6_t *rib,
    uint32_t source_router_id,
    bgp_rib6_discard_result_t *result)
{
    rib6_impl_t *impl = rib6_impl_get(rib);
    libbgp_prefix6_t *active_prefixes = NULL;
    size_t active_count = 0u;
    rib6_source_entry_t *source;
    size_t i;
    libbgp_err_t err = LIBBGP_OK;

    if (result != NULL) {
        memset(result, 0, sizeof(*result));
    }
    if (impl == NULL || result == NULL) {
        return LIBBGP_ERR_INVALID;
    }

    bgp_lock(&impl->lock);
    source = rib6_source_index_find(impl, source_router_id);
    if (source != NULL) {
        for (i = 0u; i < source->count && err == LIBBGP_OK; i++) {
            bgp_hashmap_entry_t *entry = source->entries[i];
            libbgp_rib6_route_t *route = (libbgp_rib6_route_t *)entry->value;

            if (route->source_router_id == source_router_id &&
                rib6_best_exact_locked(impl, &route->prefix) == route) {
                err = rib6_prefix_array_push(&active_prefixes, &active_count, &route->prefix);
                if (err != LIBBGP_OK) {
                    break;
                }
            }
        }
    }
    if (err != LIBBGP_OK) {
        bgp_unlock(&impl->lock);
        bgp_free(active_prefixes);
        return err;
    }

    (void)rib6_remove_source_locked(impl, source_router_id);

    for (i = 0u; i < active_count && err == LIBBGP_OK; i++) {
        libbgp_rib6_route_t *replacement = rib6_best_exact_locked(impl, &active_prefixes[i]);

        if (replacement == NULL) {
            err = rib6_prefix_array_push(&result->withdrawn, &result->withdrawn_count, &active_prefixes[i]);
        } else {
            err = rib6_result_add_replacement(result, replacement);
        }
    }
    bgp_unlock(&impl->lock);
    bgp_free(active_prefixes);
    if (err != LIBBGP_OK) {
        bgp_rib6_discard_result_destroy(result);
    }
    return err;
}

void bgp_rib6_saved_route_destroy(bgp_rib6_saved_route_t *saved)
{
    if (saved == NULL || saved->entry == NULL) {
        return;
    }
    rib6_detached_entry_free((bgp_hashmap_entry_t *)saved->entry);
    saved->entry = NULL;
}

libbgp_err_t bgp_rib6_saved_route_update_id(
    const bgp_rib6_saved_route_t *saved,
    uint64_t *update_id)
{
    const bgp_hashmap_entry_t *entry;
    const libbgp_rib6_route_t *route;

    if (update_id != NULL) {
        *update_id = 0u;
    }
    if (saved == NULL || update_id == NULL) {
        return LIBBGP_ERR_INVALID;
    }
    if (saved->entry == NULL) {
        return LIBBGP_ERR_NOT_FOUND;
    }
    entry = (const bgp_hashmap_entry_t *)saved->entry;
    route = (const libbgp_rib6_route_t *)entry->value;
    if (route == NULL) {
        return LIBBGP_ERR_INVALID;
    }
    *update_id = route->update_id;
    return LIBBGP_OK;
}

libbgp_err_t bgp_rib6_exact_update_id(
    libbgp_rib6_t *rib,
    uint32_t source_router_id,
    const libbgp_prefix6_t *prefix,
    uint64_t *update_id)
{
    rib6_impl_t *impl = rib6_impl_get(rib);
    libbgp_rib6_route_t *route;

    if (impl == NULL || prefix == NULL) {
        return LIBBGP_ERR_INVALID;
    }
    bgp_lock(&impl->lock);
    route = rib6_find_locked(impl, source_router_id, prefix);
    if (route == NULL) {
        bgp_unlock(&impl->lock);
        return LIBBGP_ERR_NOT_FOUND;
    }
    if (update_id != NULL) {
        *update_id = route->update_id;
    }
    bgp_unlock(&impl->lock);
    return LIBBGP_OK;
}

libbgp_err_t bgp_rib6_withdraw_exact_if_update_id(
    libbgp_rib6_t *rib,
    uint32_t source_router_id,
    const libbgp_prefix6_t *prefix,
    uint64_t update_id)
{
    rib6_impl_t *impl = rib6_impl_get(rib);
    libbgp_rib6_route_t *route;
    libbgp_err_t err = LIBBGP_OK;

    if (impl == NULL || prefix == NULL || update_id == 0u) {
        return LIBBGP_ERR_INVALID;
    }
    bgp_lock(&impl->lock);
    route = rib6_find_locked(impl, source_router_id, prefix);
    if (route == NULL) {
        err = LIBBGP_ERR_NOT_FOUND;
    } else if (route->update_id == update_id) {
        err = rib6_withdraw_locked(impl, source_router_id, prefix);
    }
    bgp_unlock(&impl->lock);
    return err;
}

libbgp_err_t bgp_rib6_withdraw_exact_save(
    libbgp_rib6_t *rib,
    uint32_t source_router_id,
    const libbgp_prefix6_t *prefix,
    bgp_rib6_saved_route_t *saved,
    bool *had_route)
{
    rib6_impl_t *impl = rib6_impl_get(rib);
    bgp_hashmap_entry_t *entry = NULL;
    libbgp_err_t err;

    if (had_route != NULL) {
        *had_route = false;
    }
    if (saved != NULL) {
        saved->entry = NULL;
    }
    if (impl == NULL || prefix == NULL || saved == NULL) {
        return LIBBGP_ERR_INVALID;
    }
    bgp_lock(&impl->lock);
    err = rib6_detach_locked(impl, source_router_id, prefix, &entry);
    bgp_unlock(&impl->lock);
    if (err == LIBBGP_ERR_NOT_FOUND) {
        return LIBBGP_OK;
    }
    if (err != LIBBGP_OK) {
        return err;
    }
    saved->entry = entry;
    if (had_route != NULL) {
        *had_route = true;
    }
    return LIBBGP_OK;
}

libbgp_err_t bgp_rib6_restore_saved_if_absent(
    libbgp_rib6_t *rib,
    uint32_t source_router_id,
    bgp_rib6_saved_route_t *saved)
{
    rib6_impl_t *impl = rib6_impl_get(rib);
    bgp_hashmap_entry_t *entry;
    libbgp_rib6_route_t *route;
    libbgp_err_t err;

    if (impl == NULL || saved == NULL) {
        return LIBBGP_ERR_INVALID;
    }
    if (saved->entry == NULL) {
        return LIBBGP_OK;
    }
    entry = (bgp_hashmap_entry_t *)saved->entry;
    route = (libbgp_rib6_route_t *)entry->value;
    if (route == NULL || route->source_router_id != source_router_id) {
        return LIBBGP_ERR_INVALID;
    }
    bgp_lock(&impl->lock);
    if (rib6_find_locked(impl, source_router_id, &route->prefix) != NULL) {
        bgp_unlock(&impl->lock);
        return LIBBGP_OK;
    }
    err = rib6_attach_detached_locked(impl, entry);
    if (err == LIBBGP_OK) {
        saved->entry = NULL;
    }
    bgp_unlock(&impl->lock);
    return err;
}
