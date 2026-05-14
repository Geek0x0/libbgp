#include "libbgp/rib4.h"

#include <string.h>

#include "hashmap.h"
#include "internal.h"
#include "radix4.h"
#include "rib_internal.h"

typedef struct rib4_key {
    libbgp_prefix4_t prefix;
} rib4_key_t;

typedef struct rib4_source_key {
    uint32_t source_router_id;
} rib4_source_key_t;

typedef struct rib4_source_entry {
    uint32_t source_router_id;
    bgp_hashmap_entry_t **entries;
    size_t count;
    size_t cap;
} rib4_source_entry_t;

typedef struct rib4_lpm_key {
    libbgp_prefix4_t prefix;
} rib4_lpm_key_t;

typedef struct rib4_lpm_entry {
    libbgp_prefix4_t prefix;
    bgp_hashmap_entry_t **entries;
    size_t count;
    size_t cap;
    libbgp_rib4_route_t *best;
} rib4_lpm_entry_t;

typedef struct rib4_impl {
    bgp_hashmap_t routes;
    bgp_hashmap_t sources;
    bgp_hashmap_t lpm_groups;
    bgp_radix4_t lpm_tree;
    bgp_lock_t lock;
    uint64_t next_update_id;
} rib4_impl_t;

static uint64_t hash_u64_mix(uint64_t x)
{
    x ^= x >> 33;
    x *= 0xff51afd7ed558ccdull;
    x ^= x >> 33;
    x *= 0xc4ceb9fe1a85ec53ull;
    x ^= x >> 33;
    return x;
}

static uint64_t rib4_hash(const void *key, void *ctx)
{
    const rib4_key_t *k = (const rib4_key_t *)key;

    BGP_UNUSED(ctx);
    return hash_u64_mix((uint64_t)k->prefix.addr ^ ((uint64_t)k->prefix.len << 32));
}

static bool rib4_key_eq(const void *a, const void *b, void *ctx)
{
    const rib4_key_t *ka = (const rib4_key_t *)a;
    const rib4_key_t *kb = (const rib4_key_t *)b;

    BGP_UNUSED(ctx);
    return libbgp_prefix4_eq(&ka->prefix, &kb->prefix);
}

static uint64_t rib4_source_hash(const void *key, void *ctx)
{
    const rib4_source_key_t *k = (const rib4_source_key_t *)key;

    BGP_UNUSED(ctx);
    return hash_u64_mix((uint64_t)k->source_router_id);
}

static bool rib4_source_key_eq(const void *a, const void *b, void *ctx)
{
    BGP_UNUSED(ctx);
    return ((const rib4_source_key_t *)a)->source_router_id ==
           ((const rib4_source_key_t *)b)->source_router_id;
}

static libbgp_prefix4_t rib4_lpm_normalize_prefix(const libbgp_prefix4_t *prefix)
{
    libbgp_prefix4_t normalized;

    memset(&normalized, 0, sizeof(normalized));
    if (prefix == NULL || prefix->len > 32u) {
        return normalized;
    }
    normalized = *prefix;
    normalized.addr &= libbgp_cidr_to_mask(prefix->len);
    return normalized;
}

static uint64_t rib4_lpm_hash(const void *key, void *ctx)
{
    const rib4_lpm_key_t *k = (const rib4_lpm_key_t *)key;

    BGP_UNUSED(ctx);
    return hash_u64_mix((uint64_t)k->prefix.addr ^ ((uint64_t)k->prefix.len << 32));
}

static bool rib4_lpm_key_eq(const void *a, const void *b, void *ctx)
{
    const rib4_lpm_key_t *ka = (const rib4_lpm_key_t *)a;
    const rib4_lpm_key_t *kb = (const rib4_lpm_key_t *)b;

    BGP_UNUSED(ctx);
    return libbgp_prefix4_eq(&ka->prefix, &kb->prefix);
}

static int bgp_router_id_cmp(uint32_t a, uint32_t b)
{
    /*
     * source_router_id values are stored as NBO bytes in a uint32_t (see rib4.h).
     * Compare byte-by-byte in memory order so that the comparison reflects
     * dotted-decimal (first-octet-first) ordering per RFC 4271 §9.1.2.2.
     */
    uint8_t buf_a[4];
    uint8_t buf_b[4];

    memcpy(buf_a, &a, sizeof(buf_a));
    memcpy(buf_b, &b, sizeof(buf_b));
    return memcmp(buf_a, buf_b, sizeof(buf_a));
}

static void rib4_route_free(libbgp_rib4_route_t *route)
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

static void rib4_route_snapshot_clear(libbgp_rib4_route_t *route)
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

libbgp_err_t bgp_rib4_route_snapshot_clone(
    const libbgp_rib4_route_t *src,
    libbgp_rib4_route_t *dst)
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

static void rib4_entry_free(void *key, void *value, void *ctx)
{
    BGP_UNUSED(ctx);
    bgp_free(key);
    rib4_route_free((libbgp_rib4_route_t *)value);
}

static void rib4_source_entry_free(void *key, void *value, void *ctx)
{
    rib4_source_entry_t *entry = (rib4_source_entry_t *)value;

    BGP_UNUSED(ctx);
    bgp_free(key);
    if (entry != NULL) {
        bgp_free(entry->entries);
        bgp_free(entry);
    }
}

static void rib4_lpm_entry_free(void *key, void *value, void *ctx)
{
    rib4_lpm_entry_t *entry = (rib4_lpm_entry_t *)value;

    BGP_UNUSED(ctx);
    bgp_free(key);
    if (entry != NULL) {
        bgp_free(entry->entries);
        bgp_free(entry);
    }
}

static rib4_impl_t *rib4_impl_get(const libbgp_rib4_t *rib)
{
    return rib == NULL ? NULL : (rib4_impl_t *)rib->impl;
}

static uint64_t rib4_next_update_id(rib4_impl_t *impl)
{
    impl->next_update_id++;
    if (impl->next_update_id == 0u) {
        impl->next_update_id++;
    }
    return impl->next_update_id;
}

static rib4_source_entry_t *rib4_source_index_find(
    rib4_impl_t *impl,
    uint32_t source_router_id)
{
    rib4_source_key_t find_key;

    find_key.source_router_id = source_router_id;
    return (rib4_source_entry_t *)bgp_hashmap_find_first(&impl->sources, &find_key);
}

static libbgp_err_t rib4_source_index_add(
    rib4_impl_t *impl,
    bgp_hashmap_entry_t *route_entry)
{
    libbgp_rib4_route_t *route;
    rib4_source_entry_t *source;

    if (impl == NULL || route_entry == NULL || route_entry->value == NULL) {
        return LIBBGP_ERR_INVALID;
    }
    route = (libbgp_rib4_route_t *)route_entry->value;
    source = rib4_source_index_find(impl, route->source_router_id);
    if (source == NULL) {
        rib4_source_key_t *key;

        key = (rib4_source_key_t *)bgp_malloc(sizeof(*key));
        if (key == NULL) {
            return LIBBGP_ERR_NOMEM;
        }
        source = (rib4_source_entry_t *)bgp_calloc(1u, sizeof(*source));
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

static void rib4_source_index_remove(rib4_impl_t *impl, bgp_hashmap_entry_t *route_entry)
{
    libbgp_rib4_route_t *route;
    rib4_source_entry_t *source;
    size_t i;

    if (impl == NULL || route_entry == NULL || route_entry->value == NULL) {
        return;
    }
    route = (libbgp_rib4_route_t *)route_entry->value;
    source = rib4_source_index_find(impl, route->source_router_id);
    if (source == NULL) {
        return;
    }
    for (i = 0u; i < source->count; i++) {
        if (source->entries[i] == route_entry) {
            source->count--;
            source->entries[i] = source->entries[source->count];
            if (source->count == 0u) {
                rib4_source_key_t find_key;

                find_key.source_router_id = route->source_router_id;
                (void)bgp_hashmap_remove_one(&impl->sources, &find_key, source);
            }
            return;
        }
    }
}

static libbgp_err_t rib4_route_clone(
    rib4_impl_t *impl,
    const libbgp_rib4_route_t *src,
    libbgp_rib4_route_t **out_route,
    rib4_key_t **out_key)
{
    libbgp_rib4_route_t *route;
    rib4_key_t *key;
    size_t i;

    if (src->prefix.len > 32u || (src->attr_count != 0u && src->attrs == NULL)) {
        return LIBBGP_ERR_INVALID;
    }

    route = (libbgp_rib4_route_t *)bgp_calloc(1u, sizeof(*route));
    if (route == NULL) {
        return LIBBGP_ERR_NOMEM;
    }
    *route = *src;
    if (route->local_pref == 0u) {
        route->local_pref = 100u;
    }
    if (route->update_id == 0u) {
        route->update_id = rib4_next_update_id(impl);
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

    key = (rib4_key_t *)bgp_malloc(sizeof(*key));
    if (key == NULL) {
        rib4_route_free(route);
        return LIBBGP_ERR_NOMEM;
    }
    key->prefix = route->prefix;

    *out_route = route;
    *out_key = key;
    return LIBBGP_OK;
}

static bool rib4_neighbor_as(const libbgp_rib4_route_t *route, uint32_t *neighbor_as)
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

static bool rib4_better(const libbgp_rib4_route_t *a, const libbgp_rib4_route_t *b)
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
    if (a->med != b->med && rib4_neighbor_as(a, &a_neighbor_as) &&
        rib4_neighbor_as(b, &b_neighbor_as) && a_neighbor_as == b_neighbor_as) {
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

static bool rib4_addr_matches(const libbgp_prefix4_t *prefix, uint32_t dest)
{
    uint32_t mask;

    if (prefix == NULL || prefix->len > 32u) {
        return false;
    }
    mask = libbgp_cidr_to_mask(prefix->len);
    return (dest & mask) == (prefix->addr & mask);
}

static libbgp_rib4_route_t *rib4_find_locked(
    rib4_impl_t *impl,
    uint32_t source_router_id,
    const libbgp_prefix4_t *prefix);

static libbgp_rib4_route_t *rib4_best_exact_locked(
    rib4_impl_t *impl,
    const libbgp_prefix4_t *prefix);

static libbgp_err_t rib4_lpm_index_add_locked(
    rib4_impl_t *impl,
    bgp_hashmap_entry_t *route_entry);

static void rib4_lpm_index_remove_locked(
    rib4_impl_t *impl,
    bgp_hashmap_entry_t *route_entry);

static bool rib4_route_entry_unlink_locked(rib4_impl_t *impl, bgp_hashmap_entry_t *entry)
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

static bgp_hashmap_entry_t *rib4_entry_find_value_locked(
    rib4_impl_t *impl,
    const libbgp_prefix4_t *prefix,
    const libbgp_rib4_route_t *value)
{
    rib4_key_t find_key;
    bgp_hashmap_entry_t *entry;
    uint64_t hash;
    size_t idx;

    if (impl == NULL || prefix == NULL || value == NULL) {
        return NULL;
    }
    find_key.prefix = *prefix;
    hash = rib4_hash(&find_key, NULL);
    idx = (size_t)(hash % (uint64_t)impl->routes.bucket_count);
    for (entry = impl->routes.buckets[idx]; entry != NULL; entry = entry->next) {
        if (entry->hash == hash && entry->value == value &&
            rib4_key_eq(entry->key, &find_key, NULL)) {
            return entry;
        }
    }
    return NULL;
}

static size_t rib4_remove_source_locked(rib4_impl_t *impl, uint32_t source_router_id)
{
    rib4_source_key_t find_key;
    rib4_source_entry_t *source;
    size_t removed = 0u;
    size_t i;

    find_key.source_router_id = source_router_id;
    source = (rib4_source_entry_t *)bgp_hashmap_find_first(&impl->sources, &find_key);
    if (source == NULL) {
        return 0u;
    }
    for (i = 0u; i < source->count; i++) {
        bgp_hashmap_entry_t *entry = source->entries[i];

        if (rib4_route_entry_unlink_locked(impl, entry)) {
            rib4_lpm_index_remove_locked(impl, entry);
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

static libbgp_err_t rib4_withdraw_locked(
    rib4_impl_t *impl,
    uint32_t source_router_id,
    const libbgp_prefix4_t *prefix)
{
    rib4_key_t find_key;
    size_t idx;
    uint64_t hash;
    bgp_hashmap_entry_t *entry;
    libbgp_rib4_route_t *match = NULL;
    bgp_hashmap_entry_t *match_entry = NULL;

    find_key.prefix = *prefix;
    hash = rib4_hash(&find_key, NULL);
    idx = (size_t)(hash % (uint64_t)impl->routes.bucket_count);
    for (entry = impl->routes.buckets[idx]; entry != NULL; entry = entry->next) {
        libbgp_rib4_route_t *route = (libbgp_rib4_route_t *)entry->value;
        if (entry->hash == hash && rib4_key_eq(entry->key, &find_key, NULL) &&
            route->source_router_id == source_router_id) {
            match = route;
            match_entry = entry;
            break;
        }
    }
    if (match == NULL) {
        return LIBBGP_ERR_NOT_FOUND;
    }
    rib4_source_index_remove(impl, match_entry);
    rib4_lpm_index_remove_locked(impl, match_entry);
    if (bgp_hashmap_remove_one(&impl->routes, &find_key, match) != LIBBGP_OK) {
        return LIBBGP_ERR_NOT_FOUND;
    }
    return LIBBGP_OK;
}

static libbgp_err_t rib4_detach_locked(
    rib4_impl_t *impl,
    uint32_t source_router_id,
    const libbgp_prefix4_t *prefix,
    bgp_hashmap_entry_t **out_entry)
{
    rib4_key_t find_key;
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
    hash = rib4_hash(&find_key, NULL);
    idx = (size_t)(hash % (uint64_t)impl->routes.bucket_count);
    link = &impl->routes.buckets[idx];
    while (*link != NULL) {
        bgp_hashmap_entry_t *entry = *link;
        libbgp_rib4_route_t *route = (libbgp_rib4_route_t *)entry->value;

        if (entry->hash == hash && rib4_key_eq(entry->key, &find_key, NULL) &&
            route->source_router_id == source_router_id) {
            *link = entry->next;
            entry->next = NULL;
            impl->routes.len--;
            rib4_source_index_remove(impl, entry);
            rib4_lpm_index_remove_locked(impl, entry);
            *out_entry = entry;
            return LIBBGP_OK;
        }
        link = &entry->next;
    }
    return LIBBGP_ERR_NOT_FOUND;
}

static libbgp_err_t rib4_detach_value_locked(
    rib4_impl_t *impl,
    const libbgp_prefix4_t *prefix,
    const libbgp_rib4_route_t *value,
    bgp_hashmap_entry_t **out_entry)
{
    rib4_key_t find_key;
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
    hash = rib4_hash(&find_key, NULL);
    idx = (size_t)(hash % (uint64_t)impl->routes.bucket_count);
    link = &impl->routes.buckets[idx];
    while (*link != NULL) {
        bgp_hashmap_entry_t *entry = *link;

        if (entry->hash == hash && rib4_key_eq(entry->key, &find_key, NULL) &&
            entry->value == value) {
            *link = entry->next;
            entry->next = NULL;
            impl->routes.len--;
            rib4_source_index_remove(impl, entry);
            rib4_lpm_index_remove_locked(impl, entry);
            *out_entry = entry;
            return LIBBGP_OK;
        }
        link = &entry->next;
    }
    return LIBBGP_ERR_NOT_FOUND;
}

static libbgp_err_t rib4_attach_detached_locked(rib4_impl_t *impl, bgp_hashmap_entry_t *entry)
{
    libbgp_rib4_route_t *route;
    libbgp_rib4_route_t *old;
    size_t idx;

    if (impl == NULL || entry == NULL || entry->key == NULL || entry->value == NULL) {
        return LIBBGP_ERR_INVALID;
    }
    route = (libbgp_rib4_route_t *)entry->value;
    old = rib4_find_locked(impl, route->source_router_id, &route->prefix);
    if (old != NULL) {
        return LIBBGP_ERR_EXISTS;
    }
    entry->hash = rib4_hash(entry->key, NULL);
    idx = (size_t)(entry->hash % (uint64_t)impl->routes.bucket_count);
    entry->next = impl->routes.buckets[idx];
    impl->routes.buckets[idx] = entry;
    impl->routes.len++;
    if (rib4_source_index_add(impl, entry) != LIBBGP_OK) {
        (void)rib4_route_entry_unlink_locked(impl, entry);
        return LIBBGP_ERR_NOMEM;
    }
    if (rib4_lpm_index_add_locked(impl, entry) != LIBBGP_OK) {
        rib4_source_index_remove(impl, entry);
        (void)rib4_route_entry_unlink_locked(impl, entry);
        return LIBBGP_ERR_NOMEM;
    }
    return LIBBGP_OK;
}

static void rib4_detached_entry_free(bgp_hashmap_entry_t *entry)
{
    if (entry == NULL) {
        return;
    }
    rib4_entry_free(entry->key, entry->value, NULL);
    bgp_free(entry);
}

static libbgp_rib4_route_t *rib4_find_locked(
    rib4_impl_t *impl,
    uint32_t source_router_id,
    const libbgp_prefix4_t *prefix)
{
    rib4_key_t find_key;
    size_t idx;
    uint64_t hash;
    bgp_hashmap_entry_t *entry;

    find_key.prefix = *prefix;
    hash = rib4_hash(&find_key, NULL);
    idx = (size_t)(hash % (uint64_t)impl->routes.bucket_count);
    for (entry = impl->routes.buckets[idx]; entry != NULL; entry = entry->next) {
        libbgp_rib4_route_t *route = (libbgp_rib4_route_t *)entry->value;
        if (entry->hash == hash && rib4_key_eq(entry->key, &find_key, NULL) &&
            route->source_router_id == source_router_id) {
            return route;
        }
    }
    return NULL;
}

static libbgp_rib4_route_t *rib4_best_exact_locked(
    rib4_impl_t *impl,
    const libbgp_prefix4_t *prefix)
{
    rib4_key_t find_key;
    size_t idx;
    uint64_t hash;
    bgp_hashmap_entry_t *entry;
    libbgp_rib4_route_t *best = NULL;

    if (impl == NULL || prefix == NULL) {
        return NULL;
    }
    find_key.prefix = *prefix;
    hash = rib4_hash(&find_key, NULL);
    idx = (size_t)(hash % (uint64_t)impl->routes.bucket_count);
    for (entry = impl->routes.buckets[idx]; entry != NULL; entry = entry->next) {
        libbgp_rib4_route_t *route = (libbgp_rib4_route_t *)entry->value;

        if (entry->hash == hash && rib4_key_eq(entry->key, &find_key, NULL) &&
            libbgp_prefix4_eq(&route->prefix, prefix) &&
            (best == NULL || rib4_better(route, best))) {
            best = route;
        }
    }
    return best;
}

static rib4_lpm_entry_t *rib4_lpm_group_find_locked(
    rib4_impl_t *impl,
    const libbgp_prefix4_t *prefix)
{
    rib4_lpm_key_t find_key;

    if (impl == NULL || prefix == NULL || prefix->len > 32u) {
        return NULL;
    }
    find_key.prefix = rib4_lpm_normalize_prefix(prefix);
    return (rib4_lpm_entry_t *)bgp_hashmap_find_first(&impl->lpm_groups, &find_key);
}

static libbgp_rib4_route_t *rib4_lpm_group_best_locked(const rib4_lpm_entry_t *group)
{
    libbgp_rib4_route_t *best = NULL;
    size_t i;

    if (group == NULL) {
        return NULL;
    }
    for (i = 0u; i < group->count; i++) {
        libbgp_rib4_route_t *route = (libbgp_rib4_route_t *)group->entries[i]->value;

        if (best == NULL || rib4_better(route, best)) {
            best = route;
        }
    }
    return best;
}

static void rib4_lpm_group_remove_locked(rib4_impl_t *impl, rib4_lpm_entry_t *group)
{
    rib4_lpm_key_t find_key;

    if (impl == NULL || group == NULL) {
        return;
    }
    find_key.prefix = group->prefix;
    (void)bgp_hashmap_remove_one(&impl->lpm_groups, &find_key, group);
}

static void rib4_lpm_index_remove_locked(rib4_impl_t *impl, bgp_hashmap_entry_t *route_entry)
{
    libbgp_rib4_route_t *route;
    rib4_lpm_entry_t *group;
    size_t i;

    if (impl == NULL || route_entry == NULL || route_entry->value == NULL) {
        return;
    }
    route = (libbgp_rib4_route_t *)route_entry->value;
    group = rib4_lpm_group_find_locked(impl, &route->prefix);
    if (group == NULL) {
        return;
    }
    for (i = 0u; i < group->count; i++) {
        if (group->entries[i] == route_entry) {
            bool removed_best = group->best == route;

            group->count--;
            group->entries[i] = group->entries[group->count];
            if (group->count == 0u) {
                (void)bgp_radix4_remove(&impl->lpm_tree, group->prefix.addr, group->prefix.len);
                rib4_lpm_group_remove_locked(impl, group);
                return;
            }
            if (removed_best || group->best == NULL) {
                group->best = rib4_lpm_group_best_locked(group);
                if (group->best != NULL) {
                    (void)bgp_radix4_insert(
                        &impl->lpm_tree,
                        group->prefix.addr,
                        group->prefix.len,
                        group->best);
                }
            }
            return;
        }
    }
}

static libbgp_err_t rib4_lpm_index_add_locked(rib4_impl_t *impl, bgp_hashmap_entry_t *route_entry)
{
    libbgp_rib4_route_t *route;
    rib4_lpm_key_t find_key;
    rib4_lpm_entry_t *group;
    bool created = false;

    if (impl == NULL || route_entry == NULL || route_entry->value == NULL) {
        return LIBBGP_ERR_INVALID;
    }
    route = (libbgp_rib4_route_t *)route_entry->value;
    find_key.prefix = rib4_lpm_normalize_prefix(&route->prefix);
    group = (rib4_lpm_entry_t *)bgp_hashmap_find_first(&impl->lpm_groups, &find_key);
    if (group == NULL) {
        rib4_lpm_key_t *key;

        key = (rib4_lpm_key_t *)bgp_malloc(sizeof(*key));
        if (key == NULL) {
            return LIBBGP_ERR_NOMEM;
        }
        group = (rib4_lpm_entry_t *)bgp_calloc(1u, sizeof(*group));
        if (group == NULL) {
            bgp_free(key);
            return LIBBGP_ERR_NOMEM;
        }
        group->entries = (bgp_hashmap_entry_t **)bgp_malloc(sizeof(*group->entries));
        if (group->entries == NULL) {
            bgp_free(group);
            bgp_free(key);
            return LIBBGP_ERR_NOMEM;
        }
        key->prefix = find_key.prefix;
        group->prefix = find_key.prefix;
        group->cap = 1u;
        if (bgp_hashmap_insert(&impl->lpm_groups, key, group) != LIBBGP_OK) {
            bgp_free(group->entries);
            bgp_free(group);
            bgp_free(key);
            return LIBBGP_ERR_NOMEM;
        }
        created = true;
    } else if (group->count >= group->cap) {
        bgp_hashmap_entry_t **next;
        size_t next_cap = group->cap == 0u ? 1u : group->cap * 2u;

        if (group->cap > SIZE_MAX / 2u ||
            next_cap > SIZE_MAX / sizeof(*group->entries)) {
            return LIBBGP_ERR_NOMEM;
        }
        next = (bgp_hashmap_entry_t **)bgp_realloc(
            group->entries,
            next_cap * sizeof(*group->entries));
        if (next == NULL) {
            return LIBBGP_ERR_NOMEM;
        }
        group->entries = next;
        group->cap = next_cap;
    }

    group->entries[group->count] = route_entry;
    group->count++;
    if (group->best == NULL || rib4_better(route, group->best)) {
        libbgp_err_t err = bgp_radix4_insert(
            &impl->lpm_tree,
            group->prefix.addr,
            group->prefix.len,
            route);

        if (err != LIBBGP_OK) {
            group->count--;
            if (created) {
                rib4_lpm_group_remove_locked(impl, group);
            }
            return err;
        }
        group->best = route;
    }
    return LIBBGP_OK;
}

static libbgp_err_t rib4_prefix_array_push(
    libbgp_prefix4_t **items,
    size_t *count,
    size_t *cap,
    const libbgp_prefix4_t *prefix)
{
    libbgp_prefix4_t *next;
    size_t new_cap;

    if (items == NULL || count == NULL || cap == NULL || prefix == NULL) {
        return LIBBGP_ERR_INVALID;
    }
    if (*count >= *cap) {
        if (*cap == 0u) {
            new_cap = 64u;
        } else {
            if (*cap > SIZE_MAX / 2u) {
                return LIBBGP_ERR_NOMEM;
            }
            new_cap = *cap * 2u;
        }
        if (new_cap <= *count || new_cap > SIZE_MAX / sizeof(**items)) {
            return LIBBGP_ERR_NOMEM;
        }
        next = (libbgp_prefix4_t *)bgp_realloc(*items, new_cap * sizeof(**items));
        if (next == NULL) {
            return LIBBGP_ERR_NOMEM;
        }
        *items = next;
        *cap = new_cap;
    }
    (*items)[*count] = *prefix;
    (*count)++;
    return LIBBGP_OK;
}

static libbgp_err_t rib4_result_add_replacement(
    bgp_rib4_discard_result_t *result,
    size_t *cap,
    const libbgp_rib4_route_t *route)
{
    libbgp_rib4_route_t *next;
    libbgp_err_t err;
    size_t old_cap;
    size_t new_cap;

    if (result == NULL || cap == NULL || route == NULL) {
        return LIBBGP_ERR_INVALID;
    }
    if (result->replacement_count >= *cap) {
        old_cap = *cap;
        if (*cap == 0u) {
            new_cap = 64u;
        } else {
            if (*cap > SIZE_MAX / 2u) {
                return LIBBGP_ERR_NOMEM;
            }
            new_cap = *cap * 2u;
        }
        if (new_cap <= result->replacement_count || new_cap > SIZE_MAX / sizeof(*result->replacements)) {
            return LIBBGP_ERR_NOMEM;
        }
        next = (libbgp_rib4_route_t *)bgp_realloc(
            result->replacements,
            new_cap * sizeof(*result->replacements));
        if (next == NULL) {
            return LIBBGP_ERR_NOMEM;
        }
        result->replacements = next;
        memset(
            &result->replacements[old_cap],
            0,
            (new_cap - old_cap) * sizeof(*result->replacements));
        *cap = new_cap;
    }
    memset(&result->replacements[result->replacement_count], 0, sizeof(result->replacements[result->replacement_count]));
    err = bgp_rib4_route_snapshot_clone(route, &result->replacements[result->replacement_count]);
    if (err != LIBBGP_OK) {
        return err;
    }
    result->replacement_count++;
    return LIBBGP_OK;
}

libbgp_err_t libbgp_rib4_init(libbgp_rib4_t *rib)
{
    rib4_impl_t *impl;
    libbgp_err_t err;

    if (rib == NULL) {
        return LIBBGP_ERR_INVALID;
    }
    rib->impl = NULL;
    impl = (rib4_impl_t *)bgp_calloc(1u, sizeof(*impl));
    if (impl == NULL) {
        return LIBBGP_ERR_NOMEM;
    }
    err = bgp_hashmap_init(&impl->routes, rib4_hash, rib4_key_eq, rib4_entry_free, NULL);
    if (err != LIBBGP_OK) {
        bgp_free(impl);
        return err;
    }
    err = bgp_hashmap_init(
        &impl->sources,
        rib4_source_hash,
        rib4_source_key_eq,
        rib4_source_entry_free,
        NULL);
    if (err != LIBBGP_OK) {
        bgp_hashmap_destroy(&impl->routes);
        bgp_free(impl);
        return err;
    }
    err = bgp_hashmap_init(
        &impl->lpm_groups,
        rib4_lpm_hash,
        rib4_lpm_key_eq,
        rib4_lpm_entry_free,
        NULL);
    if (err != LIBBGP_OK) {
        bgp_hashmap_destroy(&impl->sources);
        bgp_hashmap_destroy(&impl->routes);
        bgp_free(impl);
        return err;
    }
    err = bgp_radix4_init(&impl->lpm_tree);
    if (err != LIBBGP_OK) {
        bgp_hashmap_destroy(&impl->lpm_groups);
        bgp_hashmap_destroy(&impl->sources);
        bgp_hashmap_destroy(&impl->routes);
        bgp_free(impl);
        return err;
    }
    bgp_lock_init(&impl->lock);
    rib->impl = impl;
    return LIBBGP_OK;
}

void libbgp_rib4_destroy(libbgp_rib4_t *rib)
{
    rib4_impl_t *impl = rib4_impl_get(rib);

    if (impl == NULL) {
        return;
    }
    bgp_lock(&impl->lock);
    bgp_radix4_destroy(&impl->lpm_tree);
    bgp_hashmap_destroy(&impl->lpm_groups);
    bgp_hashmap_destroy(&impl->sources);
    bgp_hashmap_destroy(&impl->routes);
    bgp_unlock(&impl->lock);
    bgp_lock_destroy(&impl->lock);
    bgp_free(impl);
    rib->impl = NULL;
}

libbgp_err_t libbgp_rib4_insert_local(
    libbgp_rib4_t *rib,
    const libbgp_prefix4_t *prefix,
    uint32_t next_hop,
    int32_t weight)
{
    libbgp_rib4_route_t route;
    libbgp_pattr_t *attrs[3] = { NULL, NULL, NULL };
    libbgp_err_t err;

    if (prefix == NULL) {
        return LIBBGP_ERR_INVALID;
    }
    attrs[0] = libbgp_pattr_new(LIBBGP_PATTR_ORIGIN);
    attrs[1] = libbgp_pattr_new(LIBBGP_PATTR_AS_PATH);
    attrs[2] = libbgp_pattr_new(LIBBGP_PATTR_NEXT_HOP);
    if (attrs[0] == NULL || attrs[1] == NULL || attrs[2] == NULL) {
        libbgp_pattr_unref(attrs[0]);
        libbgp_pattr_unref(attrs[1]);
        libbgp_pattr_unref(attrs[2]);
        return LIBBGP_ERR_NOMEM;
    }
    attrs[0]->data.origin.origin = 0u;
    attrs[1]->data.as_path.is_4b = true;
    attrs[2]->data.next_hop.next_hop = next_hop;

    memset(&route, 0, sizeof(route));
    route.prefix = *prefix;
    route.next_hop = next_hop;
    route.weight = weight;
    route.local_pref = 100u;
    route.origin = 0u;
    route.is_ibgp = false;
    route.attrs = attrs;
    route.attr_count = 3u;
    err = libbgp_rib4_insert(rib, &route);
    libbgp_pattr_unref(attrs[0]);
    libbgp_pattr_unref(attrs[1]);
    libbgp_pattr_unref(attrs[2]);
    return err;
}

libbgp_err_t libbgp_rib4_insert(libbgp_rib4_t *rib, const libbgp_rib4_route_t *route)
{
    return bgp_rib4_insert_save_replaced(rib, route, NULL, NULL, NULL);
}

static void rib4_change_set(
    bgp_rib4_change_t *change,
    bgp_rib_change_kind_t kind,
    const libbgp_rib4_route_t *best)
{
    change->kind = kind;
    change->best = best;
}

static libbgp_err_t rib4_insert_save_replaced_locked(
    rib4_impl_t *impl,
    const libbgp_rib4_route_t *route,
    bgp_rib4_saved_route_t *replaced,
    bool *had_replaced,
    uint64_t *update_id,
    bgp_hashmap_entry_t **old_entry)
{
    libbgp_rib4_route_t *copy = NULL;
    libbgp_rib4_route_t *old = NULL;
    bgp_hashmap_entry_t *new_entry = NULL;
    rib4_key_t *key = NULL;
    libbgp_err_t err;

    if (old_entry != NULL) {
        *old_entry = NULL;
    }
    old = rib4_find_locked(impl, route->source_router_id, &route->prefix);
    if (route->source_router_id == 0u && old != NULL &&
        replaced == NULL && had_replaced == NULL && update_id == NULL) {
        err = LIBBGP_ERR_EXISTS;
    } else {
        err = rib4_route_clone(impl, route, &copy, &key);
    }
    if (err == LIBBGP_OK) {
        err = bgp_hashmap_insert(&impl->routes, key, copy);
        if (err != LIBBGP_OK) {
            bgp_free(key);
            rib4_route_free(copy);
        } else {
            new_entry = rib4_entry_find_value_locked(impl, &copy->prefix, copy);
            if (new_entry == NULL) {
                err = LIBBGP_ERR_NOT_FOUND;
            } else {
                err = rib4_source_index_add(impl, new_entry);
            }
            if (err != LIBBGP_OK) {
                if (new_entry != NULL && rib4_route_entry_unlink_locked(impl, new_entry)) {
                    rib4_entry_free(new_entry->key, new_entry->value, NULL);
                    bgp_free(new_entry);
                } else {
                    (void)bgp_hashmap_remove_one(&impl->routes, key, copy);
                }
            } else {
                err = rib4_lpm_index_add_locked(impl, new_entry);
                if (err != LIBBGP_OK) {
                    rib4_source_index_remove(impl, new_entry);
                    if (rib4_route_entry_unlink_locked(impl, new_entry)) {
                        rib4_entry_free(new_entry->key, new_entry->value, NULL);
                        bgp_free(new_entry);
                    }
                }
            }
        }
        if (err == LIBBGP_OK && old != NULL) {
            err = rib4_detach_value_locked(impl, &copy->prefix, old, old_entry);
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
    } else if (copy != NULL) {
        bgp_free(key);
        rib4_route_free(copy);
    }
    return err;
}

libbgp_err_t bgp_rib4_insert_track_best(
    libbgp_rib4_t *rib,
    const libbgp_rib4_route_t *route,
    bgp_rib4_change_t *change,
    uint64_t *update_id)
{
    rib4_impl_t *impl = rib4_impl_get(rib);
    const libbgp_rib4_route_t *before = NULL;
    const libbgp_rib4_route_t *after = NULL;
    bgp_hashmap_entry_t *old_entry = NULL;
    bgp_rib_change_kind_t kind;
    libbgp_err_t err;

    if (change != NULL) {
        rib4_change_set(change, BGP_RIB_CHANGE_NO_BEST_CHANGE, NULL);
    }
    if (impl == NULL || route == NULL || change == NULL) {
        return LIBBGP_ERR_INVALID;
    }

    bgp_lock(&impl->lock);
    before = rib4_best_exact_locked(impl, &route->prefix);
    err = rib4_insert_save_replaced_locked(impl, route, NULL, NULL, update_id, &old_entry);
    if (err == LIBBGP_OK) {
        after = rib4_best_exact_locked(impl, &route->prefix);
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
            rib4_change_set(change, kind, after);
        }
    }
    bgp_unlock(&impl->lock);
    rib4_detached_entry_free(old_entry);
    return err;
}

libbgp_err_t bgp_rib4_withdraw_track_best(
    libbgp_rib4_t *rib,
    uint32_t source_router_id,
    const libbgp_prefix4_t *prefix,
    bgp_rib4_change_t *change)
{
    rib4_impl_t *impl = rib4_impl_get(rib);
    const libbgp_rib4_route_t *before = NULL;
    const libbgp_rib4_route_t *after = NULL;
    bool withdrew_best = false;
    libbgp_err_t err;

    if (change != NULL) {
        rib4_change_set(change, BGP_RIB_CHANGE_NO_BEST_CHANGE, NULL);
    }
    if (impl == NULL || prefix == NULL || change == NULL) {
        return LIBBGP_ERR_INVALID;
    }

    bgp_lock(&impl->lock);
    before = rib4_best_exact_locked(impl, prefix);
    withdrew_best = before != NULL && before->source_router_id == source_router_id;
    err = rib4_withdraw_locked(impl, source_router_id, prefix);
    if (err == LIBBGP_OK) {
        after = rib4_best_exact_locked(impl, prefix);
        if (!withdrew_best) {
            rib4_change_set(change, BGP_RIB_CHANGE_NO_BEST_CHANGE, after);
        } else if (after == NULL) {
            rib4_change_set(change, BGP_RIB_CHANGE_UNREACHABLE, NULL);
        } else {
            rib4_change_set(change, BGP_RIB_CHANGE_REPLACEMENT_BEST, after);
        }
    }
    bgp_unlock(&impl->lock);
    return err;
}

libbgp_err_t bgp_rib4_insert_save_replaced(
    libbgp_rib4_t *rib,
    const libbgp_rib4_route_t *route,
    bgp_rib4_saved_route_t *replaced,
    bool *had_replaced,
    uint64_t *update_id)
{
    rib4_impl_t *impl = rib4_impl_get(rib);
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
    err = rib4_insert_save_replaced_locked(impl, route, replaced, had_replaced, update_id, &old_entry);
    bgp_unlock(&impl->lock);
    rib4_detached_entry_free(old_entry);
    return err;
}

libbgp_err_t libbgp_rib4_withdraw(
    libbgp_rib4_t *rib,
    uint32_t source_router_id,
    const libbgp_prefix4_t *prefix)
{
    rib4_impl_t *impl = rib4_impl_get(rib);
    libbgp_err_t err;

    if (impl == NULL || prefix == NULL) {
        return LIBBGP_ERR_INVALID;
    }

    bgp_lock(&impl->lock);
    err = rib4_withdraw_locked(impl, source_router_id, prefix);
    bgp_unlock(&impl->lock);
    return err;
}

libbgp_err_t libbgp_rib4_discard(libbgp_rib4_t *rib, uint32_t source_router_id)
{
    rib4_impl_t *impl = rib4_impl_get(rib);

    if (impl == NULL) {
        return LIBBGP_ERR_INVALID;
    }

    bgp_lock(&impl->lock);
    (void)rib4_remove_source_locked(impl, source_router_id);
    bgp_unlock(&impl->lock);
    return LIBBGP_OK;
}

libbgp_err_t libbgp_rib4_lookup_scoped(
    const libbgp_rib4_t *rib,
    uint32_t source_router_id,
    uint32_t dest_addr,
    const libbgp_rib4_route_t **out_route)
{
    rib4_impl_t *impl = rib4_impl_get(rib);
    const libbgp_rib4_route_t *best = NULL;
    size_t i;

    if (impl == NULL || out_route == NULL) {
        return LIBBGP_ERR_INVALID;
    }

    bgp_lock(&impl->lock);
    for (i = 0u; i < impl->routes.bucket_count; i++) {
        bgp_hashmap_entry_t *entry;
        for (entry = impl->routes.buckets[i]; entry != NULL; entry = entry->next) {
            const libbgp_rib4_route_t *route = (const libbgp_rib4_route_t *)entry->value;
            if (route->source_router_id != source_router_id || !rib4_addr_matches(&route->prefix, dest_addr)) {
                continue;
            }
            if (best == NULL || route->prefix.len > best->prefix.len ||
                (route->prefix.len == best->prefix.len && rib4_better(route, best))) {
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

libbgp_err_t libbgp_rib4_lookup(
    const libbgp_rib4_t *rib,
    uint32_t dest_addr,
    const libbgp_rib4_route_t **out_route)
{
    rib4_impl_t *impl = rib4_impl_get(rib);
    const libbgp_rib4_route_t *best;

    if (impl == NULL || out_route == NULL) {
        return LIBBGP_ERR_INVALID;
    }

    bgp_lock(&impl->lock);
    best = (const libbgp_rib4_route_t *)bgp_radix4_lookup_lpm(&impl->lpm_tree, dest_addr);
    if (best == NULL || !rib4_addr_matches(&best->prefix, dest_addr)) {
        bgp_unlock(&impl->lock);
        return LIBBGP_ERR_NOT_FOUND;
    }
    *out_route = best;
    bgp_unlock(&impl->lock);
    return LIBBGP_OK;
}

size_t libbgp_rib4_route_count(const libbgp_rib4_t *rib)
{
    rib4_impl_t *impl = rib4_impl_get(rib);
    size_t count;

    if (impl == NULL) {
        return 0u;
    }
    bgp_lock(&impl->lock);
    count = bgp_hashmap_len(&impl->routes);
    bgp_unlock(&impl->lock);
    return count;
}

libbgp_err_t bgp_rib4_foreach_route(
    const libbgp_rib4_t *rib,
    bgp_rib4_route_iter_fn fn,
    void *ctx)
{
    rib4_impl_t *impl = rib4_impl_get(rib);
    bool keep_going = true;
    size_t i;

    if (impl == NULL || fn == NULL) {
        return LIBBGP_ERR_INVALID;
    }
    bgp_lock(&impl->lock);
    for (i = 0u; keep_going && i < impl->routes.bucket_count; i++) {
        bgp_hashmap_entry_t *entry;

        for (entry = impl->routes.buckets[i]; entry != NULL; entry = entry->next) {
            keep_going = fn((const libbgp_rib4_route_t *)entry->value, ctx);
            if (!keep_going) {
                break;
            }
        }
    }
    bgp_unlock(&impl->lock);
    return LIBBGP_OK;
}

libbgp_err_t bgp_rib4_foreach_best_route(
    const libbgp_rib4_t *rib,
    bgp_rib4_route_iter_fn fn,
    void *ctx)
{
    rib4_impl_t *impl = rib4_impl_get(rib);
    libbgp_rib4_route_t *routes = NULL;
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
            const libbgp_rib4_route_t *current = (const libbgp_rib4_route_t *)entry->value;
            const libbgp_rib4_route_t *best = rib4_best_exact_locked(impl, &current->prefix);

            if (best != current) {
                continue;
            }

            if (route_count == route_capacity) {
                libbgp_rib4_route_t *next;
                size_t next_capacity = route_capacity == 0u ? 8u : route_capacity * 2u;

                if (route_capacity > SIZE_MAX / 2u ||
                    next_capacity > SIZE_MAX / sizeof(*routes)) {
                    err = LIBBGP_ERR_NOMEM;
                    break;
                }
                next = (libbgp_rib4_route_t *)bgp_realloc(routes, next_capacity * sizeof(*routes));
                if (next == NULL) {
                    err = LIBBGP_ERR_NOMEM;
                    break;
                }
                routes = next;
                memset(&routes[route_capacity], 0, (next_capacity - route_capacity) * sizeof(*routes));
                route_capacity = next_capacity;
            }
            err = bgp_rib4_route_snapshot_clone(current, &routes[route_count]);
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
        rib4_route_snapshot_clear(&routes[i]);
    }
    bgp_free(routes);
    return err;
}

void bgp_rib4_route_snapshot_destroy(libbgp_rib4_route_t *route)
{
    rib4_route_snapshot_clear(route);
}

void bgp_rib4_discard_result_destroy(bgp_rib4_discard_result_t *result)
{
    size_t i;

    if (result == NULL) {
        return;
    }
    for (i = 0u; i < result->replacement_count; i++) {
        rib4_route_snapshot_clear(&result->replacements[i]);
    }
    bgp_free(result->withdrawn);
    bgp_free(result->replacements);
    memset(result, 0, sizeof(*result));
}

libbgp_err_t bgp_rib4_best_exact_clone(
    libbgp_rib4_t *rib,
    const libbgp_prefix4_t *prefix,
    libbgp_rib4_route_t *out_route,
    bool *found)
{
    rib4_impl_t *impl = rib4_impl_get(rib);
    libbgp_rib4_route_t *best;
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
    best = rib4_best_exact_locked(impl, prefix);
    if (best != NULL) {
        err = bgp_rib4_route_snapshot_clone(best, out_route);
        if (err == LIBBGP_OK && found != NULL) {
            *found = true;
        }
    }
    bgp_unlock(&impl->lock);
    return err;
}

libbgp_err_t bgp_rib4_discard_collect(
    libbgp_rib4_t *rib,
    uint32_t source_router_id,
    bgp_rib4_discard_result_t *result)
{
    rib4_impl_t *impl = rib4_impl_get(rib);
    libbgp_prefix4_t *active_prefixes = NULL;
    size_t active_count = 0u;
    size_t active_cap = 0u;
    size_t withdrawn_cap = 0u;
    size_t replacement_cap = 0u;
    rib4_source_entry_t *source;
    size_t i;
    libbgp_err_t err = LIBBGP_OK;

    if (result != NULL) {
        memset(result, 0, sizeof(*result));
    }
    if (impl == NULL || result == NULL) {
        return LIBBGP_ERR_INVALID;
    }

    bgp_lock(&impl->lock);
    source = rib4_source_index_find(impl, source_router_id);
    if (source != NULL) {
        for (i = 0u; i < source->count && err == LIBBGP_OK; i++) {
            bgp_hashmap_entry_t *entry = source->entries[i];
            libbgp_rib4_route_t *route = (libbgp_rib4_route_t *)entry->value;

            if (route->source_router_id == source_router_id &&
                rib4_best_exact_locked(impl, &route->prefix) == route) {
                err = rib4_prefix_array_push(&active_prefixes, &active_count, &active_cap, &route->prefix);
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

    (void)rib4_remove_source_locked(impl, source_router_id);

    for (i = 0u; i < active_count && err == LIBBGP_OK; i++) {
        libbgp_rib4_route_t *replacement = rib4_best_exact_locked(impl, &active_prefixes[i]);

        if (replacement == NULL) {
            err = rib4_prefix_array_push(
                &result->withdrawn,
                &result->withdrawn_count,
                &withdrawn_cap,
                &active_prefixes[i]);
        } else {
            err = rib4_result_add_replacement(result, &replacement_cap, replacement);
        }
    }
    bgp_unlock(&impl->lock);
    bgp_free(active_prefixes);
    if (err != LIBBGP_OK) {
        bgp_rib4_discard_result_destroy(result);
    }
    return err;
}

void bgp_rib4_saved_route_destroy(bgp_rib4_saved_route_t *saved)
{
    if (saved == NULL || saved->entry == NULL) {
        return;
    }
    rib4_detached_entry_free((bgp_hashmap_entry_t *)saved->entry);
    saved->entry = NULL;
}

libbgp_err_t bgp_rib4_saved_route_update_id(
    const bgp_rib4_saved_route_t *saved,
    uint64_t *update_id)
{
    const bgp_hashmap_entry_t *entry;
    const libbgp_rib4_route_t *route;

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
    route = (const libbgp_rib4_route_t *)entry->value;
    if (route == NULL) {
        return LIBBGP_ERR_INVALID;
    }
    *update_id = route->update_id;
    return LIBBGP_OK;
}

libbgp_err_t bgp_rib4_exact_update_id(
    libbgp_rib4_t *rib,
    uint32_t source_router_id,
    const libbgp_prefix4_t *prefix,
    uint64_t *update_id)
{
    rib4_impl_t *impl = rib4_impl_get(rib);
    libbgp_rib4_route_t *route;

    if (impl == NULL || prefix == NULL) {
        return LIBBGP_ERR_INVALID;
    }
    bgp_lock(&impl->lock);
    route = rib4_find_locked(impl, source_router_id, prefix);
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

libbgp_err_t bgp_rib4_withdraw_exact_if_update_id(
    libbgp_rib4_t *rib,
    uint32_t source_router_id,
    const libbgp_prefix4_t *prefix,
    uint64_t update_id)
{
    rib4_impl_t *impl = rib4_impl_get(rib);
    libbgp_rib4_route_t *route;
    libbgp_err_t err = LIBBGP_OK;

    if (impl == NULL || prefix == NULL || update_id == 0u) {
        return LIBBGP_ERR_INVALID;
    }
    bgp_lock(&impl->lock);
    route = rib4_find_locked(impl, source_router_id, prefix);
    if (route == NULL) {
        err = LIBBGP_ERR_NOT_FOUND;
    } else if (route->update_id == update_id) {
        err = rib4_withdraw_locked(impl, source_router_id, prefix);
    }
    bgp_unlock(&impl->lock);
    return err;
}

libbgp_err_t bgp_rib4_withdraw_exact_save(
    libbgp_rib4_t *rib,
    uint32_t source_router_id,
    const libbgp_prefix4_t *prefix,
    bgp_rib4_saved_route_t *saved,
    bool *had_route)
{
    rib4_impl_t *impl = rib4_impl_get(rib);
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
    err = rib4_detach_locked(impl, source_router_id, prefix, &entry);
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

libbgp_err_t bgp_rib4_restore_saved_if_absent(
    libbgp_rib4_t *rib,
    uint32_t source_router_id,
    bgp_rib4_saved_route_t *saved)
{
    rib4_impl_t *impl = rib4_impl_get(rib);
    bgp_hashmap_entry_t *entry;
    libbgp_rib4_route_t *route;
    libbgp_err_t err;

    if (impl == NULL || saved == NULL) {
        return LIBBGP_ERR_INVALID;
    }
    if (saved->entry == NULL) {
        return LIBBGP_OK;
    }
    entry = (bgp_hashmap_entry_t *)saved->entry;
    route = (libbgp_rib4_route_t *)entry->value;
    if (route == NULL || route->source_router_id != source_router_id) {
        return LIBBGP_ERR_INVALID;
    }
    bgp_lock(&impl->lock);
    if (rib4_find_locked(impl, source_router_id, &route->prefix) != NULL) {
        bgp_unlock(&impl->lock);
        return LIBBGP_OK;
    }
    err = rib4_attach_detached_locked(impl, entry);
    if (err == LIBBGP_OK) {
        saved->entry = NULL;
    }
    bgp_unlock(&impl->lock);
    return err;
}
