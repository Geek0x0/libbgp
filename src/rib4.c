#include "libbgp/rib4.h"

#include <string.h>

#include "hashmap.h"
#include "internal.h"
#include "rib_internal.h"

typedef struct rib4_key {
    libbgp_prefix4_t prefix;
} rib4_key_t;

typedef struct rib4_impl {
    bgp_hashmap_t routes;
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

static int bgp_router_id_cmp(uint32_t a, uint32_t b)
{
    uint8_t a_bytes[4];
    uint8_t b_bytes[4];

    memcpy(a_bytes, &a, sizeof(a_bytes));
    memcpy(b_bytes, &b, sizeof(b_bytes));
    return memcmp(a_bytes, b_bytes, sizeof(a_bytes));
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

static void rib4_entry_free(void *key, void *value, void *ctx)
{
    BGP_UNUSED(ctx);
    bgp_free(key);
    rib4_route_free((libbgp_rib4_route_t *)value);
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

static bool rib4_better(const libbgp_rib4_route_t *a, const libbgp_rib4_route_t *b)
{
    uint32_t a_lp;
    uint32_t b_lp;

    if (b == NULL) {
        return true;
    }
    if (a->is_ibgp != b->is_ibgp) {
        return !a->is_ibgp;
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
    if (a->origin_as == b->origin_as && a->med != b->med) {
        return a->med < b->med;
    }
    if (a->update_id != b->update_id) {
        return a->update_id > b->update_id;
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

    find_key.prefix = *prefix;
    hash = rib4_hash(&find_key, NULL);
    idx = (size_t)(hash % (uint64_t)impl->routes.bucket_count);
    for (entry = impl->routes.buckets[idx]; entry != NULL; entry = entry->next) {
        libbgp_rib4_route_t *route = (libbgp_rib4_route_t *)entry->value;
        if (entry->hash == hash && rib4_key_eq(entry->key, &find_key, NULL) &&
            route->source_router_id == source_router_id) {
            match = route;
            break;
        }
    }
    if (match == NULL) {
        return LIBBGP_ERR_NOT_FOUND;
    }
    return bgp_hashmap_remove_one(&impl->routes, &find_key, match);
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

    if (prefix == NULL) {
        return LIBBGP_ERR_INVALID;
    }
    memset(&route, 0, sizeof(route));
    route.prefix = *prefix;
    route.next_hop = next_hop;
    route.weight = weight;
    route.local_pref = 100u;
    route.origin = 0u;
    route.is_ibgp = false;
    return libbgp_rib4_insert(rib, &route);
}

libbgp_err_t libbgp_rib4_insert(libbgp_rib4_t *rib, const libbgp_rib4_route_t *route)
{
    rib4_impl_t *impl = rib4_impl_get(rib);
    libbgp_rib4_route_t *copy = NULL;
    libbgp_rib4_route_t *old = NULL;
    rib4_key_t *key = NULL;
    libbgp_err_t err;

    if (impl == NULL || route == NULL) {
        return LIBBGP_ERR_INVALID;
    }

    bgp_lock(&impl->lock);
    err = rib4_route_clone(impl, route, &copy, &key);
    if (err == LIBBGP_OK) {
        old = rib4_find_locked(impl, copy->source_router_id, &copy->prefix);
        err = bgp_hashmap_insert(&impl->routes, key, copy);
        if (err != LIBBGP_OK) {
            bgp_free(key);
            rib4_route_free(copy);
        } else if (old != NULL) {
            rib4_key_t old_key;

            old_key.prefix = copy->prefix;
            (void)bgp_hashmap_remove_one(&impl->routes, &old_key, old);
        }
    }
    bgp_unlock(&impl->lock);
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
    bool removed;

    if (impl == NULL) {
        return LIBBGP_ERR_INVALID;
    }

    bgp_lock(&impl->lock);
    do {
        size_t i;
        libbgp_rib4_route_t *match = NULL;
        rib4_key_t key;

        removed = false;
        for (i = 0u; i < impl->routes.bucket_count && match == NULL; i++) {
            bgp_hashmap_entry_t *entry;
            for (entry = impl->routes.buckets[i]; entry != NULL; entry = entry->next) {
                libbgp_rib4_route_t *route = (libbgp_rib4_route_t *)entry->value;
                if (route->source_router_id == source_router_id) {
                    key.prefix = route->prefix;
                    match = route;
                    break;
                }
            }
        }
        if (match != NULL) {
            (void)bgp_hashmap_remove_one(&impl->routes, &key, match);
            removed = true;
        }
    } while (removed);
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
            if (!rib4_addr_matches(&route->prefix, dest_addr)) {
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

void libbgp_rib4_saved_route_destroy(libbgp_rib4_saved_route_t *saved)
{
    if (saved == NULL || saved->entry == NULL) {
        return;
    }
    rib4_detached_entry_free((bgp_hashmap_entry_t *)saved->entry);
    saved->entry = NULL;
}

libbgp_err_t libbgp_rib4_exact_update_id(
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

libbgp_err_t libbgp_rib4_withdraw_exact_if_update_id(
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

libbgp_err_t libbgp_rib4_withdraw_exact_save(
    libbgp_rib4_t *rib,
    uint32_t source_router_id,
    const libbgp_prefix4_t *prefix,
    libbgp_rib4_saved_route_t *saved,
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

libbgp_err_t libbgp_rib4_restore_saved_if_absent(
    libbgp_rib4_t *rib,
    uint32_t source_router_id,
    libbgp_rib4_saved_route_t *saved)
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
