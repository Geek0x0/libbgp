#include "libbgp/rib6.h"

#include <string.h>

#include "hashmap.h"
#include "internal.h"
#include "rib_internal.h"

typedef struct rib6_key {
    libbgp_prefix6_t prefix;
} rib6_key_t;

typedef struct rib6_impl {
    bgp_hashmap_t routes;
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

static int bgp_router_id_cmp(uint32_t a, uint32_t b)
{
    uint8_t a_bytes[4];
    uint8_t b_bytes[4];

    memcpy(a_bytes, &a, sizeof(a_bytes));
    memcpy(b_bytes, &b, sizeof(b_bytes));
    return memcmp(a_bytes, b_bytes, sizeof(a_bytes));
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

static void rib6_entry_free(void *key, void *value, void *ctx)
{
    BGP_UNUSED(ctx);
    bgp_free(key);
    rib6_route_free((libbgp_rib6_route_t *)value);
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

static bool rib6_better(const libbgp_rib6_route_t *a, const libbgp_rib6_route_t *b)
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

    find_key.prefix = *prefix;
    hash = rib6_hash(&find_key, NULL);
    idx = (size_t)(hash % (uint64_t)impl->routes.bucket_count);
    for (entry = impl->routes.buckets[idx]; entry != NULL; entry = entry->next) {
        libbgp_rib6_route_t *route = (libbgp_rib6_route_t *)entry->value;
        if (entry->hash == hash && rib6_key_eq(entry->key, &find_key, NULL) &&
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

libbgp_err_t bgp_rib6_insert_save_replaced(
    libbgp_rib6_t *rib,
    const libbgp_rib6_route_t *route,
    bgp_rib6_saved_route_t *replaced,
    bool *had_replaced,
    uint64_t *update_id)
{
    rib6_impl_t *impl = rib6_impl_get(rib);
    libbgp_rib6_route_t *copy = NULL;
    libbgp_rib6_route_t *old = NULL;
    bgp_hashmap_entry_t *old_entry = NULL;
    rib6_key_t *key = NULL;
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
        } else if (old != NULL) {
            err = rib6_detach_value_locked(impl, &copy->prefix, old, &old_entry);
            if (err == LIBBGP_ERR_NOT_FOUND) {
                err = LIBBGP_OK;
            } else if (err == LIBBGP_OK) {
                if (replaced != NULL) {
                    replaced->entry = old_entry;
                    old_entry = NULL;
                }
                if (had_replaced != NULL) {
                    *had_replaced = true;
                }
            }
            if (err == LIBBGP_OK && update_id != NULL) {
                *update_id = copy->update_id;
            }
        } else if (update_id != NULL) {
            *update_id = copy->update_id;
        }
    }
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
    bool removed;

    if (impl == NULL) {
        return LIBBGP_ERR_INVALID;
    }

    bgp_lock(&impl->lock);
    do {
        size_t i;
        libbgp_rib6_route_t *match = NULL;
        rib6_key_t key;

        removed = false;
        for (i = 0u; i < impl->routes.bucket_count && match == NULL; i++) {
            bgp_hashmap_entry_t *entry;
            for (entry = impl->routes.buckets[i]; entry != NULL; entry = entry->next) {
                libbgp_rib6_route_t *route = (libbgp_rib6_route_t *)entry->value;
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
