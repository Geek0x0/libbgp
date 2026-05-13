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

static void rib4_key_only_free(void *key, void *value, void *ctx)
{
    BGP_UNUSED(value);
    BGP_UNUSED(ctx);
    bgp_free(key);
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

static size_t rib4_remove_source_locked(rib4_impl_t *impl, uint32_t source_router_id)
{
    size_t removed = 0u;
    size_t i;

    for (i = 0u; i < impl->routes.bucket_count; i++) {
        bgp_hashmap_entry_t **link = &impl->routes.buckets[i];

        while (*link != NULL) {
            bgp_hashmap_entry_t *entry = *link;
            libbgp_rib4_route_t *route = (libbgp_rib4_route_t *)entry->value;

            if (route->source_router_id != source_router_id) {
                link = &entry->next;
                continue;
            }
            *link = entry->next;
            if (impl->routes.free_entry != NULL) {
                impl->routes.free_entry(entry->key, entry->value, impl->routes.ctx);
            }
            bgp_free(entry);
            impl->routes.len--;
            removed++;
        }
    }
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

static libbgp_err_t rib4_prefix_array_push(
    libbgp_prefix4_t **items,
    size_t *count,
    const libbgp_prefix4_t *prefix)
{
    libbgp_prefix4_t *next;

    if (items == NULL || count == NULL || prefix == NULL) {
        return LIBBGP_ERR_INVALID;
    }
    if (*count == SIZE_MAX || *count + 1u > SIZE_MAX / sizeof(**items)) {
        return LIBBGP_ERR_NOMEM;
    }
    next = (libbgp_prefix4_t *)bgp_realloc(*items, (*count + 1u) * sizeof(**items));
    if (next == NULL) {
        return LIBBGP_ERR_NOMEM;
    }
    *items = next;
    (*items)[*count] = *prefix;
    (*count)++;
    return LIBBGP_OK;
}

static libbgp_err_t rib4_result_add_replacement(
    bgp_rib4_discard_result_t *result,
    const libbgp_rib4_route_t *route)
{
    libbgp_rib4_route_t *next;
    libbgp_err_t err;

    if (result == NULL || route == NULL) {
        return LIBBGP_ERR_INVALID;
    }
    if (result->replacement_count == SIZE_MAX ||
        result->replacement_count + 1u > SIZE_MAX / sizeof(*result->replacements)) {
        return LIBBGP_ERR_NOMEM;
    }
    next = (libbgp_rib4_route_t *)bgp_realloc(
        result->replacements,
        (result->replacement_count + 1u) * sizeof(*result->replacements));
    if (next == NULL) {
        return LIBBGP_ERR_NOMEM;
    }
    result->replacements = next;
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
        } else if (old != NULL) {
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
        } else if (update_id != NULL) {
            *update_id = copy->update_id;
        }
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
    {
        bgp_hashmap_t best_by_prefix;

        memset(&best_by_prefix, 0, sizeof(best_by_prefix));
        err = bgp_hashmap_init(&best_by_prefix, rib4_hash, rib4_key_eq, rib4_key_only_free, NULL);
        for (i = 0u; i < impl->routes.bucket_count && err == LIBBGP_OK; i++) {
            bgp_hashmap_entry_t *entry;

            for (entry = impl->routes.buckets[i]; entry != NULL; entry = entry->next) {
                libbgp_rib4_route_t *current = (libbgp_rib4_route_t *)entry->value;
                libbgp_rib4_route_t *best = (libbgp_rib4_route_t *)bgp_hashmap_find_first(&best_by_prefix, entry->key);

                if (best == NULL) {
                    rib4_key_t *key = (rib4_key_t *)bgp_malloc(sizeof(*key));
                    if (key == NULL) {
                        err = LIBBGP_ERR_NOMEM;
                        break;
                    }
                    key->prefix = current->prefix;
                    err = bgp_hashmap_insert(&best_by_prefix, key, current);
                    if (err != LIBBGP_OK) {
                        bgp_free(key);
                        break;
                    }
                } else if (rib4_better(current, best)) {
                    (void)bgp_hashmap_remove_one(&best_by_prefix, entry->key, best);
                    {
                        rib4_key_t *key = (rib4_key_t *)bgp_malloc(sizeof(*key));
                        if (key == NULL) {
                            err = LIBBGP_ERR_NOMEM;
                            break;
                        }
                        key->prefix = current->prefix;
                        err = bgp_hashmap_insert(&best_by_prefix, key, current);
                        if (err != LIBBGP_OK) {
                            bgp_free(key);
                            break;
                        }
                    }
                }
            }
        }
        if (err == LIBBGP_OK) {
            for (i = 0u; i < best_by_prefix.bucket_count && err == LIBBGP_OK; i++) {
                bgp_hashmap_entry_t *entry;

                for (entry = best_by_prefix.buckets[i]; entry != NULL; entry = entry->next) {
                    const libbgp_rib4_route_t *current = (const libbgp_rib4_route_t *)entry->value;

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
        }
        bgp_hashmap_destroy(&best_by_prefix);
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
    size_t i;
    libbgp_err_t err = LIBBGP_OK;

    if (result != NULL) {
        memset(result, 0, sizeof(*result));
    }
    if (impl == NULL || result == NULL) {
        return LIBBGP_ERR_INVALID;
    }

    bgp_lock(&impl->lock);
    for (i = 0u; i < impl->routes.bucket_count && err == LIBBGP_OK; i++) {
        bgp_hashmap_entry_t *entry;

        for (entry = impl->routes.buckets[i]; entry != NULL; entry = entry->next) {
            libbgp_rib4_route_t *route = (libbgp_rib4_route_t *)entry->value;

            if (route->source_router_id == source_router_id &&
                rib4_best_exact_locked(impl, &route->prefix) == route) {
                err = rib4_prefix_array_push(&active_prefixes, &active_count, &route->prefix);
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
            err = rib4_prefix_array_push(&result->withdrawn, &result->withdrawn_count, &active_prefixes[i]);
        } else {
            err = rib4_result_add_replacement(result, replacement);
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
