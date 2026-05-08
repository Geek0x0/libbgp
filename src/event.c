#include "libbgp/event.h"

#include <string.h>

#include "internal.h"

typedef struct event_subscriber {
    uint64_t id;
    libbgp_event_type_t type;
    libbgp_event_cb cb;
    void *ctx;
} event_subscriber_t;

typedef struct event_snapshot {
    libbgp_event_cb cb;
    void *ctx;
} event_snapshot_t;

typedef struct event_bus_impl {
    event_subscriber_t *subs;
    size_t count;
    size_t cap;
    uint64_t next_id;
    bgp_lock_t lock;
} event_bus_impl_t;

static event_bus_impl_t *event_bus_impl_get(const libbgp_event_bus_t *bus)
{
    return bus == NULL ? NULL : (event_bus_impl_t *)bus->impl;
}

static bool event_reserve(event_bus_impl_t *impl, size_t needed)
{
    event_subscriber_t *subs;
    size_t new_cap;

    if (needed <= impl->cap) {
        return true;
    }
    new_cap = impl->cap == 0u ? 4u : impl->cap * 2u;
    while (new_cap < needed) {
        if (new_cap > SIZE_MAX / 2u) {
            return false;
        }
        new_cap *= 2u;
    }
    if (new_cap > SIZE_MAX / sizeof(*impl->subs)) {
        return false;
    }
    subs = (event_subscriber_t *)bgp_realloc(impl->subs, new_cap * sizeof(*impl->subs));
    if (subs == NULL) {
        return false;
    }
    impl->subs = subs;
    impl->cap = new_cap;
    return true;
}

static uint64_t event_next_id(event_bus_impl_t *impl)
{
    impl->next_id++;
    if (impl->next_id == 0u) {
        impl->next_id++;
    }
    return impl->next_id;
}

libbgp_err_t libbgp_event_bus_init(libbgp_event_bus_t *bus)
{
    event_bus_impl_t *impl;

    if (bus == NULL) {
        return LIBBGP_ERR_BAD_LEN;
    }
    bus->impl = NULL;
    impl = (event_bus_impl_t *)bgp_calloc(1u, sizeof(*impl));
    if (impl == NULL) {
        return LIBBGP_ERR_NOMEM;
    }
    bgp_lock_init(&impl->lock);
    bus->impl = impl;
    return LIBBGP_OK;
}

void libbgp_event_bus_destroy(libbgp_event_bus_t *bus)
{
    event_bus_impl_t *impl = event_bus_impl_get(bus);
    event_subscriber_t *subs;

    if (impl == NULL) {
        return;
    }
    bgp_lock(&impl->lock);
    subs = impl->subs;
    impl->subs = NULL;
    impl->count = 0u;
    impl->cap = 0u;
    bus->impl = NULL;
    bgp_unlock(&impl->lock);
    bgp_lock_destroy(&impl->lock);
    bgp_free(subs);
    bgp_free(impl);
}

libbgp_err_t libbgp_event_bus_subscribe(
    libbgp_event_bus_t *bus,
    libbgp_event_type_t type,
    libbgp_event_cb cb,
    void *ctx,
    uint64_t *out_id)
{
    event_bus_impl_t *impl = event_bus_impl_get(bus);
    uint64_t id;

    if (impl == NULL || cb == NULL) {
        return LIBBGP_ERR_BAD_LEN;
    }
    bgp_lock(&impl->lock);
    if (!event_reserve(impl, impl->count + 1u)) {
        bgp_unlock(&impl->lock);
        return LIBBGP_ERR_NOMEM;
    }
    id = event_next_id(impl);
    impl->subs[impl->count].id = id;
    impl->subs[impl->count].type = type;
    impl->subs[impl->count].cb = cb;
    impl->subs[impl->count].ctx = ctx;
    impl->count++;
    bgp_unlock(&impl->lock);
    if (out_id != NULL) {
        *out_id = id;
    }
    return LIBBGP_OK;
}

libbgp_err_t libbgp_event_bus_unsubscribe(libbgp_event_bus_t *bus, uint64_t id)
{
    event_bus_impl_t *impl = event_bus_impl_get(bus);
    size_t i;

    if (impl == NULL) {
        return LIBBGP_ERR_BAD_LEN;
    }
    bgp_lock(&impl->lock);
    for (i = 0u; i < impl->count; i++) {
        if (impl->subs[i].id == id) {
            if (i + 1u < impl->count) {
                memmove(&impl->subs[i], &impl->subs[i + 1u],
                    (impl->count - i - 1u) * sizeof(*impl->subs));
            }
            impl->count--;
            bgp_unlock(&impl->lock);
            return LIBBGP_OK;
        }
    }
    bgp_unlock(&impl->lock);
    return LIBBGP_ERR_NOT_FOUND;
}

size_t libbgp_event_bus_publish(libbgp_event_bus_t *bus, const libbgp_event_t *event)
{
    event_bus_impl_t *impl = event_bus_impl_get(bus);
    event_snapshot_t *snapshot = NULL;
    size_t match_count = 0u;
    size_t i;

    if (impl == NULL || event == NULL) {
        return 0u;
    }
    bgp_lock(&impl->lock);
    for (i = 0u; i < impl->count; i++) {
        if (impl->subs[i].type == event->type) {
            match_count++;
        }
    }
    if (match_count != 0u) {
        if (match_count > SIZE_MAX / sizeof(*snapshot)) {
            bgp_unlock(&impl->lock);
            return 0u;
        }
        snapshot = (event_snapshot_t *)bgp_calloc(match_count, sizeof(*snapshot));
        if (snapshot == NULL) {
            bgp_unlock(&impl->lock);
            return 0u;
        }
        match_count = 0u;
        for (i = 0u; i < impl->count; i++) {
            if (impl->subs[i].type == event->type) {
                snapshot[match_count].cb = impl->subs[i].cb;
                snapshot[match_count].ctx = impl->subs[i].ctx;
                match_count++;
            }
        }
    }
    bgp_unlock(&impl->lock);

    for (i = 0u; i < match_count; i++) {
        snapshot[i].cb(event, snapshot[i].ctx);
    }
    bgp_free(snapshot);
    return match_count;
}

size_t libbgp_event_bus_subscriber_count(const libbgp_event_bus_t *bus)
{
    event_bus_impl_t *impl = event_bus_impl_get(bus);
    size_t count;

    if (impl == NULL) {
        return 0u;
    }
    bgp_lock(&impl->lock);
    count = impl->count;
    bgp_unlock(&impl->lock);
    return count;
}
