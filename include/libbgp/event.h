#ifndef LIBBGP_EVENT_H
#define LIBBGP_EVENT_H


/**
 * @file event.h
 * @brief Synchronous event bus for route, session, collision, and custom events.
 * @ingroup libbgp_event
 */
#include <stddef.h>
#include <stdint.h>

#include "libbgp/types.h"
#include "libbgp/prefix4.h"
#include "libbgp/prefix6.h"
#include "libbgp/update.h"

typedef enum libbgp_event_type {
    LIBBGP_EVENT_ROUTE_ADDED = 1,
    LIBBGP_EVENT_ROUTE_WITHDRAWN = 2,
    LIBBGP_EVENT_SESSION_UP = 3,
    LIBBGP_EVENT_SESSION_DOWN = 4,
    LIBBGP_EVENT_COLLISION = 5,
    LIBBGP_EVENT_CUSTOM = 255
} libbgp_event_type_t;

typedef struct libbgp_event {
    libbgp_event_type_t type;
    uint32_t source_router_id;
    const libbgp_prefix4_t *prefix4;
    const libbgp_prefix6_t *prefix6;
    const libbgp_update_msg_t *update;
    void *user_data;
} libbgp_event_t;

typedef void (*libbgp_event_cb)(const libbgp_event_t *event, void *ctx);

struct libbgp_event_bus {
    void *impl;
};

LIBBGP_API libbgp_err_t libbgp_event_bus_init(libbgp_event_bus_t *bus);
LIBBGP_API void libbgp_event_bus_destroy(libbgp_event_bus_t *bus);
LIBBGP_API libbgp_err_t libbgp_event_bus_subscribe(
    libbgp_event_bus_t *bus,
    libbgp_event_type_t type,
    libbgp_event_cb cb,
    void *ctx,
    uint64_t *out_id);
LIBBGP_API libbgp_err_t libbgp_event_bus_unsubscribe(libbgp_event_bus_t *bus, uint64_t id);
/*
 * Publish snapshots matching subscribers before invoking callbacks. An
 * unsubscribe during an in-flight publish does not cancel callbacks already
 * captured by that publish.
 */
LIBBGP_API size_t libbgp_event_bus_publish(libbgp_event_bus_t *bus, const libbgp_event_t *event);
/*
 * Publish while excluding the subscriber with publisher_id. Pass 0 when the
 * publisher is not subscribed or should receive its own event.
 */
LIBBGP_API size_t libbgp_event_bus_publish_from(
    libbgp_event_bus_t *bus,
    uint64_t publisher_id,
    const libbgp_event_t *event);
LIBBGP_API size_t libbgp_event_bus_subscriber_count(const libbgp_event_bus_t *bus);

#endif
