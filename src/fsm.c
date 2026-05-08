#include "libbgp/fsm.h"

#include <string.h>

#include "internal.h"
#include "libbgp/capability.h"
#include "libbgp/notification.h"

#define FSM_NOTIFY_MESSAGE_HEADER_ERROR 1u
#define FSM_NOTIFY_OPEN_MESSAGE_ERROR 2u
#define FSM_NOTIFY_HOLD_TIMER_EXPIRED 4u
#define FSM_NOTIFY_CEASE 6u
#define FSM_OPEN_ERR_UNSUPPORTED_VERSION 1u
#define FSM_OPEN_ERR_BAD_BGP_ID 3u
#define FSM_OPEN_ERR_UNACCEPTABLE_HOLD_TIME 6u

typedef struct fsm_impl {
    struct libbgp_fsm_config config;
    libbgp_fsm_state_t state;
    uint32_t peer_asn;
    uint32_t peer_bgp_id;
    uint16_t negotiated_hold_time;
    uint64_t current_ms;
    uint64_t last_rx_ms;
    uint64_t last_keepalive_ms;
    bool clock_initialized;
    libbgp_rib4_t *rib4;
    libbgp_event_bus_t *bus;
    libbgp_out_handler_t *out;
    bgp_lock_t lock;
} fsm_impl_t;

static fsm_impl_t *fsm_impl_get(const libbgp_fsm_t *fsm)
{
    return fsm == NULL ? NULL : (fsm_impl_t *)fsm->impl;
}

static void fsm_default_config(struct libbgp_fsm_config *config)
{
    config->local_asn = LIBBGP_AS_TRANS;
    config->local_bgp_id = 0u;
    config->hold_time = 90u;
    config->keepalive_time = 30u;
    config->enable_4byte_asn = true;
}

static libbgp_err_t fsm_send_packet(libbgp_out_handler_t *out, const libbgp_packet_t *pkt)
{
    uint8_t buf[LIBBGP_BGP_MAX_PACKET_LEN];
    size_t len = 0u;
    size_t sent = 0u;
    libbgp_err_t err;

    if (out == NULL) {
        return LIBBGP_OK;
    }
    err = libbgp_packet_write(pkt, buf, sizeof(buf), &len);
    if (err != LIBBGP_OK) {
        return err;
    }
    return libbgp_out_handler_send(out, buf, len, &sent);
}

static libbgp_err_t fsm_send_keepalive(libbgp_out_handler_t *out)
{
    libbgp_packet_t pkt;

    libbgp_packet_init(&pkt);
    pkt.type = LIBBGP_PACKET_KEEPALIVE;
    return fsm_send_packet(out, &pkt);
}

static libbgp_err_t fsm_send_notification(libbgp_out_handler_t *out, uint8_t code, uint8_t subcode)
{
    libbgp_packet_t pkt;
    libbgp_err_t err;

    libbgp_packet_init(&pkt);
    pkt.type = LIBBGP_PACKET_NOTIFICATION;
    libbgp_notification_init(&pkt.data.notification);
    pkt.data.notification.err_code = code;
    pkt.data.notification.err_subcode = subcode;
    err = fsm_send_packet(out, &pkt);
    libbgp_packet_destroy(&pkt);
    return err;
}

static libbgp_err_t fsm_send_open(libbgp_out_handler_t *out, const struct libbgp_fsm_config *config)
{
    libbgp_packet_t pkt;
    libbgp_err_t err;

    libbgp_packet_init(&pkt);
    pkt.type = LIBBGP_PACKET_OPEN;
    libbgp_open_init(&pkt.data.open);
    pkt.data.open.version = 4u;
    pkt.data.open.my_asn = (config->enable_4byte_asn && config->local_asn > 65535u) ?
        (uint16_t)LIBBGP_AS_TRANS : (uint16_t)config->local_asn;
    pkt.data.open.hold_time = config->hold_time;
    pkt.data.open.bgp_id = config->local_bgp_id;
    if (config->enable_4byte_asn) {
        libbgp_capability_t *cap = libbgp_capability_new(LIBBGP_CAP_4B_ASN);
        if (cap == NULL) {
            libbgp_packet_destroy(&pkt);
            return LIBBGP_ERR_NOMEM;
        }
        cap->data.asn_4b.asn = config->local_asn;
        err = libbgp_open_add_capability(&pkt.data.open, cap);
        libbgp_capability_unref(cap);
        if (err != LIBBGP_OK) {
            libbgp_packet_destroy(&pkt);
            return err;
        }
    }
    err = fsm_send_packet(out, &pkt);
    libbgp_packet_destroy(&pkt);
    return err;
}

static void fsm_publish_event(
    libbgp_event_bus_t *bus,
    libbgp_event_type_t type,
    uint32_t source_router_id,
    const libbgp_prefix4_t *prefix,
    const libbgp_update_msg_t *update)
{
    libbgp_event_t event;

    if (bus == NULL) {
        return;
    }
    memset(&event, 0, sizeof(event));
    event.type = type;
    event.source_router_id = source_router_id;
    event.prefix4 = prefix;
    event.update = update;
    (void)libbgp_event_bus_publish(bus, &event);
}

static bool fsm_state_session_up(libbgp_fsm_state_t state)
{
    return state == LIBBGP_FSM_OPEN_CONFIRM || state == LIBBGP_FSM_ESTABLISHED;
}

static void fsm_mark_rx_current(fsm_impl_t *impl)
{
    if (impl->clock_initialized) {
        impl->last_rx_ms = impl->current_ms;
    }
}

static size_t fsm_as_path_len_and_origin_as(const libbgp_pattr_t *attr, uint32_t *origin_as)
{
    size_t len = 0u;
    size_t i;

    if (origin_as != NULL) {
        *origin_as = 0u;
    }
    if (attr == NULL || attr->type != LIBBGP_PATTR_AS_PATH) {
        return 0u;
    }
    for (i = 0u; i < attr->data.as_path.segment_count; i++) {
        const libbgp_as_path_segment_t *seg = &attr->data.as_path.segments[i];
        size_t j;

        len += seg->asn_count;
        if (origin_as != NULL) {
            for (j = 0u; j < seg->asn_count; j++) {
                *origin_as = seg->asns[j];
            }
        }
    }
    return len;
}

static void fsm_fill_route_attrs(libbgp_rib4_route_t *route, const libbgp_update_msg_t *update)
{
    libbgp_pattr_t *attr;

    route->attrs = update->attrs;
    route->attr_count = update->attr_count;
    route->local_pref = 100u;

    attr = libbgp_update_find_attr(update, LIBBGP_PATTR_NEXT_HOP);
    if (attr != NULL) {
        route->next_hop = attr->data.next_hop.next_hop;
    }
    attr = libbgp_update_find_attr(update, LIBBGP_PATTR_LOCAL_PREF);
    if (attr != NULL) {
        route->local_pref = attr->data.local_pref.value;
    }
    attr = libbgp_update_find_attr(update, LIBBGP_PATTR_ORIGIN);
    if (attr != NULL) {
        route->origin = attr->data.origin.origin;
    }
    attr = libbgp_update_find_attr(update, LIBBGP_PATTR_MED);
    if (attr != NULL) {
        route->med = attr->data.med.value;
    }
    attr = libbgp_update_find_attr(update, LIBBGP_PATTR_AS_PATH);
    route->as_path_len = fsm_as_path_len_and_origin_as(attr, &route->origin_as);
}

static libbgp_err_t fsm_apply_update(
    libbgp_rib4_t *rib4,
    libbgp_event_bus_t *bus,
    uint32_t peer_bgp_id,
    const libbgp_update_msg_t *update)
{
    size_t i;
    libbgp_err_t first_err = LIBBGP_OK;

    for (i = 0u; i < update->withdrawn_count; i++) {
        libbgp_err_t err = LIBBGP_OK;

        if (rib4 != NULL) {
            err = libbgp_rib4_withdraw(rib4, peer_bgp_id, &update->withdrawn[i]);
            if (err == LIBBGP_ERR_NOT_FOUND) {
                err = LIBBGP_OK;
            }
        }
        if (err != LIBBGP_OK && first_err == LIBBGP_OK) {
            first_err = err;
        }
        fsm_publish_event(bus, LIBBGP_EVENT_ROUTE_WITHDRAWN, peer_bgp_id, &update->withdrawn[i], update);
    }
    for (i = 0u; i < update->nlri_count; i++) {
        libbgp_rib4_route_t route;
        libbgp_err_t err = LIBBGP_OK;

        memset(&route, 0, sizeof(route));
        route.prefix = update->nlri[i];
        route.source_router_id = peer_bgp_id;
        fsm_fill_route_attrs(&route, update);
        if (rib4 != NULL) {
            err = libbgp_rib4_insert(rib4, &route);
        }
        if (err != LIBBGP_OK && first_err == LIBBGP_OK) {
            first_err = err;
        }
        if (err == LIBBGP_OK) {
            fsm_publish_event(bus, LIBBGP_EVENT_ROUTE_ADDED, peer_bgp_id, &update->nlri[i], update);
        }
    }
    return first_err;
}

libbgp_err_t libbgp_fsm_init(libbgp_fsm_t *fsm, const struct libbgp_fsm_config *config)
{
    fsm_impl_t *impl;

    if (fsm == NULL) {
        return LIBBGP_ERR_INVALID;
    }
    fsm->impl = NULL;
    impl = (fsm_impl_t *)bgp_calloc(1u, sizeof(*impl));
    if (impl == NULL) {
        return LIBBGP_ERR_NOMEM;
    }
    if (config != NULL) {
        impl->config = *config;
    } else {
        fsm_default_config(&impl->config);
    }
    impl->state = LIBBGP_FSM_IDLE;
    impl->negotiated_hold_time = impl->config.hold_time;
    bgp_lock_init(&impl->lock);
    fsm->impl = impl;
    return LIBBGP_OK;
}

void libbgp_fsm_destroy(libbgp_fsm_t *fsm)
{
    fsm_impl_t *impl = fsm_impl_get(fsm);

    if (impl == NULL) {
        return;
    }
    bgp_lock_destroy(&impl->lock);
    bgp_free(impl);
    fsm->impl = NULL;
}

libbgp_fsm_state_t libbgp_fsm_state(const libbgp_fsm_t *fsm)
{
    fsm_impl_t *impl = fsm_impl_get(fsm);
    libbgp_fsm_state_t state;

    if (impl == NULL) {
        return LIBBGP_FSM_IDLE;
    }
    bgp_lock(&impl->lock);
    state = impl->state;
    bgp_unlock(&impl->lock);
    return state;
}

void libbgp_fsm_set_rib4(libbgp_fsm_t *fsm, libbgp_rib4_t *rib4)
{
    fsm_impl_t *impl = fsm_impl_get(fsm);

    if (impl == NULL) {
        return;
    }
    bgp_lock(&impl->lock);
    impl->rib4 = rib4;
    bgp_unlock(&impl->lock);
}

void libbgp_fsm_set_event_bus(libbgp_fsm_t *fsm, libbgp_event_bus_t *bus)
{
    fsm_impl_t *impl = fsm_impl_get(fsm);

    if (impl == NULL) {
        return;
    }
    bgp_lock(&impl->lock);
    impl->bus = bus;
    bgp_unlock(&impl->lock);
}

void libbgp_fsm_set_out_handler(libbgp_fsm_t *fsm, libbgp_out_handler_t *out)
{
    fsm_impl_t *impl = fsm_impl_get(fsm);

    if (impl == NULL) {
        return;
    }
    bgp_lock(&impl->lock);
    impl->out = out;
    bgp_unlock(&impl->lock);
}

libbgp_err_t libbgp_fsm_start(libbgp_fsm_t *fsm)
{
    fsm_impl_t *impl = fsm_impl_get(fsm);
    struct libbgp_fsm_config config;
    libbgp_out_handler_t *out;
    libbgp_fsm_state_t start_state;
    libbgp_err_t err;

    if (impl == NULL) {
        return LIBBGP_ERR_INVALID;
    }
    bgp_lock(&impl->lock);
    if (impl->state != LIBBGP_FSM_IDLE &&
        impl->state != LIBBGP_FSM_ACTIVE &&
        impl->state != LIBBGP_FSM_CONNECT) {
        bgp_unlock(&impl->lock);
        return LIBBGP_OK;
    }
    start_state = impl->state;
    impl->state = LIBBGP_FSM_OPEN_SENT;
    impl->peer_asn = 0u;
    impl->peer_bgp_id = 0u;
    impl->negotiated_hold_time = impl->config.hold_time;
    impl->clock_initialized = false;
    config = impl->config;
    out = impl->out;
    bgp_unlock(&impl->lock);

    err = fsm_send_open(out, &config);
    bgp_lock(&impl->lock);
    if (err != LIBBGP_OK && impl->state == LIBBGP_FSM_OPEN_SENT) {
        impl->state = start_state;
    }
    bgp_unlock(&impl->lock);
    return err;
}

libbgp_err_t libbgp_fsm_stop(libbgp_fsm_t *fsm)
{
    fsm_impl_t *impl = fsm_impl_get(fsm);
    libbgp_out_handler_t *out;
    bool notify;

    if (impl == NULL) {
        return LIBBGP_ERR_INVALID;
    }
    bgp_lock(&impl->lock);
    notify = impl->state != LIBBGP_FSM_IDLE;
    out = impl->out;
    impl->state = LIBBGP_FSM_IDLE;
    impl->clock_initialized = false;
    bgp_unlock(&impl->lock);

    return notify ? fsm_send_notification(out, FSM_NOTIFY_CEASE, 0u) : LIBBGP_OK;
}

static libbgp_err_t fsm_on_open_sent(fsm_impl_t *impl, const libbgp_packet_t *pkt)
{
    libbgp_out_handler_t *out;
    uint16_t local_hold;
    uint16_t peer_hold;

    if (pkt->type != LIBBGP_PACKET_OPEN) {
        out = impl->out;
        impl->state = LIBBGP_FSM_IDLE;
        bgp_unlock(&impl->lock);
        (void)fsm_send_notification(out, FSM_NOTIFY_MESSAGE_HEADER_ERROR, 0u);
        return LIBBGP_ERR_BAD_TYPE;
    }
    if (pkt->data.open.version != 4u) {
        out = impl->out;
        impl->state = LIBBGP_FSM_IDLE;
        bgp_unlock(&impl->lock);
        (void)fsm_send_notification(out, FSM_NOTIFY_OPEN_MESSAGE_ERROR, FSM_OPEN_ERR_UNSUPPORTED_VERSION);
        return LIBBGP_ERR_BAD_LEN;
    }
    if (pkt->data.open.hold_time != 0u && pkt->data.open.hold_time < 3u) {
        out = impl->out;
        impl->state = LIBBGP_FSM_IDLE;
        bgp_unlock(&impl->lock);
        (void)fsm_send_notification(out, FSM_NOTIFY_OPEN_MESSAGE_ERROR, FSM_OPEN_ERR_UNACCEPTABLE_HOLD_TIME);
        return LIBBGP_ERR_INVALID;
    }
    if (pkt->data.open.bgp_id == 0u) {
        out = impl->out;
        impl->state = LIBBGP_FSM_IDLE;
        bgp_unlock(&impl->lock);
        (void)fsm_send_notification(out, FSM_NOTIFY_OPEN_MESSAGE_ERROR, FSM_OPEN_ERR_BAD_BGP_ID);
        return LIBBGP_ERR_INVALID;
    }
    local_hold = impl->config.hold_time;
    peer_hold = pkt->data.open.hold_time;
    impl->peer_asn = libbgp_open_get_4b_asn(&pkt->data.open);
    impl->peer_bgp_id = pkt->data.open.bgp_id;
    impl->negotiated_hold_time = (local_hold == 0u || peer_hold == 0u) ? 0u :
        (local_hold < peer_hold ? local_hold : peer_hold);
    impl->state = LIBBGP_FSM_OPEN_CONFIRM;
    impl->last_rx_ms = 0u;
    impl->last_keepalive_ms = 0u;
    impl->clock_initialized = false;
    out = impl->out;
    bgp_unlock(&impl->lock);
    return fsm_send_keepalive(out);
}

static libbgp_err_t fsm_on_open_confirm(fsm_impl_t *impl, const libbgp_packet_t *pkt)
{
    libbgp_event_bus_t *bus = NULL;

    if (pkt->type == LIBBGP_PACKET_KEEPALIVE) {
        fsm_mark_rx_current(impl);
        impl->state = LIBBGP_FSM_ESTABLISHED;
        bus = impl->bus;
        bgp_unlock(&impl->lock);
        fsm_publish_event(bus, LIBBGP_EVENT_SESSION_UP, 0u, NULL, NULL);
        return LIBBGP_OK;
    }
    if (pkt->type == LIBBGP_PACKET_NOTIFICATION) {
        impl->state = LIBBGP_FSM_IDLE;
        bgp_unlock(&impl->lock);
        return LIBBGP_OK;
    }
    impl->state = LIBBGP_FSM_IDLE;
    bgp_unlock(&impl->lock);
    return LIBBGP_ERR_BAD_TYPE;
}

static libbgp_err_t fsm_on_established(fsm_impl_t *impl, const libbgp_packet_t *pkt)
{
    libbgp_event_bus_t *bus;
    libbgp_rib4_t *rib4;
    uint32_t peer_bgp_id;

    if (pkt->type == LIBBGP_PACKET_KEEPALIVE) {
        fsm_mark_rx_current(impl);
        bgp_unlock(&impl->lock);
        return LIBBGP_OK;
    }
    if (pkt->type == LIBBGP_PACKET_NOTIFICATION) {
        bus = impl->bus;
        impl->state = LIBBGP_FSM_IDLE;
        bgp_unlock(&impl->lock);
        fsm_publish_event(bus, LIBBGP_EVENT_SESSION_DOWN, 0u, NULL, NULL);
        return LIBBGP_OK;
    }
    if (pkt->type == LIBBGP_PACKET_OPEN) {
        impl->state = LIBBGP_FSM_IDLE;
        bgp_unlock(&impl->lock);
        return LIBBGP_ERR_BAD_TYPE;
    }
    if (pkt->type != LIBBGP_PACKET_UPDATE) {
        bgp_unlock(&impl->lock);
        return LIBBGP_ERR_BAD_TYPE;
    }
    fsm_mark_rx_current(impl);
    rib4 = impl->rib4;
    bus = impl->bus;
    peer_bgp_id = impl->peer_bgp_id;
    bgp_unlock(&impl->lock);
    return fsm_apply_update(rib4, bus, peer_bgp_id, &pkt->data.update);
}

libbgp_err_t libbgp_fsm_on_packet(libbgp_fsm_t *fsm, const libbgp_packet_t *pkt)
{
    fsm_impl_t *impl = fsm_impl_get(fsm);
    libbgp_fsm_state_t state;

    if (impl == NULL || pkt == NULL) {
        return LIBBGP_ERR_INVALID;
    }
    bgp_lock(&impl->lock);
    state = impl->state;
    if (pkt->type == LIBBGP_PACKET_NOTIFICATION) {
        if (state == LIBBGP_FSM_ESTABLISHED) {
            libbgp_event_bus_t *bus = impl->bus;
            impl->state = LIBBGP_FSM_IDLE;
            bgp_unlock(&impl->lock);
            fsm_publish_event(bus, LIBBGP_EVENT_SESSION_DOWN, 0u, NULL, NULL);
            return LIBBGP_OK;
        }
        impl->state = LIBBGP_FSM_IDLE;
        bgp_unlock(&impl->lock);
        return LIBBGP_OK;
    }

    switch (state) {
    case LIBBGP_FSM_IDLE:
        if (pkt->type == LIBBGP_PACKET_OPEN) {
            return fsm_on_open_sent(impl, pkt);
        }
        bgp_unlock(&impl->lock);
        return LIBBGP_OK;
    case LIBBGP_FSM_OPEN_SENT:
        return fsm_on_open_sent(impl, pkt);
    case LIBBGP_FSM_OPEN_CONFIRM:
        return fsm_on_open_confirm(impl, pkt);
    case LIBBGP_FSM_ESTABLISHED:
        return fsm_on_established(impl, pkt);
    case LIBBGP_FSM_CONNECT:
    case LIBBGP_FSM_ACTIVE:
    default:
        bgp_unlock(&impl->lock);
        return LIBBGP_OK;
    }
}

libbgp_err_t libbgp_fsm_tick(libbgp_fsm_t *fsm, uint64_t now_ms)
{
    fsm_impl_t *impl = fsm_impl_get(fsm);
    libbgp_out_handler_t *out = NULL;
    libbgp_event_bus_t *bus = NULL;
    bool send_keepalive = false;
    bool send_hold_expired = false;

    if (impl == NULL) {
        return LIBBGP_ERR_INVALID;
    }
    bgp_lock(&impl->lock);
    if (!impl->clock_initialized) {
        impl->current_ms = now_ms;
        impl->last_rx_ms = now_ms;
        impl->last_keepalive_ms = now_ms;
        impl->clock_initialized = true;
        bgp_unlock(&impl->lock);
        return LIBBGP_OK;
    }
    impl->current_ms = now_ms;
    if (impl->negotiated_hold_time > 0u &&
        fsm_state_session_up(impl->state) &&
        now_ms - impl->last_rx_ms > (uint64_t)impl->negotiated_hold_time * 1000u) {
        send_hold_expired = true;
        out = impl->out;
        bus = impl->bus;
        impl->state = LIBBGP_FSM_IDLE;
        impl->clock_initialized = false;
        bgp_unlock(&impl->lock);
        (void)fsm_send_notification(out, FSM_NOTIFY_HOLD_TIMER_EXPIRED, 0u);
        fsm_publish_event(bus, LIBBGP_EVENT_SESSION_DOWN, 0u, NULL, NULL);
        return LIBBGP_OK;
    }
    if ((impl->state == LIBBGP_FSM_ESTABLISHED || impl->state == LIBBGP_FSM_OPEN_CONFIRM) &&
        impl->config.keepalive_time > 0u &&
        now_ms - impl->last_keepalive_ms >= (uint64_t)impl->config.keepalive_time * 1000u) {
        send_keepalive = true;
        out = impl->out;
    }
    bgp_unlock(&impl->lock);

    if (send_keepalive) {
        libbgp_err_t err = fsm_send_keepalive(out);
        if (err == LIBBGP_OK) {
            bgp_lock(&impl->lock);
            impl->last_keepalive_ms = now_ms;
            bgp_unlock(&impl->lock);
        }
        return err;
    }
    BGP_UNUSED(send_hold_expired);
    return LIBBGP_OK;
}

uint32_t libbgp_fsm_peer_asn(const libbgp_fsm_t *fsm)
{
    fsm_impl_t *impl = fsm_impl_get(fsm);
    uint32_t peer_asn;

    if (impl == NULL) {
        return 0u;
    }
    bgp_lock(&impl->lock);
    peer_asn = impl->peer_asn;
    bgp_unlock(&impl->lock);
    return peer_asn;
}

uint32_t libbgp_fsm_peer_bgp_id(const libbgp_fsm_t *fsm)
{
    fsm_impl_t *impl = fsm_impl_get(fsm);
    uint32_t peer_bgp_id;

    if (impl == NULL) {
        return 0u;
    }
    bgp_lock(&impl->lock);
    peer_bgp_id = impl->peer_bgp_id;
    bgp_unlock(&impl->lock);
    return peer_bgp_id;
}
