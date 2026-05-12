#include "libbgp/fsm.h"

#include <string.h>

#include "internal.h"
#include "libbgp/capability.h"
#include "libbgp/filter.h"
#include "libbgp/notification.h"
#include "rib_internal.h"

#ifdef BGP_THREADSAFE
#include <pthread.h>

static pthread_mutex_t fsm_handle_lock = PTHREAD_MUTEX_INITIALIZER;

#define fsm_handle_global_lock() pthread_mutex_lock(&fsm_handle_lock)
#define fsm_handle_global_unlock() pthread_mutex_unlock(&fsm_handle_lock)
#define fsm_state_change_is_dispatch_thread(impl) \
    ((impl)->state_change_dispatch_count != 0u && \
     pthread_equal((impl)->state_change_dispatch_thread, pthread_self()))
#define fsm_state_change_wait(impl) \
    while ((impl)->state_change_dispatch_count != 0u && \
           !fsm_state_change_is_dispatch_thread(impl)) { \
        pthread_cond_wait(&(impl)->state_change_cond, &(impl)->lock); \
    }
#define fsm_state_change_signal(impl) pthread_cond_broadcast(&(impl)->state_change_cond)
#else
#define fsm_handle_global_lock() ((void)0)
#define fsm_handle_global_unlock() ((void)0)
#define fsm_state_change_is_dispatch_thread(impl) false
#define fsm_state_change_wait(impl) ((void)(impl))
#define fsm_state_change_signal(impl) ((void)(impl))
#endif

#define FSM_NOTIFY_MESSAGE_HEADER_ERROR 1u
#define FSM_NOTIFY_OPEN_MESSAGE_ERROR 2u
#define FSM_NOTIFY_UPDATE_MESSAGE_ERROR 3u
#define FSM_NOTIFY_HOLD_TIMER_EXPIRED 4u
#define FSM_NOTIFY_FSM_ERROR 5u
#define FSM_NOTIFY_CEASE 6u
#define FSM_CEASE_ERR_ADMIN_SHUTDOWN 2u
#define FSM_CEASE_ERR_ADMIN_RESET 4u
#define FSM_CEASE_ERR_COLLISION 7u
#define FSM_OPEN_ERR_UNSUPPORTED_VERSION 1u
#define FSM_OPEN_ERR_BAD_PEER_AS 2u
#define FSM_OPEN_ERR_BAD_BGP_ID 3u
#define FSM_OPEN_ERR_UNACCEPTABLE_HOLD_TIME 6u
#define FSM_UPDATE_ERR_MALFORMED_ATTR_LIST 1u
#define FSM_UPDATE_ERR_MISSING_WELL_KNOWN 3u
#define FSM_UPDATE_ERR_ATTR_LEN 5u
#define FSM_ERR_OPEN_SENT 1u
#define FSM_ERR_OPEN_CONFIRM 2u
#define FSM_ERR_ESTABLISHED 3u
#define FSM_STATE_CHANGE_QUEUE_CAP 32u

typedef struct fsm_state_change {
    libbgp_fsm_state_t old_state;
    libbgp_fsm_state_t new_state;
} fsm_state_change_t;

typedef struct fsm_impl {
    struct libbgp_fsm_config config;
    libbgp_fsm_state_t state;
    uint32_t expected_peer_asn;
    uint8_t allow_local_as;
    int32_t route_weight;
    uint32_t peer_asn;
    uint32_t peer_bgp_id;
    uint16_t negotiated_hold_time;
    uint64_t current_ms;
    uint64_t last_rx_ms;
    uint64_t last_keepalive_ms;
    bool clock_initialized;
    bool enable_mpbgp_ipv4;
    bool send_ipv4_routes;
    bool send_ipv6_routes;
    bool peer_mpbgp_ipv6;
    bool peer_4byte_asn;
    bool peer_can_send_as4_path;
    bool no_collision_detection;
    libbgp_rib4_t internal_rib4;
    libbgp_rib6_t internal_rib6;
    bool internal_rib4_initialized;
    bool internal_rib6_initialized;
    libbgp_rib4_t *rib4;
    libbgp_rib6_t *rib6;
    libbgp_event_bus_t *bus;
    libbgp_out_handler_t *out;
    const libbgp_filter_t *in_filter4;
    const libbgp_filter_t *out_filter4;
    const libbgp_filter_t *in_filter6;
    const libbgp_filter_t *out_filter6;
    libbgp_prefix4_t peering_lan4;
    libbgp_prefix6_t peering_lan6;
    uint32_t default_nexthop4;
    uint8_t default_nexthop6[16];
    uint8_t default_nexthop6_linklocal[16];
    bool no_nexthop_check4;
    bool force_default_nexthop4;
    bool no_nexthop_check6;
    bool force_default_nexthop6;
    bool ibgp_alter_nexthop;
    uint64_t route_added_sub_id;
    uint64_t route_withdrawn_sub_id;
    uint64_t collision_sub_id;
    uint64_t session_generation;
    bool local_keepalive_send_pending;
    bool local_keepalive_pending;
    bool passive_open_send_pending;
    bool passive_keepalive_pending;
    libbgp_fsm_state_change_fn state_change_cb;
    void *state_change_ctx;
    fsm_state_change_t state_changes[FSM_STATE_CHANGE_QUEUE_CAP];
    size_t state_change_count;
    size_t state_change_dispatch_count;
    size_t refcount;
    bool destroy_started;
    bgp_lock_t lock;
#ifdef BGP_THREADSAFE
    pthread_cond_t state_change_cond;
    pthread_t state_change_dispatch_thread;
#endif
} fsm_impl_t;

static void fsm_route_event_cb(const libbgp_event_t *event, void *ctx);

typedef struct fsm_applied_route4 {
    size_t seq;
    libbgp_prefix4_t prefix;
    uint64_t update_id;
    bool restore_replaced;
    bgp_rib_change_kind_t change_kind;
    libbgp_rib4_route_t best_route;
    bgp_rib4_saved_route_t replaced;
} fsm_applied_route4_t;

typedef struct fsm_applied_route6 {
    size_t seq;
    libbgp_prefix6_t prefix;
    uint64_t update_id;
    bool restore_replaced;
    bgp_rib_change_kind_t change_kind;
    libbgp_rib6_route_t best_route;
    bgp_rib6_saved_route_t replaced;
} fsm_applied_route6_t;

typedef struct fsm_withdrawn_route4 {
    size_t seq;
    libbgp_prefix4_t prefix;
    bool publish_withdrawn;
    bool publish_replacement;
    libbgp_rib4_route_t replacement_route;
    bgp_rib4_saved_route_t saved;
} fsm_withdrawn_route4_t;

typedef struct fsm_withdrawn_route6 {
    size_t seq;
    libbgp_prefix6_t prefix;
    bool publish_withdrawn;
    bool publish_replacement;
    libbgp_rib6_route_t replacement_route;
    bgp_rib6_saved_route_t saved;
} fsm_withdrawn_route6_t;

typedef struct fsm_update_journal {
    size_t event_seq;
    fsm_applied_route4_t *routes4;
    size_t routes4_count;
    size_t routes4_cap;
    fsm_applied_route6_t *routes6;
    size_t routes6_count;
    size_t routes6_cap;
    fsm_withdrawn_route4_t *withdrawn4;
    size_t withdrawn4_count;
    size_t withdrawn4_cap;
    fsm_withdrawn_route6_t *withdrawn6;
    size_t withdrawn6_count;
    size_t withdrawn6_cap;
} fsm_update_journal_t;

static fsm_impl_t *fsm_impl_get(const libbgp_fsm_t *fsm)
{
    return fsm == NULL ? NULL : (fsm_impl_t *)fsm->impl;
}

static libbgp_err_t fsm_update_from_route4(const libbgp_rib4_route_t *route, libbgp_update_msg_t *update);
static libbgp_err_t fsm_update_from_route6(const libbgp_rib6_route_t *route, libbgp_update_msg_t *update);
static libbgp_err_t fsm_clone_update(const libbgp_update_msg_t *src, libbgp_update_msg_t *dst);
static const libbgp_pattr_t *fsm_find_mp_reach6_for_prefix(
    const libbgp_update_msg_t *update,
    const libbgp_prefix6_t *prefix);

static void fsm_set_state(fsm_impl_t *impl, libbgp_fsm_state_t state)
{
    libbgp_fsm_state_t old_state;

    if (impl == NULL || impl->state == state) {
        return;
    }
    old_state = impl->state;
    impl->state = state;
    if (impl->state_change_cb == NULL) {
        return;
    }
    if (impl->state_change_count >= FSM_STATE_CHANGE_QUEUE_CAP) {
        impl->state_changes[FSM_STATE_CHANGE_QUEUE_CAP - 1u].new_state = state;
        return;
    }
    impl->state_changes[impl->state_change_count].old_state = old_state;
    impl->state_changes[impl->state_change_count].new_state = state;
    impl->state_change_count++;
}

static size_t fsm_drain_state_changes(
    fsm_impl_t *impl,
    libbgp_fsm_state_change_fn *out_cb,
    void **out_ctx,
    fsm_state_change_t changes[FSM_STATE_CHANGE_QUEUE_CAP])
{
    size_t count;

    if (out_cb != NULL) {
        *out_cb = NULL;
    }
    if (out_ctx != NULL) {
        *out_ctx = NULL;
    }
    if (impl == NULL) {
        return 0u;
    }
    bgp_lock(&impl->lock);
    fsm_state_change_wait(impl);
    if (out_cb != NULL) {
        *out_cb = impl->state_change_cb;
    }
    if (out_ctx != NULL) {
        *out_ctx = impl->state_change_ctx;
    }
    count = impl->state_change_count;
    if (count != 0u) {
        memcpy(changes, impl->state_changes, count * sizeof(changes[0]));
        impl->state_change_dispatch_count++;
#ifdef BGP_THREADSAFE
        impl->state_change_dispatch_thread = pthread_self();
#endif
    }
    impl->state_change_count = 0u;
    bgp_unlock(&impl->lock);
    return count;
}

static void fsm_dispatch_drained_state_changes(
    fsm_impl_t *impl,
    libbgp_fsm_state_change_fn cb,
    void *ctx,
    const fsm_state_change_t *changes,
    size_t count)
{
    size_t i;

    if (cb != NULL && changes != NULL) {
        for (i = 0u; i < count; i++) {
            bool callback_current;

            bgp_lock(&impl->lock);
            callback_current = impl->state_change_cb == cb && impl->state_change_ctx == ctx;
            bgp_unlock(&impl->lock);
            if (!callback_current) {
                break;
            }
            cb(changes[i].old_state, changes[i].new_state, ctx);
        }
    }
    if (count != 0u) {
        bgp_lock(&impl->lock);
        if (impl->state_change_dispatch_count != 0u) {
            impl->state_change_dispatch_count--;
        }
        fsm_state_change_signal(impl);
        bgp_unlock(&impl->lock);
    }
}

static void fsm_dispatch_state_changes_impl(fsm_impl_t *impl)
{
    fsm_state_change_t changes[FSM_STATE_CHANGE_QUEUE_CAP];
    libbgp_fsm_state_change_fn cb;
    void *ctx;
    size_t count;

    count = fsm_drain_state_changes(impl, &cb, &ctx, changes);
    fsm_dispatch_drained_state_changes(impl, cb, ctx, changes, count);
}


static bool fsm_impl_acquire(fsm_impl_t *impl)
{
    bool acquired = false;

    if (impl == NULL) {
        return false;
    }
    bgp_lock(&impl->lock);
    if (!impl->destroy_started) {
        impl->refcount++;
        acquired = true;
    }
    bgp_unlock(&impl->lock);
    return acquired;
}

static fsm_impl_t *fsm_handle_acquire(const libbgp_fsm_t *fsm)
{
    fsm_impl_t *impl;

    fsm_handle_global_lock();
    impl = fsm_impl_get(fsm);
    if (!fsm_impl_acquire(impl)) {
        impl = NULL;
    }
    fsm_handle_global_unlock();
    return impl;
}

static bool fsm_impl_release(fsm_impl_t *impl)
{
    bool should_free = false;

    if (impl == NULL) {
        return false;
    }
    bgp_lock(&impl->lock);
    if (impl->refcount > 0u) {
        impl->refcount--;
    }
    should_free = impl->destroy_started && impl->refcount == 0u;
    bgp_unlock(&impl->lock);
    return should_free;
}

static void fsm_impl_free(fsm_impl_t *impl)
{
    if (impl == NULL) {
        return;
    }
#ifdef BGP_THREADSAFE
    pthread_cond_destroy(&impl->state_change_cond);
#endif
    bgp_lock_destroy(&impl->lock);
    if (impl->internal_rib6_initialized) {
        libbgp_rib6_destroy(&impl->internal_rib6);
    }
    if (impl->internal_rib4_initialized) {
        libbgp_rib4_destroy(&impl->internal_rib4);
    }
    bgp_free(impl);
}

static bool fsm_event_ctx_retain(void *ctx)
{
    return fsm_impl_acquire((fsm_impl_t *)ctx);
}

static void fsm_impl_release_free(fsm_impl_t *impl)
{
    if (fsm_impl_release(impl)) {
        fsm_impl_free(impl);
    }
}

static void fsm_event_ctx_release(void *ctx)
{
    fsm_impl_release_free((fsm_impl_t *)ctx);
}

static void fsm_default_config(struct libbgp_fsm_config *config)
{
    config->local_asn = LIBBGP_AS_TRANS;
    config->local_bgp_id = 0u;
    config->hold_time = 120u;
    config->keepalive_time = 40u;
    config->enable_4byte_asn = true;
    config->enable_mpbgp_ipv6 = false;
}

static libbgp_err_t fsm_send_packet(libbgp_out_handler_t *out, const libbgp_packet_t *pkt)
{
    uint8_t buf[LIBBGP_BGP_MAX_PACKET_LEN];
    size_t len = 0u;
    size_t total = 0u;
    size_t sent = 0u;
    libbgp_err_t err;

    if (out == NULL) {
        return LIBBGP_ERR_INVALID;
    }
    err = libbgp_packet_write(pkt, buf, sizeof(buf), &len);
    if (err != LIBBGP_OK) {
        return err;
    }
    while (total < len) {
        sent = 0u;
        err = libbgp_out_handler_send(out, buf + total, len - total, &sent);
        if (err != LIBBGP_OK) {
            return err;
        }
        if (sent == 0u || sent > len - total) {
            return LIBBGP_ERR_WRITE;
        }
        total += sent;
    }
    return LIBBGP_OK;
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

static bool fsm_local_open_config_valid(const struct libbgp_fsm_config *config)
{
    if (config == NULL || config->local_bgp_id == 0u) {
        return false;
    }
    if (config->hold_time != 0u && config->hold_time < 3u) {
        return false;
    }
    if (!config->enable_4byte_asn && config->local_asn > 65535u) {
        return false;
    }
    return true;
}

static bool fsm_valid_peer_bgp_id(uint32_t peer_id, uint32_t local_id)
{
    uint8_t first = (uint8_t)(peer_id >> 24);

    if (peer_id == 0u || peer_id == local_id) {
        return false;
    }
    if (first == 0u || first == 127u || first >= 224u) {
        return false;
    }
    return true;
}

static libbgp_err_t fsm_add_mpbgp_cap(libbgp_open_msg_t *open, uint16_t afi)
{
    libbgp_capability_t *cap;
    libbgp_err_t err;

    cap = libbgp_capability_new(LIBBGP_CAP_MP_BGP);
    if (cap == NULL) {
        return LIBBGP_ERR_NOMEM;
    }
    cap->data.mp_bgp.afi = afi;
    cap->data.mp_bgp.safi = LIBBGP_SAFI_UNICAST;
    err = libbgp_open_add_capability(open, cap);
    libbgp_capability_unref(cap);
    return err;
}

static libbgp_err_t fsm_send_open(
    libbgp_out_handler_t *out,
    const struct libbgp_fsm_config *config,
    bool enable_mpbgp_ipv4)
{
    libbgp_packet_t pkt;
    libbgp_err_t err;

    if (!fsm_local_open_config_valid(config)) {
        return LIBBGP_ERR_INVALID;
    }
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
    if (enable_mpbgp_ipv4) {
        err = fsm_add_mpbgp_cap(&pkt.data.open, LIBBGP_AFI_IPV4);
        if (err != LIBBGP_OK) {
            libbgp_packet_destroy(&pkt);
            return err;
        }
    }
    if (config->enable_mpbgp_ipv6) {
        err = fsm_add_mpbgp_cap(&pkt.data.open, LIBBGP_AFI_IPV6);
        if (err != LIBBGP_OK) {
            libbgp_packet_destroy(&pkt);
            return err;
        }
    }
    err = fsm_send_packet(out, &pkt);
    libbgp_packet_destroy(&pkt);
    return err;
}

static bool fsm_open_has_any_mpbgp(const libbgp_open_msg_t *open)
{
    size_t i;

    if (open == NULL) {
        return false;
    }
    for (i = 0u; i < open->capability_count; i++) {
        const libbgp_capability_t *cap = open->capabilities[i];

        if (cap != NULL && cap->type == LIBBGP_CAP_MP_BGP) {
            return true;
        }
    }
    return false;
}

static void fsm_negotiate_route_families(
    const fsm_impl_t *impl,
    const libbgp_open_msg_t *open,
    bool *send_ipv4_routes,
    bool *send_ipv6_routes)
{
    bool local_mp4;
    bool local_mp6;
    bool peer_has_mpbgp;
    bool peer_mp4;
    bool peer_mp6;

    if (send_ipv4_routes != NULL) {
        *send_ipv4_routes = false;
    }
    if (send_ipv6_routes != NULL) {
        *send_ipv6_routes = false;
    }
    if (impl == NULL || open == NULL) {
        return;
    }

    local_mp4 = impl->enable_mpbgp_ipv4;
    local_mp6 = impl->config.enable_mpbgp_ipv6;
    peer_has_mpbgp = fsm_open_has_any_mpbgp(open);
    peer_mp4 = libbgp_open_has_mpbgp(open, LIBBGP_AFI_IPV4, LIBBGP_SAFI_UNICAST);
    peer_mp6 = libbgp_open_has_mpbgp(open, LIBBGP_AFI_IPV6, LIBBGP_SAFI_UNICAST);

    if (peer_has_mpbgp && (local_mp4 || local_mp6)) {
        if (send_ipv4_routes != NULL) {
            *send_ipv4_routes = local_mp4 && peer_mp4;
        }
        if (send_ipv6_routes != NULL) {
            *send_ipv6_routes = local_mp6 && peer_mp6;
        }
        return;
    }

    if (send_ipv4_routes != NULL) {
        *send_ipv4_routes = !(local_mp6 && !local_mp4);
    }
}

static void fsm_publish_event(
    libbgp_event_bus_t *bus,
    uint64_t publisher_id,
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
    (void)libbgp_event_bus_publish_from(bus, publisher_id, &event);
}

static void fsm_publish_event6(
    libbgp_event_bus_t *bus,
    uint64_t publisher_id,
    libbgp_event_type_t type,
    uint32_t source_router_id,
    const libbgp_prefix6_t *prefix,
    const libbgp_update_msg_t *update)
{
    libbgp_event_t event;

    if (bus == NULL) {
        return;
    }
    memset(&event, 0, sizeof(event));
    event.type = type;
    event.source_router_id = source_router_id;
    event.prefix6 = prefix;
    event.update = update;
    (void)libbgp_event_bus_publish_from(bus, publisher_id, &event);
}

static bool fsm_state_hold_timer_active(libbgp_fsm_state_t state)
{
    return state == LIBBGP_FSM_OPEN_CONFIRM || state == LIBBGP_FSM_ESTABLISHED;
}

static bool fsm_state_pre_open(libbgp_fsm_state_t state)
{
    return state == LIBBGP_FSM_IDLE ||
        state == LIBBGP_FSM_CONNECT ||
        state == LIBBGP_FSM_ACTIVE;
}

static uint16_t fsm_effective_keepalive_time(const fsm_impl_t *impl)
{
    uint16_t interval;
    uint16_t hold_third;

    if (impl->negotiated_hold_time == 0u) {
        return 0u;
    }
    hold_third = (uint16_t)(impl->negotiated_hold_time / 3u);
    if (hold_third == 0u) {
        hold_third = 1u;
    }
    interval = impl->config.keepalive_time;
    if (interval == 0u) {
        return hold_third;
    }
    if (hold_third < interval) {
        interval = hold_third;
    }
    return interval;
}

static void fsm_discard_peer_routes(libbgp_rib4_t *rib4, libbgp_rib6_t *rib6, uint32_t peer_bgp_id)
{
    if (rib4 != NULL) {
        (void)libbgp_rib4_discard(rib4, peer_bgp_id);
    }
    if (rib6 != NULL) {
        (void)libbgp_rib6_discard(rib6, peer_bgp_id);
    }
}

static void fsm_update_journal_destroy(fsm_update_journal_t *journal)
{
    size_t i;

    if (journal == NULL) {
        return;
    }
    for (i = 0u; i < journal->routes4_count; i++) {
        bgp_rib4_route_snapshot_destroy(&journal->routes4[i].best_route);
        bgp_rib4_saved_route_destroy(&journal->routes4[i].replaced);
    }
    for (i = 0u; i < journal->routes6_count; i++) {
        bgp_rib6_route_snapshot_destroy(&journal->routes6[i].best_route);
        bgp_rib6_saved_route_destroy(&journal->routes6[i].replaced);
    }
    for (i = 0u; i < journal->withdrawn4_count; i++) {
        bgp_rib4_route_snapshot_destroy(&journal->withdrawn4[i].replacement_route);
        bgp_rib4_saved_route_destroy(&journal->withdrawn4[i].saved);
    }
    for (i = 0u; i < journal->withdrawn6_count; i++) {
        bgp_rib6_route_snapshot_destroy(&journal->withdrawn6[i].replacement_route);
        bgp_rib6_saved_route_destroy(&journal->withdrawn6[i].saved);
    }
    bgp_free(journal->routes4);
    bgp_free(journal->routes6);
    bgp_free(journal->withdrawn4);
    bgp_free(journal->withdrawn6);
    memset(journal, 0, sizeof(*journal));
}

static libbgp_err_t fsm_update_journal_reserve4_to(fsm_update_journal_t *journal, size_t needed)
{
    fsm_applied_route4_t *next;
    size_t cap;

    if (journal == NULL || needed <= journal->routes4_cap) {
        return LIBBGP_OK;
    }
    cap = journal->routes4_cap == 0u ? 4u : journal->routes4_cap;
    while (cap < needed) {
        size_t next_cap = cap * 2u;

        if (next_cap < cap) {
            return LIBBGP_ERR_NOMEM;
        }
        cap = next_cap;
    }
    if (cap > SIZE_MAX / sizeof(*journal->routes4)) {
        return LIBBGP_ERR_NOMEM;
    }
    next = (fsm_applied_route4_t *)bgp_realloc(journal->routes4, cap * sizeof(*journal->routes4));
    if (next == NULL) {
        return LIBBGP_ERR_NOMEM;
    }
    journal->routes4 = next;
    journal->routes4_cap = cap;
    return LIBBGP_OK;
}

static libbgp_err_t fsm_update_journal_reserve6_to(fsm_update_journal_t *journal, size_t needed)
{
    fsm_applied_route6_t *next;
    size_t cap;

    if (journal == NULL || needed <= journal->routes6_cap) {
        return LIBBGP_OK;
    }
    cap = journal->routes6_cap == 0u ? 4u : journal->routes6_cap;
    while (cap < needed) {
        size_t next_cap = cap * 2u;

        if (next_cap < cap) {
            return LIBBGP_ERR_NOMEM;
        }
        cap = next_cap;
    }
    if (cap > SIZE_MAX / sizeof(*journal->routes6)) {
        return LIBBGP_ERR_NOMEM;
    }
    next = (fsm_applied_route6_t *)bgp_realloc(journal->routes6, cap * sizeof(*journal->routes6));
    if (next == NULL) {
        return LIBBGP_ERR_NOMEM;
    }
    journal->routes6 = next;
    journal->routes6_cap = cap;
    return LIBBGP_OK;
}

static libbgp_err_t fsm_update_journal_reserve_withdrawn4_to(fsm_update_journal_t *journal, size_t needed)
{
    fsm_withdrawn_route4_t *next;
    size_t cap;

    if (journal == NULL || needed <= journal->withdrawn4_cap) {
        return LIBBGP_OK;
    }
    cap = journal->withdrawn4_cap == 0u ? 4u : journal->withdrawn4_cap;
    while (cap < needed) {
        size_t next_cap = cap * 2u;

        if (next_cap < cap) {
            return LIBBGP_ERR_NOMEM;
        }
        cap = next_cap;
    }
    if (cap > SIZE_MAX / sizeof(*journal->withdrawn4)) {
        return LIBBGP_ERR_NOMEM;
    }
    next = (fsm_withdrawn_route4_t *)bgp_realloc(journal->withdrawn4, cap * sizeof(*journal->withdrawn4));
    if (next == NULL) {
        return LIBBGP_ERR_NOMEM;
    }
    journal->withdrawn4 = next;
    journal->withdrawn4_cap = cap;
    return LIBBGP_OK;
}

static libbgp_err_t fsm_update_journal_reserve_withdrawn6_to(fsm_update_journal_t *journal, size_t needed)
{
    fsm_withdrawn_route6_t *next;
    size_t cap;

    if (journal == NULL || needed <= journal->withdrawn6_cap) {
        return LIBBGP_OK;
    }
    cap = journal->withdrawn6_cap == 0u ? 4u : journal->withdrawn6_cap;
    while (cap < needed) {
        size_t next_cap = cap * 2u;

        if (next_cap < cap) {
            return LIBBGP_ERR_NOMEM;
        }
        cap = next_cap;
    }
    if (cap > SIZE_MAX / sizeof(*journal->withdrawn6)) {
        return LIBBGP_ERR_NOMEM;
    }
    next = (fsm_withdrawn_route6_t *)bgp_realloc(journal->withdrawn6, cap * sizeof(*journal->withdrawn6));
    if (next == NULL) {
        return LIBBGP_ERR_NOMEM;
    }
    journal->withdrawn6 = next;
    journal->withdrawn6_cap = cap;
    return LIBBGP_OK;
}

static libbgp_err_t fsm_update_journal_reserve4(fsm_update_journal_t *journal)
{
    if (journal == NULL) {
        return LIBBGP_OK;
    }
    if (journal->routes4_count == SIZE_MAX) {
        return LIBBGP_ERR_NOMEM;
    }
    return fsm_update_journal_reserve4_to(journal, journal->routes4_count + 1u);
}

static libbgp_err_t fsm_update_journal_reserve6(fsm_update_journal_t *journal)
{
    if (journal == NULL) {
        return LIBBGP_OK;
    }
    if (journal->routes6_count == SIZE_MAX) {
        return LIBBGP_ERR_NOMEM;
    }
    return fsm_update_journal_reserve6_to(journal, journal->routes6_count + 1u);
}

static libbgp_err_t fsm_update_journal_reserve_withdrawn4(fsm_update_journal_t *journal)
{
    if (journal == NULL) {
        return LIBBGP_OK;
    }
    if (journal->withdrawn4_count == SIZE_MAX) {
        return LIBBGP_ERR_NOMEM;
    }
    return fsm_update_journal_reserve_withdrawn4_to(journal, journal->withdrawn4_count + 1u);
}

static libbgp_err_t fsm_update_journal_reserve_withdrawn6(fsm_update_journal_t *journal)
{
    if (journal == NULL) {
        return LIBBGP_OK;
    }
    if (journal->withdrawn6_count == SIZE_MAX) {
        return LIBBGP_ERR_NOMEM;
    }
    return fsm_update_journal_reserve_withdrawn6_to(journal, journal->withdrawn6_count + 1u);
}

static libbgp_err_t fsm_update_journal_reserve_update(
    fsm_update_journal_t *journal,
    libbgp_rib4_t *rib4,
    libbgp_rib6_t *rib6,
    const libbgp_update_msg_t *update)
{
    size_t routes4_needed = 0u;
    size_t routes6_needed = 0u;
    size_t withdrawn4_needed = 0u;
    size_t withdrawn6_needed = 0u;
    size_t i;
    libbgp_err_t err;

    if (journal == NULL || update == NULL) {
        return LIBBGP_OK;
    }
    if (rib4 != NULL) {
        if (update->nlri_count > SIZE_MAX - journal->routes4_count) {
            return LIBBGP_ERR_NOMEM;
        }
        if (update->withdrawn_count > SIZE_MAX - journal->withdrawn4_count) {
            return LIBBGP_ERR_NOMEM;
        }
        routes4_needed = journal->routes4_count + update->nlri_count;
        withdrawn4_needed = journal->withdrawn4_count + update->withdrawn_count;
    }
    if (rib6 != NULL) {
        routes6_needed = journal->routes6_count;
        withdrawn6_needed = journal->withdrawn6_count;
        for (i = 0u; i < update->attr_count; i++) {
            const libbgp_pattr_t *attr = update->attrs[i];

            if (attr->type == LIBBGP_PATTR_MP_REACH_IPV6) {
                if (attr->data.mp_reach_ipv6.nlri_count > SIZE_MAX - routes6_needed) {
                    return LIBBGP_ERR_NOMEM;
                }
                routes6_needed += attr->data.mp_reach_ipv6.nlri_count;
            } else if (attr->type == LIBBGP_PATTR_MP_UNREACH_IPV6) {
                if (attr->data.mp_unreach_ipv6.withdrawn_count > SIZE_MAX - withdrawn6_needed) {
                    return LIBBGP_ERR_NOMEM;
                }
                withdrawn6_needed += attr->data.mp_unreach_ipv6.withdrawn_count;
            }
        }
    }
    err = fsm_update_journal_reserve4_to(journal, routes4_needed);
    if (err != LIBBGP_OK) {
        return err;
    }
    err = fsm_update_journal_reserve6_to(journal, routes6_needed);
    if (err != LIBBGP_OK) {
        return err;
    }
    err = fsm_update_journal_reserve_withdrawn4_to(journal, withdrawn4_needed);
    if (err != LIBBGP_OK) {
        return err;
    }
    return fsm_update_journal_reserve_withdrawn6_to(journal, withdrawn6_needed);
}

static libbgp_err_t fsm_update_journal_record4(
    fsm_update_journal_t *journal,
    const libbgp_prefix4_t *prefix,
    uint64_t update_id,
    bool restore_replaced,
    bgp_rib4_saved_route_t *replaced,
    bgp_rib4_change_t *change)
{
    libbgp_err_t err;
    fsm_applied_route4_t *entry;

    if (journal == NULL) {
        return LIBBGP_OK;
    }
    if (prefix == NULL || update_id == 0u) {
        return LIBBGP_OK;
    }
    err = fsm_update_journal_reserve4(journal);
    if (err != LIBBGP_OK) {
        return err;
    }
    entry = &journal->routes4[journal->routes4_count];
    memset(entry, 0, sizeof(*entry));
    entry->seq = journal->event_seq++;
    entry->prefix = *prefix;
    entry->update_id = update_id;
    entry->restore_replaced = restore_replaced;
    if (change != NULL) {
        entry->change_kind = change->kind;
        if ((change->kind == BGP_RIB_CHANGE_NEW_BEST ||
             change->kind == BGP_RIB_CHANGE_REPLACEMENT_BEST) &&
            change->best != NULL) {
            entry->best_route = *change->best;
        }
    }
    if (replaced != NULL) {
        entry->replaced = *replaced;
        replaced->entry = NULL;
    }
    journal->routes4_count++;
    return LIBBGP_OK;
}

static libbgp_err_t fsm_update_journal_record6(
    fsm_update_journal_t *journal,
    const libbgp_prefix6_t *prefix,
    uint64_t update_id,
    bool restore_replaced,
    bgp_rib6_saved_route_t *replaced,
    bgp_rib6_change_t *change)
{
    libbgp_err_t err;
    fsm_applied_route6_t *entry;

    if (journal == NULL) {
        return LIBBGP_OK;
    }
    if (prefix == NULL || update_id == 0u) {
        return LIBBGP_OK;
    }
    err = fsm_update_journal_reserve6(journal);
    if (err != LIBBGP_OK) {
        return err;
    }
    entry = &journal->routes6[journal->routes6_count];
    memset(entry, 0, sizeof(*entry));
    entry->seq = journal->event_seq++;
    entry->prefix = *prefix;
    entry->update_id = update_id;
    entry->restore_replaced = restore_replaced;
    if (change != NULL) {
        entry->change_kind = change->kind;
        if ((change->kind == BGP_RIB_CHANGE_NEW_BEST ||
             change->kind == BGP_RIB_CHANGE_REPLACEMENT_BEST) &&
            change->best != NULL) {
            entry->best_route = *change->best;
        }
    }
    if (replaced != NULL) {
        entry->replaced = *replaced;
        replaced->entry = NULL;
    }
    journal->routes6_count++;
    return LIBBGP_OK;
}

static bool fsm_update_journal_has_route4(
    const fsm_update_journal_t *journal,
    const libbgp_prefix4_t *prefix,
    uint64_t update_id)
{
    size_t i;

    if (journal == NULL || prefix == NULL || update_id == 0u) {
        return false;
    }
    for (i = 0u; i < journal->routes4_count; i++) {
        if (journal->routes4[i].update_id == update_id &&
            libbgp_prefix4_eq(&journal->routes4[i].prefix, prefix)) {
            return true;
        }
    }
    return false;
}

static bool fsm_update_journal_has_route6(
    const fsm_update_journal_t *journal,
    const libbgp_prefix6_t *prefix,
    uint64_t update_id)
{
    size_t i;

    if (journal == NULL || prefix == NULL || update_id == 0u) {
        return false;
    }
    for (i = 0u; i < journal->routes6_count; i++) {
        if (journal->routes6[i].update_id == update_id &&
            libbgp_prefix6_eq(&journal->routes6[i].prefix, prefix)) {
            return true;
        }
    }
    return false;
}

static libbgp_err_t fsm_update_journal_record_withdraw4(
    fsm_update_journal_t *journal,
    libbgp_rib4_t *rib4,
    uint32_t peer_bgp_id,
    const libbgp_prefix4_t *prefix)
{
    libbgp_err_t err;
    libbgp_err_t snapshot_err;
    libbgp_rib4_route_t best_before;
    libbgp_rib4_route_t best_after;
    bool had_route = false;
    bool before_found = false;
    bool after_found = false;
    bool removed_best = false;
    uint64_t removed_update_id = 0u;
    fsm_withdrawn_route4_t *entry;

    if (journal == NULL || rib4 == NULL) {
        return LIBBGP_OK;
    }
    memset(&best_before, 0, sizeof(best_before));
    memset(&best_after, 0, sizeof(best_after));
    err = bgp_rib4_best_exact_clone(rib4, prefix, &best_before, &before_found);
    if (err != LIBBGP_OK) {
        return err;
    }
    err = fsm_update_journal_reserve_withdrawn4(journal);
    if (err != LIBBGP_OK) {
        bgp_rib4_route_snapshot_destroy(&best_before);
        return err;
    }
    entry = &journal->withdrawn4[journal->withdrawn4_count];
    memset(entry, 0, sizeof(*entry));
    entry->prefix = *prefix;
    err = bgp_rib4_withdraw_exact_save(rib4, peer_bgp_id, prefix, &entry->saved, &had_route);
    if (err == LIBBGP_OK && had_route) {
        snapshot_err = bgp_rib4_saved_route_update_id(&entry->saved, &removed_update_id);
        if (snapshot_err == LIBBGP_OK && before_found &&
            best_before.source_router_id == peer_bgp_id &&
            best_before.update_id == removed_update_id) {
            removed_best = true;
            err = bgp_rib4_best_exact_clone(rib4, prefix, &best_after, &after_found);
        } else if (snapshot_err != LIBBGP_OK) {
            err = snapshot_err;
        }
    }
    if (err == LIBBGP_OK && had_route) {
        entry->seq = journal->event_seq++;
        if (removed_best && after_found) {
            entry->publish_replacement = true;
            entry->replacement_route = best_after;
            memset(&best_after, 0, sizeof(best_after));
        } else if (removed_best) {
            entry->publish_withdrawn = true;
        }
        journal->withdrawn4_count++;
    }
    if (err != LIBBGP_OK && had_route) {
        (void)bgp_rib4_restore_saved_if_absent(rib4, peer_bgp_id, &entry->saved);
        bgp_rib4_saved_route_destroy(&entry->saved);
    }
    bgp_rib4_route_snapshot_destroy(&best_after);
    bgp_rib4_route_snapshot_destroy(&best_before);
    return err;
}

static libbgp_err_t fsm_update_journal_record_withdraw6(
    fsm_update_journal_t *journal,
    libbgp_rib6_t *rib6,
    uint32_t peer_bgp_id,
    const libbgp_prefix6_t *prefix)
{
    libbgp_err_t err;
    libbgp_err_t snapshot_err;
    libbgp_rib6_route_t best_before;
    libbgp_rib6_route_t best_after;
    bool had_route = false;
    bool before_found = false;
    bool after_found = false;
    bool removed_best = false;
    uint64_t removed_update_id = 0u;
    fsm_withdrawn_route6_t *entry;

    if (journal == NULL || rib6 == NULL) {
        return LIBBGP_OK;
    }
    memset(&best_before, 0, sizeof(best_before));
    memset(&best_after, 0, sizeof(best_after));
    err = bgp_rib6_best_exact_clone(rib6, prefix, &best_before, &before_found);
    if (err != LIBBGP_OK) {
        return err;
    }
    err = fsm_update_journal_reserve_withdrawn6(journal);
    if (err != LIBBGP_OK) {
        bgp_rib6_route_snapshot_destroy(&best_before);
        return err;
    }
    entry = &journal->withdrawn6[journal->withdrawn6_count];
    memset(entry, 0, sizeof(*entry));
    entry->prefix = *prefix;
    err = bgp_rib6_withdraw_exact_save(rib6, peer_bgp_id, prefix, &entry->saved, &had_route);
    if (err == LIBBGP_OK && had_route) {
        snapshot_err = bgp_rib6_saved_route_update_id(&entry->saved, &removed_update_id);
        if (snapshot_err == LIBBGP_OK && before_found &&
            best_before.source_router_id == peer_bgp_id &&
            best_before.update_id == removed_update_id) {
            removed_best = true;
            err = bgp_rib6_best_exact_clone(rib6, prefix, &best_after, &after_found);
        } else if (snapshot_err != LIBBGP_OK) {
            err = snapshot_err;
        }
    }
    if (err == LIBBGP_OK && had_route) {
        entry->seq = journal->event_seq++;
        if (removed_best && after_found) {
            entry->publish_replacement = true;
            entry->replacement_route = best_after;
            memset(&best_after, 0, sizeof(best_after));
        } else if (removed_best) {
            entry->publish_withdrawn = true;
        }
        journal->withdrawn6_count++;
    }
    if (err != LIBBGP_OK && had_route) {
        (void)bgp_rib6_restore_saved_if_absent(rib6, peer_bgp_id, &entry->saved);
        bgp_rib6_saved_route_destroy(&entry->saved);
    }
    bgp_rib6_route_snapshot_destroy(&best_after);
    bgp_rib6_route_snapshot_destroy(&best_before);
    return err;
}

static void fsm_remove_journaled_insertions(
    const fsm_update_journal_t *journal,
    libbgp_rib4_t *rib4,
    libbgp_rib6_t *rib6,
    uint32_t peer_bgp_id)
{
    size_t i;

    if (journal == NULL) {
        return;
    }
    if (rib4 != NULL) {
        for (i = journal->routes4_count; i > 0u; i--) {
            (void)bgp_rib4_withdraw_exact_if_update_id(
                rib4,
                peer_bgp_id,
                &journal->routes4[i - 1u].prefix,
                journal->routes4[i - 1u].update_id);
        }
    }
    if (rib6 != NULL) {
        for (i = journal->routes6_count; i > 0u; i--) {
            (void)bgp_rib6_withdraw_exact_if_update_id(
                rib6,
                peer_bgp_id,
                &journal->routes6[i - 1u].prefix,
                journal->routes6[i - 1u].update_id);
        }
    }
}

static void fsm_restore_journaled_replacements(
    const fsm_update_journal_t *journal,
    libbgp_rib4_t *rib4,
    libbgp_rib6_t *rib6,
    uint32_t peer_bgp_id)
{
    size_t i;

    if (journal == NULL) {
        return;
    }
    if (rib4 != NULL) {
        for (i = 0u; i < journal->routes4_count; i++) {
            if (journal->routes4[i].restore_replaced) {
                (void)bgp_rib4_restore_saved_if_absent(rib4, peer_bgp_id, &journal->routes4[i].replaced);
            }
        }
    }
    if (rib6 != NULL) {
        for (i = 0u; i < journal->routes6_count; i++) {
            if (journal->routes6[i].restore_replaced) {
                (void)bgp_rib6_restore_saved_if_absent(rib6, peer_bgp_id, &journal->routes6[i].replaced);
            }
        }
    }
}

static void fsm_restore_journaled_withdrawals(
    const fsm_update_journal_t *journal,
    libbgp_rib4_t *rib4,
    libbgp_rib6_t *rib6,
    uint32_t peer_bgp_id)
{
    size_t i;

    if (journal == NULL) {
        return;
    }
    if (rib4 != NULL) {
        for (i = 0u; i < journal->withdrawn4_count; i++) {
            (void)bgp_rib4_restore_saved_if_absent(rib4, peer_bgp_id, &journal->withdrawn4[i].saved);
        }
    }
    if (rib6 != NULL) {
        for (i = 0u; i < journal->withdrawn6_count; i++) {
            (void)bgp_rib6_restore_saved_if_absent(rib6, peer_bgp_id, &journal->withdrawn6[i].saved);
        }
    }
}

static void fsm_rollback_update_journal(
    const fsm_update_journal_t *journal,
    libbgp_rib4_t *rib4,
    libbgp_rib6_t *rib6,
    uint32_t peer_bgp_id)
{
    fsm_remove_journaled_insertions(journal, rib4, rib6, peer_bgp_id);
    fsm_restore_journaled_replacements(journal, rib4, rib6, peer_bgp_id);
    fsm_restore_journaled_withdrawals(journal, rib4, rib6, peer_bgp_id);
}

static void fsm_cleanup_stale_update_journal(
    const fsm_update_journal_t *journal,
    libbgp_rib4_t *rib4,
    libbgp_rib6_t *rib6,
    uint32_t peer_bgp_id)
{
    fsm_remove_journaled_insertions(journal, rib4, rib6, peer_bgp_id);
}

static void fsm_mark_rx_current(fsm_impl_t *impl)
{
    if (impl->clock_initialized) {
        impl->last_rx_ms = impl->current_ms;
    }
}

static bool fsm_update_session_current(fsm_impl_t *impl, uint64_t session_generation)
{
    return impl->state == LIBBGP_FSM_ESTABLISHED &&
        impl->session_generation == session_generation;
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
    if (attr->data.as_path.segment_count != 0u && attr->data.as_path.segments == NULL) {
        return 0u;
    }
    for (i = 0u; i < attr->data.as_path.segment_count; i++) {
        const libbgp_as_path_segment_t *seg = &attr->data.as_path.segments[i];
        size_t j;

        if (seg->type != 2u) {
            continue;
        }
        if (seg->asn_count != 0u && seg->asns == NULL) {
            continue;
        }
        len += seg->asn_count;
        if (origin_as != NULL) {
            for (j = 0u; j < seg->asn_count; j++) {
                *origin_as = seg->asns[j];
            }
        }
    }
    return len;
}

static bool fsm_update_has_advertisements(const libbgp_update_msg_t *update)
{
    size_t i;

    if (update == NULL) {
        return false;
    }
    if (update->nlri_count != 0u) {
        return true;
    }
    for (i = 0u; i < update->attr_count; i++) {
        const libbgp_pattr_t *attr = update->attrs[i];

        if (attr != NULL &&
            attr->type == LIBBGP_PATTR_MP_REACH_IPV6 &&
            attr->data.mp_reach_ipv6.nlri_count != 0u) {
            return true;
        }
    }
    return false;
}

static bool fsm_prefix4_contains_addr(const libbgp_prefix4_t *prefix, uint32_t addr)
{
    libbgp_prefix4_t host;

    if (prefix == NULL) {
        return true;
    }
    host.addr = addr;
    host.len = 32u;
    return libbgp_prefix4_includes(prefix, &host);
}

static bool fsm_prefix6_contains_addr(const libbgp_prefix6_t *prefix, const uint8_t addr[16])
{
    libbgp_prefix6_t host;

    if (prefix == NULL) {
        return true;
    }
    if (addr == NULL) {
        return false;
    }
    memcpy(host.addr, addr, sizeof(host.addr));
    host.len = 128u;
    return libbgp_prefix6_includes(prefix, &host);
}

static bool fsm_valid_addr4(const fsm_impl_t *impl, uint32_t addr)
{
    uint8_t bytes[4];
    uint8_t first;

    if (impl != NULL &&
        (addr == impl->default_nexthop4 || addr == impl->config.local_bgp_id)) {
        return false;
    }
    memcpy(bytes, &addr, sizeof(bytes));
    first = bytes[0];
    if (first == 0u || first == 127u || first >= 224u) {
        return false;
    }
    return true;
}

static bool fsm_zero_addr6(const uint8_t addr[16])
{
    static const uint8_t zero[16] = { 0u };

    return addr != NULL && memcmp(addr, zero, sizeof(zero)) == 0;
}

static bool fsm_linklocal_addr6(const uint8_t addr[16])
{
    return addr != NULL && addr[0] == 0xfeu && (addr[1] & 0xc0u) == 0x80u;
}

static bool fsm_valid_addr6(const uint8_t addr[16])
{
    if (addr == NULL || fsm_zero_addr6(addr)) {
        return false;
    }
    if (addr[0] == 0xffu || fsm_linklocal_addr6(addr)) {
        return false;
    }
    return true;
}

static int fsm_router_id_cmp(uint32_t a, uint32_t b)
{
    uint8_t a_bytes[4];
    uint8_t b_bytes[4];

    memcpy(a_bytes, &a, sizeof(a_bytes));
    memcpy(b_bytes, &b, sizeof(b_bytes));
    return memcmp(a_bytes, b_bytes, sizeof(a_bytes));
}

static bool fsm_ipv4_next_hop_acceptable(const fsm_impl_t *impl, uint32_t next_hop, bool is_ibgp)
{
    if (!fsm_valid_addr4(impl, next_hop)) {
        return false;
    }
    if (impl != NULL && !impl->no_nexthop_check4 && !is_ibgp &&
        !fsm_prefix4_contains_addr(&impl->peering_lan4, next_hop)) {
        return false;
    }
    return true;
}

static bool fsm_ipv6_next_hop_acceptable(
    const fsm_impl_t *impl,
    const uint8_t next_hop[32],
    size_t next_hop_len,
    bool is_ibgp)
{
    if (next_hop == NULL || (next_hop_len != 16u && next_hop_len != 32u)) {
        return false;
    }
    if (!fsm_valid_addr6(next_hop)) {
        return false;
    }
    if (next_hop_len == 32u && !fsm_zero_addr6(&next_hop[16]) &&
        !fsm_linklocal_addr6(&next_hop[16])) {
        return false;
    }
    if (impl != NULL && !impl->no_nexthop_check6 && !is_ibgp &&
        !fsm_prefix6_contains_addr(&impl->peering_lan6, next_hop)) {
        return false;
    }
    return true;
}

static libbgp_err_t fsm_update_set_next_hop4(libbgp_update_msg_t *update, uint32_t next_hop)
{
    libbgp_pattr_t *attr;
    libbgp_err_t err;

    if (update == NULL) {
        return LIBBGP_ERR_INVALID;
    }
    attr = libbgp_update_find_attr(update, LIBBGP_PATTR_NEXT_HOP);
    if (attr != NULL) {
        attr->data.next_hop.next_hop = next_hop;
        return LIBBGP_OK;
    }
    attr = libbgp_pattr_new(LIBBGP_PATTR_NEXT_HOP);
    if (attr == NULL) {
        return LIBBGP_ERR_NOMEM;
    }
    attr->data.next_hop.next_hop = next_hop;
    err = libbgp_update_add_attr(update, attr);
    libbgp_pattr_unref(attr);
    return err;
}

static libbgp_err_t fsm_update_ensure_origin(libbgp_update_msg_t *update, uint8_t origin)
{
    libbgp_pattr_t *attr;
    libbgp_err_t err;

    if (libbgp_update_find_attr(update, LIBBGP_PATTR_ORIGIN) != NULL) {
        return LIBBGP_OK;
    }
    attr = libbgp_pattr_new(LIBBGP_PATTR_ORIGIN);
    if (attr == NULL) {
        return LIBBGP_ERR_NOMEM;
    }
    attr->data.origin.origin = origin;
    err = libbgp_update_add_attr(update, attr);
    libbgp_pattr_unref(attr);
    return err;
}

static libbgp_err_t fsm_update_ensure_empty_as_path(libbgp_update_msg_t *update)
{
    libbgp_pattr_t *attr;
    libbgp_err_t err;

    if (libbgp_update_find_attr(update, LIBBGP_PATTR_AS_PATH) != NULL) {
        return LIBBGP_OK;
    }
    attr = libbgp_pattr_new(LIBBGP_PATTR_AS_PATH);
    if (attr == NULL) {
        return LIBBGP_ERR_NOMEM;
    }
    attr->data.as_path.is_4b = true;
    err = libbgp_update_add_attr(update, attr);
    libbgp_pattr_unref(attr);
    return err;
}

static libbgp_err_t fsm_alter_nexthop4(
    libbgp_update_msg_t *update,
    const libbgp_prefix4_t *peering_lan4,
    uint32_t default_nexthop4,
    bool force_default_nexthop4,
    bool is_ibgp,
    bool ibgp_alter_nexthop)
{
    libbgp_pattr_t *next_hop;

    if (update == NULL || update->nlri_count == 0u) {
        return LIBBGP_OK;
    }
    if (is_ibgp && !ibgp_alter_nexthop) {
        return LIBBGP_OK;
    }
    next_hop = libbgp_update_find_attr(update, LIBBGP_PATTR_NEXT_HOP);
    if (force_default_nexthop4 || next_hop == NULL) {
        if (!fsm_valid_addr4(NULL, default_nexthop4)) {
            return LIBBGP_ERR_INVALID;
        }
        return fsm_update_set_next_hop4(update, default_nexthop4);
    }
    if (!fsm_prefix4_contains_addr(peering_lan4, next_hop->data.next_hop.next_hop)) {
        if (!fsm_valid_addr4(NULL, default_nexthop4)) {
            return LIBBGP_ERR_INVALID;
        }
        next_hop->data.next_hop.next_hop = default_nexthop4;
    }
    return LIBBGP_OK;
}

static libbgp_err_t fsm_alter_nexthop6(
    libbgp_update_msg_t *update,
    const libbgp_prefix6_t *peering_lan6,
    const uint8_t default_nexthop6[16],
    const uint8_t default_nexthop6_linklocal[16],
    bool force_default_nexthop6,
    bool is_ibgp,
    bool ibgp_alter_nexthop)
{
    size_t i;

    if (update == NULL || default_nexthop6 == NULL) {
        return LIBBGP_ERR_INVALID;
    }
    if (is_ibgp && !ibgp_alter_nexthop) {
        return LIBBGP_OK;
    }
    for (i = 0u; i < update->attr_count; i++) {
        libbgp_pattr_t *attr = update->attrs[i];

        if (attr == NULL || attr->type != LIBBGP_PATTR_MP_REACH_IPV6 ||
            attr->data.mp_reach_ipv6.nlri_count == 0u) {
            continue;
        }
        if (force_default_nexthop6 ||
            !fsm_prefix6_contains_addr(peering_lan6, attr->data.mp_reach_ipv6.nexthop)) {
            if (!fsm_valid_addr6(default_nexthop6)) {
                return LIBBGP_ERR_INVALID;
            }
            if (default_nexthop6_linklocal != NULL &&
                !fsm_zero_addr6(default_nexthop6_linklocal) &&
                !fsm_linklocal_addr6(default_nexthop6_linklocal)) {
                return LIBBGP_ERR_INVALID;
            }
            memcpy(attr->data.mp_reach_ipv6.nexthop, default_nexthop6, 16u);
            if (default_nexthop6_linklocal != NULL &&
                !fsm_zero_addr6(default_nexthop6_linklocal)) {
                memcpy(&attr->data.mp_reach_ipv6.nexthop[16], default_nexthop6_linklocal, 16u);
                attr->data.mp_reach_ipv6.nexthop_len = 32u;
            } else {
                memset(&attr->data.mp_reach_ipv6.nexthop[16], 0, 16u);
                attr->data.mp_reach_ipv6.nexthop_len = 16u;
            }
        }
    }
    return LIBBGP_OK;
}

static bool fsm_as_path_exceeds_local_as(
    const libbgp_pattr_t *attr,
    uint32_t local_asn,
    uint8_t allow_local_as)
{
    size_t i;

    if (attr == NULL || attr->type != LIBBGP_PATTR_AS_PATH) {
        return false;
    }
    if (attr->data.as_path.segment_count != 0u && attr->data.as_path.segments == NULL) {
        return false;
    }
    for (i = 0u; i < attr->data.as_path.segment_count; i++) {
        const libbgp_as_path_segment_t *seg = &attr->data.as_path.segments[i];
        size_t local_count = 0u;
        size_t j;

        if (seg->asn_count != 0u && seg->asns == NULL) {
            continue;
        }
        for (j = 0u; j < seg->asn_count; j++) {
            if (seg->asns[j] == local_asn) {
                local_count++;
            }
        }
        if (local_count > (size_t)allow_local_as) {
            return true;
        }
    }
    return false;
}

static libbgp_err_t fsm_update_exceeds_local_as(
    const libbgp_update_msg_t *update,
    uint32_t local_asn,
    uint8_t allow_local_as,
    bool restore_as4_path,
    bool *exceeds)
{
    libbgp_update_msg_t restored;
    libbgp_err_t err;

    if (exceeds == NULL) {
        return LIBBGP_ERR_INVALID;
    }
    *exceeds = false;
    if (!fsm_update_has_advertisements(update)) {
        return LIBBGP_OK;
    }
    if (!restore_as4_path || libbgp_update_find_attr(update, LIBBGP_PATTR_AS4_PATH) == NULL) {
        *exceeds = fsm_as_path_exceeds_local_as(
            libbgp_update_find_attr(update, LIBBGP_PATTR_AS_PATH),
            local_asn,
            allow_local_as);
        return LIBBGP_OK;
    }

    libbgp_update_init(&restored);
    err = fsm_clone_update(update, &restored);
    if (err == LIBBGP_OK) {
        err = libbgp_update_restore_as_path(&restored);
    }
    if (err == LIBBGP_OK) {
        *exceeds = fsm_as_path_exceeds_local_as(
            libbgp_update_find_attr(&restored, LIBBGP_PATTR_AS_PATH),
            local_asn,
            allow_local_as);
    }
    libbgp_update_destroy(&restored);
    return err;
}

static void fsm_fill_route_attrs(
    libbgp_rib4_route_t *route,
    const libbgp_update_msg_t *update,
    int32_t weight)
{
    libbgp_pattr_t *attr;

    route->attrs = update->attrs;
    route->attr_count = update->attr_count;
    route->weight = weight;
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

static bool fsm_ipv4_route_attr(const libbgp_pattr_t *attr)
{
    return attr != NULL &&
        attr->type != LIBBGP_PATTR_MP_REACH_IPV6 &&
        attr->type != LIBBGP_PATTR_MP_UNREACH_IPV6;
}

static bool fsm_ipv6_route_attr(const libbgp_pattr_t *attr)
{
    return attr != NULL &&
        attr->type != LIBBGP_PATTR_NEXT_HOP &&
        attr->type != LIBBGP_PATTR_MP_REACH_IPV6 &&
        attr->type != LIBBGP_PATTR_MP_UNREACH_IPV6;
}

static void fsm_fill_route6_attrs(
    libbgp_rib6_route_t *route,
    const libbgp_update_msg_t *update,
    const libbgp_pattr_t *mp_reach,
    int32_t weight)
{
    libbgp_pattr_t *attr;

    route->weight = weight;
    route->local_pref = 100u;
    memcpy(route->next_hop, mp_reach->data.mp_reach_ipv6.nexthop, sizeof(route->next_hop));
    if (mp_reach->data.mp_reach_ipv6.nexthop_len == 32u) {
        memcpy(
            route->next_hop_linklocal,
            &mp_reach->data.mp_reach_ipv6.nexthop[16],
            sizeof(route->next_hop_linklocal));
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

static libbgp_err_t fsm_make_route6(
    uint32_t peer_bgp_id,
    const libbgp_update_msg_t *update,
    const libbgp_pattr_t *mp_reach,
    const libbgp_prefix6_t *prefix,
    int32_t weight,
    bool is_ibgp,
    libbgp_rib6_route_t *route)
{
    libbgp_pattr_t **filtered = NULL;
    size_t i;
    size_t count = 0u;

    if (route == NULL) {
        return LIBBGP_ERR_INVALID;
    }
    if (mp_reach->data.mp_reach_ipv6.nexthop_len != 16u &&
        mp_reach->data.mp_reach_ipv6.nexthop_len != 32u) {
        return LIBBGP_ERR_INVALID;
    }
    memset(route, 0, sizeof(*route));
    route->prefix = *prefix;
    route->source_router_id = peer_bgp_id;
    route->is_ibgp = is_ibgp;
    fsm_fill_route6_attrs(route, update, mp_reach, weight);
    for (i = 0u; i < update->attr_count; i++) {
        if (fsm_ipv6_route_attr(update->attrs[i])) {
            count++;
        }
    }
    if (count != 0u) {
        size_t pos = 0u;

        if (count > SIZE_MAX / sizeof(*filtered)) {
            return LIBBGP_ERR_NOMEM;
        }
        filtered = (libbgp_pattr_t **)bgp_calloc(count, sizeof(*filtered));
        if (filtered == NULL) {
            return LIBBGP_ERR_NOMEM;
        }
        for (i = 0u; i < update->attr_count; i++) {
            if (fsm_ipv6_route_attr(update->attrs[i])) {
                filtered[pos++] = update->attrs[i];
            }
        }
    }
    route->attrs = filtered;
    route->attr_count = count;
    return LIBBGP_OK;
}

static void fsm_made_route6_destroy(libbgp_rib6_route_t *route)
{
    if (route == NULL) {
        return;
    }
    bgp_free(route->attrs);
    route->attrs = NULL;
    route->attr_count = 0u;
}

static libbgp_err_t fsm_validate_update_mp_attr(const libbgp_pattr_t *attr, uint8_t *notify_subcode)
{
    size_t i;

    if (attr->type == LIBBGP_PATTR_MP_REACH_IPV6) {
        if (attr->data.mp_reach_ipv6.nexthop_len != 16u &&
            attr->data.mp_reach_ipv6.nexthop_len != 32u) {
            if (notify_subcode != NULL) {
                *notify_subcode = FSM_UPDATE_ERR_ATTR_LEN;
            }
            return LIBBGP_ERR_INVALID;
        }
        if (attr->data.mp_reach_ipv6.nlri_count != 0u &&
            attr->data.mp_reach_ipv6.nlri == NULL) {
            if (notify_subcode != NULL) {
                *notify_subcode = FSM_UPDATE_ERR_MALFORMED_ATTR_LIST;
            }
            return LIBBGP_ERR_INVALID;
        }
        for (i = 0u; i < attr->data.mp_reach_ipv6.nlri_count; i++) {
            if (attr->data.mp_reach_ipv6.nlri[i].len > 128u) {
                if (notify_subcode != NULL) {
                    *notify_subcode = FSM_UPDATE_ERR_MALFORMED_ATTR_LIST;
                }
                return LIBBGP_ERR_INVALID;
            }
        }
    } else if (attr->type == LIBBGP_PATTR_MP_UNREACH_IPV6) {
        if (attr->data.mp_unreach_ipv6.withdrawn_count != 0u &&
            attr->data.mp_unreach_ipv6.withdrawn == NULL) {
            if (notify_subcode != NULL) {
                *notify_subcode = FSM_UPDATE_ERR_MALFORMED_ATTR_LIST;
            }
            return LIBBGP_ERR_INVALID;
        }
        for (i = 0u; i < attr->data.mp_unreach_ipv6.withdrawn_count; i++) {
            if (attr->data.mp_unreach_ipv6.withdrawn[i].len > 128u) {
                if (notify_subcode != NULL) {
                    *notify_subcode = FSM_UPDATE_ERR_MALFORMED_ATTR_LIST;
                }
                return LIBBGP_ERR_INVALID;
            }
        }
    }
    return LIBBGP_OK;
}

static bool fsm_semantic_duplicate_attr(libbgp_pattr_type_t type)
{
    switch (type) {
    case LIBBGP_PATTR_ORIGIN:
    case LIBBGP_PATTR_AS_PATH:
    case LIBBGP_PATTR_NEXT_HOP:
    case LIBBGP_PATTR_MED:
    case LIBBGP_PATTR_LOCAL_PREF:
    case LIBBGP_PATTR_ATOMIC_AGGREGATE:
    case LIBBGP_PATTR_AGGREGATOR:
    case LIBBGP_PATTR_COMMUNITY:
    case LIBBGP_PATTR_AS4_PATH:
    case LIBBGP_PATTR_AS4_AGGREGATOR:
    case LIBBGP_PATTR_MP_REACH_IPV6:
    case LIBBGP_PATTR_MP_UNREACH_IPV6:
        return true;
    case LIBBGP_PATTR_UNKNOWN:
    default:
        return false;
    }
}

static libbgp_err_t fsm_validate_update(const libbgp_update_msg_t *update, uint8_t *notify_subcode)
{
    size_t i;
    size_t origin_count = 0u;
    size_t as_path_count = 0u;
    size_t next_hop_count = 0u;
    size_t attr_counts[(size_t)LIBBGP_PATTR_UNKNOWN + 1u];
    bool ipv4_advertise;
    bool ipv6_advertise = false;
    libbgp_err_t err;

    if (update == NULL ||
        (update->withdrawn_count != 0u && update->withdrawn == NULL) ||
        (update->attr_count != 0u && update->attrs == NULL) ||
        (update->nlri_count != 0u && update->nlri == NULL)) {
        if (notify_subcode != NULL) {
            *notify_subcode = FSM_UPDATE_ERR_MALFORMED_ATTR_LIST;
        }
        return LIBBGP_ERR_INVALID;
    }
    for (i = 0u; i < update->withdrawn_count; i++) {
        if (update->withdrawn[i].len > 32u) {
            if (notify_subcode != NULL) {
                *notify_subcode = FSM_UPDATE_ERR_MALFORMED_ATTR_LIST;
            }
            return LIBBGP_ERR_INVALID;
        }
    }
    for (i = 0u; i < update->nlri_count; i++) {
        if (update->nlri[i].len > 32u) {
            if (notify_subcode != NULL) {
                *notify_subcode = FSM_UPDATE_ERR_MALFORMED_ATTR_LIST;
            }
            return LIBBGP_ERR_INVALID;
        }
    }
    memset(attr_counts, 0, sizeof(attr_counts));
    for (i = 0u; i < update->attr_count; i++) {
        libbgp_pattr_type_t type;

        if (update->attrs[i] == NULL) {
            if (notify_subcode != NULL) {
                *notify_subcode = FSM_UPDATE_ERR_MALFORMED_ATTR_LIST;
            }
            return LIBBGP_ERR_INVALID;
        }
        type = update->attrs[i]->type;
        if ((size_t)type <= (size_t)LIBBGP_PATTR_UNKNOWN) {
            attr_counts[(size_t)type]++;
            if (fsm_semantic_duplicate_attr(type) && attr_counts[(size_t)type] > 1u) {
                if (notify_subcode != NULL) {
                    *notify_subcode = FSM_UPDATE_ERR_MALFORMED_ATTR_LIST;
                }
                return LIBBGP_ERR_INVALID;
            }
        }
        if (type == LIBBGP_PATTR_ORIGIN) {
            origin_count++;
        } else if (type == LIBBGP_PATTR_AS_PATH) {
            as_path_count++;
        } else if (type == LIBBGP_PATTR_NEXT_HOP) {
            next_hop_count++;
        } else if (type == LIBBGP_PATTR_MP_REACH_IPV6 &&
            update->attrs[i]->data.mp_reach_ipv6.nlri_count != 0u) {
            ipv6_advertise = true;
        }
        err = fsm_validate_update_mp_attr(update->attrs[i], notify_subcode);
        if (err != LIBBGP_OK) {
            return err;
        }
    }
    ipv4_advertise = update->nlri_count != 0u;
    if (ipv4_advertise &&
        (origin_count != 1u || as_path_count != 1u || next_hop_count != 1u)) {
        if (notify_subcode != NULL) {
            *notify_subcode = FSM_UPDATE_ERR_MISSING_WELL_KNOWN;
        }
        return LIBBGP_ERR_INVALID;
    }
    if (ipv6_advertise && (origin_count != 1u || as_path_count != 1u)) {
        if (notify_subcode != NULL) {
            *notify_subcode = FSM_UPDATE_ERR_MISSING_WELL_KNOWN;
        }
        return LIBBGP_ERR_INVALID;
    }
    return LIBBGP_OK;
}

static libbgp_err_t fsm_apply_update(
    fsm_impl_t *impl,
    uint64_t session_generation,
    libbgp_rib4_t *rib4,
    libbgp_rib6_t *rib6,
    uint32_t peer_bgp_id,
    const libbgp_update_msg_t *update,
    fsm_update_journal_t *journal,
    bool *advertisements_ignored,
    uint8_t *notify_subcode)
{
    size_t i;
    libbgp_err_t err;
    bool ignore_advertisements;
    bool is_ibgp_session;

    err = fsm_validate_update(update, notify_subcode);
    if (err != LIBBGP_OK) {
        return err;
    }
    is_ibgp_session = impl->peer_asn == impl->config.local_asn;
    err = fsm_update_exceeds_local_as(
        update,
        impl->config.local_asn,
        impl->allow_local_as,
        impl->peer_can_send_as4_path,
        &ignore_advertisements);
    if (err != LIBBGP_OK) {
        if (notify_subcode != NULL) {
            *notify_subcode = FSM_UPDATE_ERR_MALFORMED_ATTR_LIST;
        }
        return err;
    }
    if (impl->send_ipv4_routes && !ignore_advertisements && update->nlri_count != 0u) {
        libbgp_pattr_t *next_hop = libbgp_update_find_attr(update, LIBBGP_PATTR_NEXT_HOP);

        if (next_hop == NULL ||
            !fsm_ipv4_next_hop_acceptable(impl, next_hop->data.next_hop.next_hop, is_ibgp_session)) {
            ignore_advertisements = true;
        }
    }
    if (impl->send_ipv6_routes && !ignore_advertisements) {
        for (i = 0u; i < update->attr_count; i++) {
            const libbgp_pattr_t *attr = update->attrs[i];

            if (attr != NULL && attr->type == LIBBGP_PATTR_MP_REACH_IPV6 &&
                attr->data.mp_reach_ipv6.nlri_count != 0u &&
                !fsm_ipv6_next_hop_acceptable(
                    impl,
                    attr->data.mp_reach_ipv6.nexthop,
                    attr->data.mp_reach_ipv6.nexthop_len,
                    is_ibgp_session)) {
                ignore_advertisements = true;
                break;
            }
        }
    }
    if (advertisements_ignored != NULL) {
        *advertisements_ignored = ignore_advertisements;
    }
    err = fsm_update_journal_reserve_update(journal, rib4, rib6, update);
    if (err != LIBBGP_OK) {
        return err;
    }

    for (i = 0u; impl->send_ipv4_routes && i < update->withdrawn_count; i++) {
        err = LIBBGP_OK;

        if (!fsm_update_session_current(impl, session_generation)) {
            return LIBBGP_OK;
        }

        if (rib4 != NULL) {
            err = fsm_update_journal_record_withdraw4(journal, rib4, peer_bgp_id, &update->withdrawn[i]);
            if (err != LIBBGP_OK) {
                return err;
            }
        }
        if (err != LIBBGP_OK) {
            return err;
        }
    }
    for (i = 0u; impl->send_ipv4_routes && !ignore_advertisements && i < update->nlri_count; i++) {
        libbgp_rib4_route_t route;
        libbgp_rib4_route_t best_before;
        libbgp_rib4_route_t best_after;
        bgp_rib4_change_t change;
        bgp_rib4_saved_route_t replaced;
        bool had_replaced = false;
        bool restore_replaced = false;
        bool before_found = false;
        bool after_found = false;
        uint64_t update_id = 0u;
        err = LIBBGP_OK;
        memset(&best_before, 0, sizeof(best_before));
        memset(&best_after, 0, sizeof(best_after));
        memset(&change, 0, sizeof(change));
        memset(&replaced, 0, sizeof(replaced));

        if (!fsm_update_session_current(impl, session_generation)) {
            return LIBBGP_OK;
        }

        memset(&route, 0, sizeof(route));
        route.prefix = update->nlri[i];
        route.source_router_id = peer_bgp_id;
        route.is_ibgp = is_ibgp_session;
        fsm_fill_route_attrs(&route, update, impl->route_weight);
        if (impl->in_filter4 != NULL &&
            libbgp_filter_apply_route(impl->in_filter4, &route, LIBBGP_FILTER_PERMIT) !=
                LIBBGP_FILTER_PERMIT) {
            if (advertisements_ignored != NULL) {
                *advertisements_ignored = true;
            }
            continue;
        }
        if (rib4 != NULL) {
            err = bgp_rib4_best_exact_clone(rib4, &route.prefix, &best_before, &before_found);
        }
        if (err == LIBBGP_OK && rib4 != NULL) {
            err = bgp_rib4_insert_save_replaced(rib4, &route, &replaced, &had_replaced, &update_id);
            if (err == LIBBGP_OK && had_replaced) {
                uint64_t replaced_update_id = 0u;

                err = bgp_rib4_saved_route_update_id(&replaced, &replaced_update_id);
                if (err == LIBBGP_OK) {
                    restore_replaced = !fsm_update_journal_has_route4(journal, &route.prefix, replaced_update_id);
                }
            }
        }
        if (err == LIBBGP_OK && rib4 != NULL) {
            err = bgp_rib4_best_exact_clone(rib4, &route.prefix, &best_after, &after_found);
            if (err == LIBBGP_OK) {
                if (!after_found) {
                    change.kind = BGP_RIB_CHANGE_UNREACHABLE;
                } else if (!before_found) {
                    change.kind = BGP_RIB_CHANGE_NEW_BEST;
                    change.best = &best_after;
                } else if (best_before.source_router_id == best_after.source_router_id &&
                    best_before.update_id == best_after.update_id &&
                    libbgp_prefix4_eq(&best_before.prefix, &best_after.prefix)) {
                    change.kind = BGP_RIB_CHANGE_NO_BEST_CHANGE;
                    change.best = &best_after;
                } else {
                    change.kind = BGP_RIB_CHANGE_REPLACEMENT_BEST;
                    change.best = &best_after;
                }
            }
        }
        if (err == LIBBGP_OK) {
            err = fsm_update_journal_record4(
                journal,
                &route.prefix,
                update_id,
                restore_replaced,
                &replaced,
                &change);
            if (err == LIBBGP_OK && change.best == &best_after &&
                (change.kind == BGP_RIB_CHANGE_NEW_BEST ||
                 change.kind == BGP_RIB_CHANGE_REPLACEMENT_BEST)) {
                memset(&best_after, 0, sizeof(best_after));
            }
        }
        if (err != LIBBGP_OK && rib4 != NULL) {
            (void)bgp_rib4_withdraw_exact_if_update_id(rib4, peer_bgp_id, &route.prefix, update_id);
            (void)bgp_rib4_restore_saved_if_absent(rib4, peer_bgp_id, &replaced);
        }
        bgp_rib4_route_snapshot_destroy(&best_after);
        bgp_rib4_route_snapshot_destroy(&best_before);
        bgp_rib4_saved_route_destroy(&replaced);
        if (err != LIBBGP_OK) {
            return err;
        }
    }
    for (i = 0u; i < update->attr_count; i++) {
        const libbgp_pattr_t *attr = update->attrs[i];
        size_t j;

        if (impl->send_ipv6_routes && attr->type == LIBBGP_PATTR_MP_UNREACH_IPV6) {
            for (j = 0u; j < attr->data.mp_unreach_ipv6.withdrawn_count; j++) {
                err = LIBBGP_OK;

                if (!fsm_update_session_current(impl, session_generation)) {
                    return LIBBGP_OK;
                }

                if (rib6 != NULL) {
                    err = fsm_update_journal_record_withdraw6(
                        journal,
                        rib6,
                        peer_bgp_id,
                        &attr->data.mp_unreach_ipv6.withdrawn[j]);
                    if (err != LIBBGP_OK) {
                        return err;
                    }
                }
                if (err != LIBBGP_OK) {
                    return err;
                }
            }
        }
    }
    for (i = 0u; i < update->attr_count; i++) {
        const libbgp_pattr_t *attr = update->attrs[i];
        size_t j;

        if (impl->send_ipv6_routes && !ignore_advertisements &&
            attr->type == LIBBGP_PATTR_MP_REACH_IPV6) {
            for (j = 0u; j < attr->data.mp_reach_ipv6.nlri_count; j++) {
                libbgp_rib6_route_t route;
                libbgp_rib6_route_t best_before;
                libbgp_rib6_route_t best_after;
                bgp_rib6_change_t change;
                bgp_rib6_saved_route_t replaced;
                bool had_replaced = false;
                bool restore_replaced = false;
                bool route_made = false;
                bool before_found = false;
                bool after_found = false;
                uint64_t update_id = 0u;
                err = LIBBGP_OK;
                memset(&route, 0, sizeof(route));
                memset(&best_before, 0, sizeof(best_before));
                memset(&best_after, 0, sizeof(best_after));
                memset(&change, 0, sizeof(change));
                memset(&replaced, 0, sizeof(replaced));

                if (!fsm_update_session_current(impl, session_generation)) {
                    return LIBBGP_OK;
                }

                if (rib6 != NULL || impl->in_filter6 != NULL) {
                    err = fsm_make_route6(
                        peer_bgp_id,
                        update,
                        attr,
                        &attr->data.mp_reach_ipv6.nlri[j],
                        impl->route_weight,
                        is_ibgp_session,
                        &route);
                    route_made = err == LIBBGP_OK;
                }
                if (err == LIBBGP_OK && impl->in_filter6 != NULL &&
                    libbgp_filter_apply_route6(impl->in_filter6, &route, LIBBGP_FILTER_PERMIT) !=
                        LIBBGP_FILTER_PERMIT) {
                    if (advertisements_ignored != NULL) {
                        *advertisements_ignored = true;
                    }
                    fsm_made_route6_destroy(&route);
                    continue;
                }
                if (err == LIBBGP_OK && rib6 != NULL) {
                    err = bgp_rib6_best_exact_clone(
                        rib6,
                        &attr->data.mp_reach_ipv6.nlri[j],
                        &best_before,
                        &before_found);
                }
                if (err == LIBBGP_OK && rib6 != NULL) {
                    err = bgp_rib6_insert_save_replaced(rib6, &route, &replaced, &had_replaced, &update_id);
                    if (err == LIBBGP_OK && had_replaced) {
                        uint64_t replaced_update_id = 0u;

                        err = bgp_rib6_saved_route_update_id(&replaced, &replaced_update_id);
                        if (err == LIBBGP_OK) {
                            restore_replaced = !fsm_update_journal_has_route6(
                                journal,
                                &attr->data.mp_reach_ipv6.nlri[j],
                                replaced_update_id);
                        }
                    }
                }
                if (err == LIBBGP_OK && rib6 != NULL) {
                    err = bgp_rib6_best_exact_clone(
                        rib6,
                        &attr->data.mp_reach_ipv6.nlri[j],
                        &best_after,
                        &after_found);
                    if (err == LIBBGP_OK) {
                        if (!after_found) {
                            change.kind = BGP_RIB_CHANGE_UNREACHABLE;
                        } else if (!before_found) {
                            change.kind = BGP_RIB_CHANGE_NEW_BEST;
                            change.best = &best_after;
                        } else if (best_before.source_router_id == best_after.source_router_id &&
                            best_before.update_id == best_after.update_id &&
                            libbgp_prefix6_eq(&best_before.prefix, &best_after.prefix)) {
                            change.kind = BGP_RIB_CHANGE_NO_BEST_CHANGE;
                            change.best = &best_after;
                        } else {
                            change.kind = BGP_RIB_CHANGE_REPLACEMENT_BEST;
                            change.best = &best_after;
                        }
                    }
                }
                if (route_made) {
                    fsm_made_route6_destroy(&route);
                }
                if (err == LIBBGP_OK) {
                    err = fsm_update_journal_record6(
                        journal,
                        &attr->data.mp_reach_ipv6.nlri[j],
                        update_id,
                        restore_replaced,
                        &replaced,
                        &change);
                    if (err == LIBBGP_OK && change.best == &best_after &&
                        (change.kind == BGP_RIB_CHANGE_NEW_BEST ||
                         change.kind == BGP_RIB_CHANGE_REPLACEMENT_BEST)) {
                        memset(&best_after, 0, sizeof(best_after));
                    }
                }
                if (err != LIBBGP_OK && rib6 != NULL) {
                    (void)bgp_rib6_withdraw_exact_if_update_id(
                        rib6,
                        peer_bgp_id,
                        &attr->data.mp_reach_ipv6.nlri[j],
                        update_id);
                    (void)bgp_rib6_restore_saved_if_absent(rib6, peer_bgp_id, &replaced);
                }
                bgp_rib6_route_snapshot_destroy(&best_after);
                bgp_rib6_route_snapshot_destroy(&best_before);
                bgp_rib6_saved_route_destroy(&replaced);
                if (err != LIBBGP_OK) {
                    return err;
                }
            }
        }
    }
    return LIBBGP_OK;
}

static bool fsm_publish_snapshot_current(
    fsm_impl_t *impl,
    uint64_t session_generation,
    uint64_t *route_added_sub_id,
    uint64_t *route_withdrawn_sub_id)
{
    bool current;

    bgp_lock(&impl->lock);
    current = fsm_update_session_current(impl, session_generation);
    if (route_added_sub_id != NULL) {
        *route_added_sub_id = impl->route_added_sub_id;
    }
    if (route_withdrawn_sub_id != NULL) {
        *route_withdrawn_sub_id = impl->route_withdrawn_sub_id;
    }
    bgp_unlock(&impl->lock);
    return current;
}

static void fsm_publish_route4_added_snapshot(
    libbgp_event_bus_t *bus,
    uint64_t publisher_id,
    const libbgp_rib4_route_t *route)
{
    libbgp_update_msg_t update;
    libbgp_err_t err;

    if (route == NULL) {
        return;
    }
    err = fsm_update_from_route4(route, &update);
    if (err != LIBBGP_OK) {
        return;
    }
    fsm_publish_event(
        bus,
        publisher_id,
        LIBBGP_EVENT_ROUTE_ADDED,
        route->source_router_id,
        &route->prefix,
        &update);
    libbgp_update_destroy(&update);
}

static void fsm_publish_route6_added_snapshot(
    libbgp_event_bus_t *bus,
    uint64_t publisher_id,
    const libbgp_rib6_route_t *route)
{
    libbgp_update_msg_t update;
    libbgp_err_t err;

    if (route == NULL) {
        return;
    }
    err = fsm_update_from_route6(route, &update);
    if (err != LIBBGP_OK) {
        return;
    }
    fsm_publish_event6(
        bus,
        publisher_id,
        LIBBGP_EVENT_ROUTE_ADDED,
        route->source_router_id,
        &route->prefix,
        &update);
    libbgp_update_destroy(&update);
}

static void fsm_publish_update_events(
    fsm_impl_t *impl,
    uint64_t session_generation,
    libbgp_event_bus_t *bus,
    uint32_t peer_bgp_id,
    const fsm_update_journal_t *journal)
{
    size_t seq;
    size_t i;

    if (journal == NULL) {
        return;
    }
    for (seq = 0u; seq < journal->event_seq; seq++) {
        for (i = 0u; i < journal->withdrawn4_count; i++) {
            uint64_t added_publisher = 0u;
            uint64_t withdrawn_publisher = 0u;

            if (journal->withdrawn4[i].seq != seq ||
                (!journal->withdrawn4[i].publish_replacement &&
                 !journal->withdrawn4[i].publish_withdrawn)) {
                continue;
            }
            if (!fsm_publish_snapshot_current(
                    impl,
                    session_generation,
                    &added_publisher,
                    &withdrawn_publisher)) {
                return;
            }
            if (journal->withdrawn4[i].publish_replacement) {
                fsm_publish_route4_added_snapshot(
                    bus,
                    added_publisher,
                    &journal->withdrawn4[i].replacement_route);
            } else {
                fsm_publish_event(
                    bus,
                    withdrawn_publisher,
                    LIBBGP_EVENT_ROUTE_WITHDRAWN,
                    peer_bgp_id,
                    &journal->withdrawn4[i].prefix,
                    NULL);
            }
            if (!fsm_publish_snapshot_current(impl, session_generation, NULL, NULL)) {
                return;
            }
        }
        for (i = 0u; i < journal->routes4_count; i++) {
            uint64_t added_publisher = 0u;

            if (journal->routes4[i].seq != seq ||
                (journal->routes4[i].change_kind != BGP_RIB_CHANGE_NEW_BEST &&
                 journal->routes4[i].change_kind != BGP_RIB_CHANGE_REPLACEMENT_BEST)) {
                continue;
            }
            if (!fsm_publish_snapshot_current(impl, session_generation, &added_publisher, NULL)) {
                return;
            }
            fsm_publish_route4_added_snapshot(bus, added_publisher, &journal->routes4[i].best_route);
            if (!fsm_publish_snapshot_current(impl, session_generation, NULL, NULL)) {
                return;
            }
        }
        for (i = 0u; i < journal->withdrawn6_count; i++) {
            uint64_t added_publisher = 0u;
            uint64_t withdrawn_publisher = 0u;

            if (journal->withdrawn6[i].seq != seq ||
                (!journal->withdrawn6[i].publish_replacement &&
                 !journal->withdrawn6[i].publish_withdrawn)) {
                continue;
            }
            if (!fsm_publish_snapshot_current(
                    impl,
                    session_generation,
                    &added_publisher,
                    &withdrawn_publisher)) {
                return;
            }
            if (journal->withdrawn6[i].publish_replacement) {
                fsm_publish_route6_added_snapshot(
                    bus,
                    added_publisher,
                    &journal->withdrawn6[i].replacement_route);
            } else {
                fsm_publish_event6(
                    bus,
                    withdrawn_publisher,
                    LIBBGP_EVENT_ROUTE_WITHDRAWN,
                    peer_bgp_id,
                    &journal->withdrawn6[i].prefix,
                    NULL);
            }
            if (!fsm_publish_snapshot_current(impl, session_generation, NULL, NULL)) {
                return;
            }
        }
        for (i = 0u; i < journal->routes6_count; i++) {
            uint64_t added_publisher = 0u;

            if (journal->routes6[i].seq != seq ||
                (journal->routes6[i].change_kind != BGP_RIB_CHANGE_NEW_BEST &&
                 journal->routes6[i].change_kind != BGP_RIB_CHANGE_REPLACEMENT_BEST)) {
                continue;
            }
            if (!fsm_publish_snapshot_current(impl, session_generation, &added_publisher, NULL)) {
                return;
            }
            fsm_publish_route6_added_snapshot(bus, added_publisher, &journal->routes6[i].best_route);
            if (!fsm_publish_snapshot_current(impl, session_generation, NULL, NULL)) {
                return;
            }
        }
    }
}

static void fsm_discard_peer_routes_publish(
    libbgp_event_bus_t *bus,
    libbgp_rib4_t *rib4,
    libbgp_rib6_t *rib6,
    uint32_t peer_bgp_id)
{
    bgp_rib4_discard_result_t result4;
    bgp_rib6_discard_result_t result6;
    size_t i;

    memset(&result4, 0, sizeof(result4));
    memset(&result6, 0, sizeof(result6));
    if (rib4 != NULL) {
        if (bgp_rib4_discard_collect(rib4, peer_bgp_id, &result4) == LIBBGP_OK) {
            for (i = 0u; i < result4.withdrawn_count; i++) {
                fsm_publish_event(
                    bus,
                    0u,
                    LIBBGP_EVENT_ROUTE_WITHDRAWN,
                    peer_bgp_id,
                    &result4.withdrawn[i],
                    NULL);
            }
            for (i = 0u; i < result4.replacement_count; i++) {
                fsm_publish_route4_added_snapshot(bus, 0u, &result4.replacements[i]);
            }
        } else {
            (void)libbgp_rib4_discard(rib4, peer_bgp_id);
        }
        bgp_rib4_discard_result_destroy(&result4);
    }
    if (rib6 != NULL) {
        if (bgp_rib6_discard_collect(rib6, peer_bgp_id, &result6) == LIBBGP_OK) {
            for (i = 0u; i < result6.withdrawn_count; i++) {
                fsm_publish_event6(
                    bus,
                    0u,
                    LIBBGP_EVENT_ROUTE_WITHDRAWN,
                    peer_bgp_id,
                    &result6.withdrawn[i],
                    NULL);
            }
            for (i = 0u; i < result6.replacement_count; i++) {
                fsm_publish_route6_added_snapshot(bus, 0u, &result6.replacements[i]);
            }
        } else {
            (void)libbgp_rib6_discard(rib6, peer_bgp_id);
        }
        bgp_rib6_discard_result_destroy(&result6);
    }
}

static void fsm_snapshot_teardown(
    fsm_impl_t *impl,
    libbgp_out_handler_t **out,
    libbgp_event_bus_t **bus,
    libbgp_rib4_t **rib4,
    libbgp_rib6_t **rib6,
    uint32_t *peer_bgp_id)
{
    if (out != NULL) {
        *out = impl->out;
    }
    if (bus != NULL) {
        *bus = impl->bus;
    }
    if (rib4 != NULL) {
        *rib4 = impl->rib4;
    }
    if (rib6 != NULL) {
        *rib6 = impl->rib6;
    }
    if (peer_bgp_id != NULL) {
        *peer_bgp_id = impl->peer_bgp_id;
    }
    fsm_set_state(impl, LIBBGP_FSM_IDLE);
    impl->peer_asn = 0u;
    impl->peer_bgp_id = 0u;
    impl->negotiated_hold_time = 0u;
    impl->peer_mpbgp_ipv6 = false;
    impl->peer_4byte_asn = false;
    impl->peer_can_send_as4_path = false;
    impl->send_ipv4_routes = false;
    impl->send_ipv6_routes = false;
    impl->clock_initialized = false;
    impl->local_keepalive_send_pending = false;
    impl->local_keepalive_pending = false;
    impl->passive_open_send_pending = false;
    impl->passive_keepalive_pending = false;
    impl->session_generation++;
}

static void fsm_unsubscribe_route_events(
    libbgp_event_bus_t *bus,
    uint64_t route_added_sub_id,
    uint64_t route_withdrawn_sub_id,
    uint64_t collision_sub_id)
{
    if (bus == NULL) {
        return;
    }
    if (route_added_sub_id != 0u) {
        (void)libbgp_event_bus_unsubscribe(bus, route_added_sub_id);
    }
    if (route_withdrawn_sub_id != 0u) {
        (void)libbgp_event_bus_unsubscribe(bus, route_withdrawn_sub_id);
    }
    if (collision_sub_id != 0u) {
        (void)libbgp_event_bus_unsubscribe(bus, collision_sub_id);
    }
}

static libbgp_err_t fsm_send_borrowed_update(
    libbgp_out_handler_t *out,
    const libbgp_update_msg_t *update)
{
    libbgp_packet_t pkt;

    if (update == NULL) {
        return LIBBGP_ERR_INVALID;
    }
    memset(&pkt, 0, sizeof(pkt));
    pkt.type = LIBBGP_PACKET_UPDATE;
    pkt.data.update = *update;
    return fsm_send_packet(out, &pkt);
}

static bool fsm_pattr_parse_as4_context(const libbgp_pattr_t *attr)
{
    if (attr == NULL) {
        return false;
    }
    if ((attr->type == LIBBGP_PATTR_AS_PATH || attr->type == LIBBGP_PATTR_AS4_PATH) &&
        attr->data.as_path.is_4b) {
        return true;
    }
    if ((attr->type == LIBBGP_PATTR_AGGREGATOR || attr->type == LIBBGP_PATTR_AS4_AGGREGATOR) &&
        attr->data.aggregator.is_4b) {
        return true;
    }
    return attr->type == LIBBGP_PATTR_AS4_PATH || attr->type == LIBBGP_PATTR_AS4_AGGREGATOR;
}

static libbgp_err_t fsm_clone_pattr(const libbgp_pattr_t *attr, libbgp_pattr_t **out_attr)
{
    uint8_t buf[LIBBGP_BGP_MAX_PACKET_LEN];
    size_t len = 0u;
    size_t used = 0u;
    libbgp_pattr_t *copy;
    libbgp_err_t err;

    if (attr == NULL || out_attr == NULL) {
        return LIBBGP_ERR_INVALID;
    }
    *out_attr = NULL;
    err = libbgp_pattr_write(attr, buf, sizeof(buf), &len);
    if (err != LIBBGP_OK) {
        return err;
    }
    copy = libbgp_pattr_new(LIBBGP_PATTR_UNKNOWN);
    if (copy == NULL) {
        return LIBBGP_ERR_NOMEM;
    }
    err = libbgp_pattr_parse_as4(copy, buf, len, fsm_pattr_parse_as4_context(attr), &used);
    if (err != LIBBGP_OK || used != len) {
        libbgp_pattr_unref(copy);
        return err == LIBBGP_OK ? LIBBGP_ERR_BAD_LEN : err;
    }
    *out_attr = copy;
    return LIBBGP_OK;
}

static libbgp_err_t fsm_clone_update(const libbgp_update_msg_t *src, libbgp_update_msg_t *dst)
{
    size_t i;
    libbgp_err_t err;

    if (src == NULL || dst == NULL ||
        (src->withdrawn_count != 0u && src->withdrawn == NULL) ||
        (src->attr_count != 0u && src->attrs == NULL) ||
        (src->nlri_count != 0u && src->nlri == NULL)) {
        return LIBBGP_ERR_INVALID;
    }
    libbgp_update_init(dst);
    for (i = 0u; i < src->withdrawn_count; i++) {
        err = libbgp_update_add_withdrawn(dst, &src->withdrawn[i]);
        if (err != LIBBGP_OK) {
            libbgp_update_destroy(dst);
            return err;
        }
    }
    for (i = 0u; i < src->attr_count; i++) {
        libbgp_pattr_t *attr = NULL;

        err = fsm_clone_pattr(src->attrs[i], &attr);
        if (err != LIBBGP_OK) {
            libbgp_update_destroy(dst);
            return err;
        }
        err = libbgp_update_add_attr(dst, attr);
        libbgp_pattr_unref(attr);
        if (err != LIBBGP_OK) {
            libbgp_update_destroy(dst);
            return err;
        }
    }
    for (i = 0u; i < src->nlri_count; i++) {
        err = libbgp_update_add_nlri(dst, &src->nlri[i]);
        if (err != LIBBGP_OK) {
            libbgp_update_destroy(dst);
            return err;
        }
    }
    return LIBBGP_OK;
}

static libbgp_err_t fsm_update_prepare_forward_attrs(libbgp_update_msg_t *update, bool is_ibgp)
{
    size_t i;
    size_t out = 0u;

    if (update == NULL || (update->attr_count != 0u && update->attrs == NULL)) {
        return LIBBGP_ERR_INVALID;
    }
    for (i = 0u; i < update->attr_count; i++) {
        libbgp_pattr_t *attr = update->attrs[i];
        bool keep;
        libbgp_err_t err;

        if (attr == NULL) {
            return LIBBGP_ERR_INVALID;
        }
        keep = (attr->flags & LIBBGP_PATTR_FLAG_TRANSITIVE) != 0u ||
            attr->type == LIBBGP_PATTR_MP_REACH_IPV6 ||
            attr->type == LIBBGP_PATTR_MP_UNREACH_IPV6;
        if (!is_ibgp && attr->type == LIBBGP_PATTR_LOCAL_PREF) {
            keep = false;
        }
        if (keep && !is_ibgp) {
            err = libbgp_pattr_prepare_for_ebgp_forward(attr);
            if (err != LIBBGP_OK) {
                return err;
            }
        }
    }
    for (i = 0u; i < update->attr_count; i++) {
        libbgp_pattr_t *attr = update->attrs[i];
        bool keep = (attr->flags & LIBBGP_PATTR_FLAG_TRANSITIVE) != 0u ||
            attr->type == LIBBGP_PATTR_MP_REACH_IPV6 ||
            attr->type == LIBBGP_PATTR_MP_UNREACH_IPV6;

        if (!is_ibgp && attr->type == LIBBGP_PATTR_LOCAL_PREF) {
            keep = false;
        }
        if (keep) {
            update->attrs[out++] = attr;
        } else {
            libbgp_pattr_unref(attr);
        }
    }
    update->attr_count = out;
    return LIBBGP_OK;
}

static libbgp_err_t fsm_send_prepared_update(
    libbgp_out_handler_t *out,
    const libbgp_update_msg_t *update,
    uint32_t local_asn,
    bool use_4b_asn,
    bool is_ibgp,
    const libbgp_prefix4_t *peering_lan4,
    const libbgp_prefix6_t *peering_lan6,
    uint32_t default_nexthop4,
    const uint8_t default_nexthop6[16],
    const uint8_t default_nexthop6_linklocal[16],
    bool force_default_nexthop4,
    bool force_default_nexthop6,
    bool ibgp_alter_nexthop)
{
    libbgp_update_msg_t copy;
    libbgp_err_t err;

    err = fsm_clone_update(update, &copy);
    if (err != LIBBGP_OK) {
        return err;
    }
    if (fsm_update_has_advertisements(&copy)) {
        err = fsm_update_prepare_forward_attrs(&copy, is_ibgp);
        if (err == LIBBGP_OK) {
            err = fsm_alter_nexthop4(
                &copy,
                peering_lan4,
                default_nexthop4,
                force_default_nexthop4,
                is_ibgp,
                ibgp_alter_nexthop);
        }
        if (err == LIBBGP_OK) {
            err = fsm_alter_nexthop6(
                &copy,
                peering_lan6,
                default_nexthop6,
                default_nexthop6_linklocal,
                force_default_nexthop6,
                is_ibgp,
                ibgp_alter_nexthop);
        }
        if (err == LIBBGP_OK) {
            err = use_4b_asn ? libbgp_update_restore_as_path(&copy) : libbgp_update_downgrade_as_path(&copy);
        }
        if (err == LIBBGP_OK) {
            err = use_4b_asn ? libbgp_update_restore_aggregator(&copy) : libbgp_update_downgrade_aggregator(&copy);
        }
        if (err == LIBBGP_OK && !is_ibgp) {
            err = libbgp_update_prepend_asn(&copy, local_asn, use_4b_asn);
        }
    }
    if (err == LIBBGP_OK) {
        err = fsm_send_borrowed_update(out, &copy);
    }
    libbgp_update_destroy(&copy);
    return err;
}

static libbgp_err_t fsm_send_withdraw4(
    libbgp_out_handler_t *out,
    const libbgp_prefix4_t *prefix)
{
    libbgp_packet_t pkt;
    libbgp_err_t err;

    if (prefix == NULL) {
        return LIBBGP_ERR_INVALID;
    }
    libbgp_packet_init(&pkt);
    pkt.type = LIBBGP_PACKET_UPDATE;
    libbgp_update_init(&pkt.data.update);
    err = libbgp_update_add_withdrawn(&pkt.data.update, prefix);
    if (err == LIBBGP_OK) {
        err = fsm_send_packet(out, &pkt);
    }
    libbgp_packet_destroy(&pkt);
    return err;
}

static libbgp_err_t fsm_send_withdraw6(
    libbgp_out_handler_t *out,
    const libbgp_prefix6_t *prefix)
{
    libbgp_packet_t pkt;
    libbgp_pattr_t *mp;
    libbgp_err_t err;

    if (prefix == NULL) {
        return LIBBGP_ERR_INVALID;
    }
    mp = libbgp_pattr_new(LIBBGP_PATTR_MP_UNREACH_IPV6);
    if (mp == NULL) {
        return LIBBGP_ERR_NOMEM;
    }
    mp->data.mp_unreach_ipv6.withdrawn = (libbgp_prefix6_t *)bgp_calloc(
        1u,
        sizeof(*mp->data.mp_unreach_ipv6.withdrawn));
    if (mp->data.mp_unreach_ipv6.withdrawn == NULL) {
        libbgp_pattr_unref(mp);
        return LIBBGP_ERR_NOMEM;
    }
    mp->data.mp_unreach_ipv6.withdrawn[0] = *prefix;
    mp->data.mp_unreach_ipv6.withdrawn_count = 1u;

    libbgp_packet_init(&pkt);
    pkt.type = LIBBGP_PACKET_UPDATE;
    libbgp_update_init(&pkt.data.update);
    err = libbgp_update_add_attr(&pkt.data.update, mp);
    libbgp_pattr_unref(mp);
    if (err == LIBBGP_OK) {
        err = fsm_send_packet(out, &pkt);
    }
    libbgp_packet_destroy(&pkt);
    return err;
}

static libbgp_err_t fsm_send_route_added4(
    libbgp_out_handler_t *out,
    const libbgp_event_t *event,
    uint32_t local_asn,
    bool use_4b_asn,
    bool is_ibgp,
    const libbgp_prefix4_t *peering_lan4,
    const libbgp_prefix6_t *peering_lan6,
    uint32_t default_nexthop4,
    const uint8_t default_nexthop6[16],
    const uint8_t default_nexthop6_linklocal[16],
    bool force_default_nexthop4,
    bool force_default_nexthop6,
    bool ibgp_alter_nexthop,
    int32_t route_weight)
{
    libbgp_rib4_route_t route;
    libbgp_update_msg_t update;
    libbgp_err_t err;

    if (event == NULL || event->prefix4 == NULL || event->update == NULL) {
        return LIBBGP_ERR_INVALID;
    }
    memset(&route, 0, sizeof(route));
    route.prefix = *event->prefix4;
    route.source_router_id = event->source_router_id;
    route.is_ibgp = is_ibgp;
    fsm_fill_route_attrs(&route, event->update, route_weight);
    err = fsm_update_from_route4(&route, &update);
    if (err != LIBBGP_OK) {
        return err;
    }
    err = fsm_send_prepared_update(
        out,
        &update,
        local_asn,
        use_4b_asn,
        is_ibgp,
        peering_lan4,
        peering_lan6,
        default_nexthop4,
        default_nexthop6,
        default_nexthop6_linklocal,
        force_default_nexthop4,
        force_default_nexthop6,
        ibgp_alter_nexthop);
    libbgp_update_destroy(&update);
    return err;
}

static libbgp_err_t fsm_send_route_added6(
    libbgp_out_handler_t *out,
    const libbgp_event_t *event,
    uint32_t local_asn,
    bool use_4b_asn,
    bool is_ibgp,
    const libbgp_prefix4_t *peering_lan4,
    const libbgp_prefix6_t *peering_lan6,
    uint32_t default_nexthop4,
    const uint8_t default_nexthop6[16],
    const uint8_t default_nexthop6_linklocal[16],
    bool force_default_nexthop4,
    bool force_default_nexthop6,
    bool ibgp_alter_nexthop,
    int32_t route_weight)
{
    const libbgp_pattr_t *mp_reach;
    libbgp_rib6_route_t route;
    libbgp_update_msg_t update;
    bool route_made = false;
    libbgp_err_t err;

    if (event == NULL || event->prefix6 == NULL || event->update == NULL) {
        return LIBBGP_ERR_INVALID;
    }
    mp_reach = fsm_find_mp_reach6_for_prefix(event->update, event->prefix6);
    if (mp_reach == NULL) {
        return LIBBGP_ERR_INVALID;
    }
    err = fsm_make_route6(
        event->source_router_id,
        event->update,
        mp_reach,
        event->prefix6,
        route_weight,
        is_ibgp,
        &route);
    if (err != LIBBGP_OK) {
        return err;
    }
    route_made = true;
    err = fsm_update_from_route6(&route, &update);
    if (route_made) {
        fsm_made_route6_destroy(&route);
    }
    if (err != LIBBGP_OK) {
        return err;
    }
    err = fsm_send_prepared_update(
        out,
        &update,
        local_asn,
        use_4b_asn,
        is_ibgp,
        peering_lan4,
        peering_lan6,
        default_nexthop4,
        default_nexthop6,
        default_nexthop6_linklocal,
        force_default_nexthop4,
        force_default_nexthop6,
        ibgp_alter_nexthop);
    libbgp_update_destroy(&update);
    return err;
}

static libbgp_err_t fsm_send_route_event_update(
    libbgp_out_handler_t *out,
    const libbgp_event_t *event,
    uint32_t local_asn,
    bool use_4b_asn,
    bool is_ibgp,
    const libbgp_prefix4_t *peering_lan4,
    const libbgp_prefix6_t *peering_lan6,
    uint32_t default_nexthop4,
    const uint8_t default_nexthop6[16],
    const uint8_t default_nexthop6_linklocal[16],
    bool force_default_nexthop4,
    bool force_default_nexthop6,
    bool ibgp_alter_nexthop,
    int32_t route_weight)
{
    if (event == NULL) {
        return LIBBGP_ERR_INVALID;
    }
    if (event->type == LIBBGP_EVENT_ROUTE_ADDED) {
        if (event->prefix4 != NULL) {
            return fsm_send_route_added4(
                out,
                event,
                local_asn,
                use_4b_asn,
                is_ibgp,
                peering_lan4,
                peering_lan6,
                default_nexthop4,
                default_nexthop6,
                default_nexthop6_linklocal,
                force_default_nexthop4,
                force_default_nexthop6,
                ibgp_alter_nexthop,
                route_weight);
        }
        if (event->prefix6 != NULL) {
            return fsm_send_route_added6(
                out,
                event,
                local_asn,
                use_4b_asn,
                is_ibgp,
                peering_lan4,
                peering_lan6,
                default_nexthop4,
                default_nexthop6,
                default_nexthop6_linklocal,
                force_default_nexthop4,
                force_default_nexthop6,
                ibgp_alter_nexthop,
                route_weight);
        }
    }
    if (event->type == LIBBGP_EVENT_ROUTE_WITHDRAWN) {
        if (event->prefix4 != NULL) {
            return fsm_send_withdraw4(out, event->prefix4);
        }
        if (event->prefix6 != NULL) {
            return fsm_send_withdraw6(out, event->prefix6);
        }
    }
    return LIBBGP_ERR_INVALID;
}

static bool fsm_out_filter4_permits(
    const libbgp_filter_t *filter,
    const libbgp_event_t *event,
    int32_t route_weight)
{
    libbgp_rib4_route_t route;

    if (filter == NULL || event == NULL ||
        event->type != LIBBGP_EVENT_ROUTE_ADDED ||
        event->prefix4 == NULL) {
        return true;
    }
    memset(&route, 0, sizeof(route));
    route.prefix = *event->prefix4;
    route.source_router_id = event->source_router_id;
    if (event->update != NULL) {
        fsm_fill_route_attrs(&route, event->update, route_weight);
    }
    return libbgp_filter_apply_route(filter, &route, LIBBGP_FILTER_PERMIT) ==
        LIBBGP_FILTER_PERMIT;
}

static const libbgp_pattr_t *fsm_find_mp_reach6_for_prefix(
    const libbgp_update_msg_t *update,
    const libbgp_prefix6_t *prefix)
{
    size_t i;

    if (update == NULL || prefix == NULL) {
        return NULL;
    }
    for (i = 0u; i < update->attr_count; i++) {
        const libbgp_pattr_t *attr = update->attrs[i];
        size_t j;

        if (attr == NULL || attr->type != LIBBGP_PATTR_MP_REACH_IPV6) {
            continue;
        }
        if (attr->data.mp_reach_ipv6.nlri_count != 0u && attr->data.mp_reach_ipv6.nlri == NULL) {
            return NULL;
        }
        for (j = 0u; j < attr->data.mp_reach_ipv6.nlri_count; j++) {
            if (libbgp_prefix6_eq(&attr->data.mp_reach_ipv6.nlri[j], prefix)) {
                return attr;
            }
        }
    }
    return NULL;
}

static bool fsm_out_filter6_permits(
    const libbgp_filter_t *filter,
    const libbgp_event_t *event,
    int32_t route_weight,
    bool is_ibgp)
{
    libbgp_rib6_route_t route;
    const libbgp_pattr_t *mp_reach;
    libbgp_filter_decision_t decision;
    bool route_made = false;
    libbgp_err_t err;

    if (filter == NULL || event == NULL ||
        event->type != LIBBGP_EVENT_ROUTE_ADDED ||
        event->prefix6 == NULL) {
        return true;
    }
    memset(&route, 0, sizeof(route));
    route.prefix = *event->prefix6;
    route.source_router_id = event->source_router_id;
    route.weight = route_weight;
    route.is_ibgp = is_ibgp;
    if (event->update != NULL) {
        mp_reach = fsm_find_mp_reach6_for_prefix(event->update, event->prefix6);
        if (mp_reach != NULL) {
            err = fsm_make_route6(
                event->source_router_id,
                event->update,
                mp_reach,
                event->prefix6,
                route_weight,
                is_ibgp,
                &route);
            if (err != LIBBGP_OK) {
                return false;
            }
            route_made = true;
        } else {
            route.attrs = event->update->attrs;
            route.attr_count = event->update->attr_count;
        }
    }
    decision = libbgp_filter_apply_route6(filter, &route, LIBBGP_FILTER_PERMIT);
    if (route_made) {
        fsm_made_route6_destroy(&route);
    }
    return decision == LIBBGP_FILTER_PERMIT;
}

typedef struct fsm_established_snapshot {
    bool active;
    libbgp_event_bus_t *bus;
    libbgp_out_handler_t *out;
    libbgp_rib4_t *rib4;
    libbgp_rib6_t *rib6;
    const libbgp_filter_t *out_filter4;
    const libbgp_filter_t *out_filter6;
    libbgp_prefix4_t peering_lan4;
    libbgp_prefix6_t peering_lan6;
    uint32_t default_nexthop4;
    uint8_t default_nexthop6[16];
    uint8_t default_nexthop6_linklocal[16];
    uint32_t local_asn;
    uint32_t peer_asn;
    uint32_t peer_bgp_id;
    uint64_t session_generation;
    bool use_4b_asn;
    bool peer_mpbgp_ipv6;
    bool send_ipv4_routes;
    bool send_ipv6_routes;
    bool force_default_nexthop4;
    bool force_default_nexthop6;
    bool ibgp_alter_nexthop;
} fsm_established_snapshot_t;

typedef struct fsm_advertise_rib4_ctx {
    fsm_impl_t *impl;
    fsm_established_snapshot_t snap;
    libbgp_err_t err;
} fsm_advertise_rib4_ctx_t;

typedef struct fsm_advertise_rib6_ctx {
    fsm_impl_t *impl;
    fsm_established_snapshot_t snap;
    libbgp_err_t err;
} fsm_advertise_rib6_ctx_t;

static bool fsm_established_snapshot_current(fsm_impl_t *impl, uint64_t session_generation)
{
    bool current;

    if (impl == NULL) {
        return false;
    }
    bgp_lock(&impl->lock);
    current = fsm_update_session_current(impl, session_generation);
    bgp_unlock(&impl->lock);
    return current;
}

static void fsm_snapshot_established_locked(fsm_impl_t *impl, fsm_established_snapshot_t *snap)
{
    if (snap == NULL) {
        return;
    }
    memset(snap, 0, sizeof(*snap));
    if (impl == NULL || impl->state != LIBBGP_FSM_ESTABLISHED) {
        return;
    }
    snap->active = true;
    snap->bus = impl->bus;
    snap->out = impl->out;
    snap->rib4 = impl->rib4;
    snap->rib6 = impl->rib6;
    snap->out_filter4 = impl->out_filter4;
    snap->out_filter6 = impl->out_filter6;
    snap->peering_lan4 = impl->peering_lan4;
    snap->peering_lan6 = impl->peering_lan6;
    snap->default_nexthop4 = impl->default_nexthop4;
    memcpy(snap->default_nexthop6, impl->default_nexthop6, sizeof(snap->default_nexthop6));
    memcpy(
        snap->default_nexthop6_linklocal,
        impl->default_nexthop6_linklocal,
        sizeof(snap->default_nexthop6_linklocal));
    snap->local_asn = impl->config.local_asn;
    snap->peer_asn = impl->peer_asn;
    snap->peer_bgp_id = impl->peer_bgp_id;
    snap->session_generation = impl->session_generation;
    snap->use_4b_asn = impl->peer_4byte_asn;
    snap->peer_mpbgp_ipv6 = impl->peer_mpbgp_ipv6;
    snap->send_ipv4_routes = impl->send_ipv4_routes;
    snap->send_ipv6_routes = impl->send_ipv6_routes;
    snap->force_default_nexthop4 = impl->force_default_nexthop4;
    snap->force_default_nexthop6 = impl->force_default_nexthop6;
    snap->ibgp_alter_nexthop = impl->ibgp_alter_nexthop;
}

static libbgp_err_t fsm_update_from_route4(const libbgp_rib4_route_t *route, libbgp_update_msg_t *update)
{
    size_t i;
    libbgp_err_t err;

    if (route == NULL || update == NULL || route->prefix.len > 32u) {
        return LIBBGP_ERR_INVALID;
    }
    libbgp_update_init(update);
    for (i = 0u; i < route->attr_count; i++) {
        if (route->attrs[i] == NULL) {
            libbgp_update_destroy(update);
            return LIBBGP_ERR_INVALID;
        }
        if (!fsm_ipv4_route_attr(route->attrs[i])) {
            continue;
        }
        err = libbgp_update_add_attr(update, route->attrs[i]);
        if (err != LIBBGP_OK && err != LIBBGP_ERR_EXISTS) {
            libbgp_update_destroy(update);
            return err;
        }
    }
    err = fsm_update_ensure_origin(update, route->origin);
    if (err == LIBBGP_OK) {
        err = fsm_update_ensure_empty_as_path(update);
    }
    if (err == LIBBGP_OK) {
        err = fsm_update_set_next_hop4(update, route->next_hop);
    }
    if (err == LIBBGP_OK) {
        err = libbgp_update_add_nlri(update, &route->prefix);
    }
    if (err != LIBBGP_OK) {
        libbgp_update_destroy(update);
    }
    return err;
}

static libbgp_err_t fsm_update_add_mp_reach6(
    libbgp_update_msg_t *update,
    const libbgp_prefix6_t *prefix,
    const uint8_t next_hop[16],
    const uint8_t next_hop_linklocal[16])
{
    libbgp_pattr_t *mp;
    libbgp_err_t err;

    if (update == NULL || prefix == NULL || next_hop == NULL) {
        return LIBBGP_ERR_INVALID;
    }
    mp = libbgp_pattr_new(LIBBGP_PATTR_MP_REACH_IPV6);
    if (mp == NULL) {
        return LIBBGP_ERR_NOMEM;
    }
    memcpy(mp->data.mp_reach_ipv6.nexthop, next_hop, 16u);
    mp->data.mp_reach_ipv6.nexthop_len = 16u;
    if (next_hop_linklocal != NULL && !fsm_zero_addr6(next_hop_linklocal)) {
        memcpy(&mp->data.mp_reach_ipv6.nexthop[16], next_hop_linklocal, 16u);
        mp->data.mp_reach_ipv6.nexthop_len = 32u;
    }
    mp->data.mp_reach_ipv6.nlri = (libbgp_prefix6_t *)bgp_calloc(1u, sizeof(*mp->data.mp_reach_ipv6.nlri));
    if (mp->data.mp_reach_ipv6.nlri == NULL) {
        libbgp_pattr_unref(mp);
        return LIBBGP_ERR_NOMEM;
    }
    mp->data.mp_reach_ipv6.nlri[0] = *prefix;
    mp->data.mp_reach_ipv6.nlri_count = 1u;
    err = libbgp_update_add_attr(update, mp);
    libbgp_pattr_unref(mp);
    return err;
}

static libbgp_err_t fsm_update_from_route6(const libbgp_rib6_route_t *route, libbgp_update_msg_t *update)
{
    size_t i;
    libbgp_err_t err;

    if (route == NULL || update == NULL || route->prefix.len > 128u) {
        return LIBBGP_ERR_INVALID;
    }
    libbgp_update_init(update);
    for (i = 0u; i < route->attr_count; i++) {
        if (route->attrs[i] == NULL) {
            libbgp_update_destroy(update);
            return LIBBGP_ERR_INVALID;
        }
        if (!fsm_ipv6_route_attr(route->attrs[i])) {
            continue;
        }
        err = libbgp_update_add_attr(update, route->attrs[i]);
        if (err != LIBBGP_OK && err != LIBBGP_ERR_EXISTS) {
            libbgp_update_destroy(update);
            return err;
        }
    }
    err = fsm_update_ensure_origin(update, route->origin);
    if (err == LIBBGP_OK) {
        err = fsm_update_ensure_empty_as_path(update);
    }
    if (err == LIBBGP_OK) {
        err = fsm_update_add_mp_reach6(update, &route->prefix, route->next_hop, route->next_hop_linklocal);
    }
    if (err != LIBBGP_OK) {
        libbgp_update_destroy(update);
    }
    return err;
}

static bool fsm_advertise_rib4_cb(const libbgp_rib4_route_t *route, void *ctx)
{
    fsm_advertise_rib4_ctx_t *adv = (fsm_advertise_rib4_ctx_t *)ctx;
    libbgp_update_msg_t update;
    bool is_ibgp;

    if (adv == NULL || adv->err != LIBBGP_OK || route == NULL) {
        return false;
    }
    if (!fsm_established_snapshot_current(adv->impl, adv->snap.session_generation)) {
        return false;
    }
    if (route->source_router_id == adv->snap.peer_bgp_id) {
        return true;
    }
    is_ibgp = adv->snap.local_asn == adv->snap.peer_asn;
    if (is_ibgp && route->is_ibgp) {
        return true;
    }
    if (adv->snap.out_filter4 != NULL &&
        libbgp_filter_apply_route(adv->snap.out_filter4, route, LIBBGP_FILTER_PERMIT) !=
            LIBBGP_FILTER_PERMIT) {
        return true;
    }
    adv->err = fsm_update_from_route4(route, &update);
    if (adv->err == LIBBGP_OK) {
        adv->err = fsm_send_prepared_update(
            adv->snap.out,
            &update,
            adv->snap.local_asn,
            adv->snap.use_4b_asn,
            is_ibgp,
            &adv->snap.peering_lan4,
            &adv->snap.peering_lan6,
            adv->snap.default_nexthop4,
            adv->snap.default_nexthop6,
            adv->snap.default_nexthop6_linklocal,
            adv->snap.force_default_nexthop4,
            adv->snap.force_default_nexthop6,
            adv->snap.ibgp_alter_nexthop);
        libbgp_update_destroy(&update);
    }
    return adv->err == LIBBGP_OK &&
        fsm_established_snapshot_current(adv->impl, adv->snap.session_generation);
}

static libbgp_err_t fsm_advertise_existing_rib4(
    fsm_impl_t *impl,
    const fsm_established_snapshot_t *snap)
{
    fsm_advertise_rib4_ctx_t ctx;
    libbgp_err_t err;

    if (snap == NULL || !snap->active || snap->rib4 == NULL || !snap->send_ipv4_routes) {
        return LIBBGP_OK;
    }
    ctx.impl = impl;
    ctx.snap = *snap;
    ctx.err = LIBBGP_OK;
    err = bgp_rib4_foreach_best_route(snap->rib4, fsm_advertise_rib4_cb, &ctx);
    if (err != LIBBGP_OK) {
        return err;
    }
    return ctx.err;
}

static bool fsm_advertise_rib6_cb(const libbgp_rib6_route_t *route, void *ctx)
{
    fsm_advertise_rib6_ctx_t *adv = (fsm_advertise_rib6_ctx_t *)ctx;
    libbgp_update_msg_t update;
    bool is_ibgp;

    if (adv == NULL || adv->err != LIBBGP_OK || route == NULL) {
        return false;
    }
    if (!fsm_established_snapshot_current(adv->impl, adv->snap.session_generation)) {
        return false;
    }
    if (!adv->snap.send_ipv6_routes || route->source_router_id == adv->snap.peer_bgp_id) {
        return true;
    }
    is_ibgp = adv->snap.local_asn == adv->snap.peer_asn;
    if (is_ibgp && route->is_ibgp) {
        return true;
    }
    if (adv->snap.out_filter6 != NULL &&
        libbgp_filter_apply_route6(adv->snap.out_filter6, route, LIBBGP_FILTER_PERMIT) !=
            LIBBGP_FILTER_PERMIT) {
        return true;
    }
    adv->err = fsm_update_from_route6(route, &update);
    if (adv->err == LIBBGP_OK) {
        adv->err = fsm_send_prepared_update(
            adv->snap.out,
            &update,
            adv->snap.local_asn,
            adv->snap.use_4b_asn,
            is_ibgp,
            &adv->snap.peering_lan4,
            &adv->snap.peering_lan6,
            adv->snap.default_nexthop4,
            adv->snap.default_nexthop6,
            adv->snap.default_nexthop6_linklocal,
            adv->snap.force_default_nexthop4,
            adv->snap.force_default_nexthop6,
            adv->snap.ibgp_alter_nexthop);
        libbgp_update_destroy(&update);
    }
    return adv->err == LIBBGP_OK &&
        fsm_established_snapshot_current(adv->impl, adv->snap.session_generation);
}

static libbgp_err_t fsm_advertise_existing_rib6(
    fsm_impl_t *impl,
    const fsm_established_snapshot_t *snap)
{
    fsm_advertise_rib6_ctx_t ctx;
    libbgp_err_t err;

    if (snap == NULL || !snap->active || snap->rib6 == NULL || !snap->send_ipv6_routes) {
        return LIBBGP_OK;
    }
    ctx.impl = impl;
    ctx.snap = *snap;
    ctx.err = LIBBGP_OK;
    err = bgp_rib6_foreach_best_route(snap->rib6, fsm_advertise_rib6_cb, &ctx);
    if (err != LIBBGP_OK) {
        return err;
    }
    return ctx.err;
}

static void fsm_teardown_current_established(fsm_impl_t *impl, uint64_t session_generation)
{
    libbgp_event_bus_t *bus = NULL;
    libbgp_rib4_t *rib4 = NULL;
    libbgp_rib6_t *rib6 = NULL;
    uint32_t peer_bgp_id = 0u;
    fsm_state_change_t changes[FSM_STATE_CHANGE_QUEUE_CAP];
    libbgp_fsm_state_change_fn cb = NULL;
    void *ctx = NULL;
    size_t change_count = 0u;
    bool torn_down = false;

    bgp_lock(&impl->lock);
    if (impl->state == LIBBGP_FSM_ESTABLISHED &&
        impl->session_generation == session_generation) {
        fsm_snapshot_teardown(impl, NULL, &bus, &rib4, &rib6, &peer_bgp_id);
        torn_down = true;
    }
    bgp_unlock(&impl->lock);
    if (torn_down) {
        change_count = fsm_drain_state_changes(impl, &cb, &ctx, changes);
        fsm_discard_peer_routes_publish(bus, rib4, rib6, peer_bgp_id);
        fsm_publish_event(bus, 0u, LIBBGP_EVENT_SESSION_DOWN, 0u, NULL, NULL);
        fsm_dispatch_drained_state_changes(impl, cb, ctx, changes, change_count);
    }
}

static libbgp_err_t fsm_run_established_actions(
    fsm_impl_t *impl,
    const fsm_established_snapshot_t *snap)
{
    bool current = false;
    fsm_state_change_t changes[FSM_STATE_CHANGE_QUEUE_CAP];
    libbgp_fsm_state_change_fn cb = NULL;
    void *ctx = NULL;
    size_t change_count = 0u;
    libbgp_err_t err;

    if (snap == NULL || !snap->active) {
        return LIBBGP_OK;
    }
    err = fsm_advertise_existing_rib4(impl, snap);
    if (err != LIBBGP_OK) {
        fsm_teardown_current_established(impl, snap->session_generation);
        return err;
    }
    if (!fsm_established_snapshot_current(impl, snap->session_generation)) {
        return LIBBGP_OK;
    }
    err = fsm_advertise_existing_rib6(impl, snap);
    if (err != LIBBGP_OK) {
        fsm_teardown_current_established(impl, snap->session_generation);
        return err;
    }
    bgp_lock(&impl->lock);
    current = fsm_update_session_current(impl, snap->session_generation);
    bgp_unlock(&impl->lock);
    if (current) {
        change_count = fsm_drain_state_changes(impl, &cb, &ctx, changes);
        fsm_publish_event(snap->bus, 0u, LIBBGP_EVENT_SESSION_UP, 0u, NULL, NULL);
        fsm_dispatch_drained_state_changes(impl, cb, ctx, changes, change_count);
    }
    return LIBBGP_OK;
}

static void fsm_collision_event_cb(const libbgp_event_t *event, fsm_impl_t *impl)
{
    libbgp_out_handler_t *out = NULL;
    fsm_state_change_t changes[FSM_STATE_CHANGE_QUEUE_CAP];
    libbgp_fsm_state_change_fn cb = NULL;
    void *ctx = NULL;
    size_t change_count = 0u;
    bool *handled;
    bool drop_old = false;

    if (event == NULL || impl == NULL || event->type != LIBBGP_EVENT_COLLISION) {
        return;
    }
    handled = (bool *)event->user_data;
    bgp_lock(&impl->lock);
    if (impl->no_collision_detection) {
        bgp_unlock(&impl->lock);
        return;
    }
    if (impl->state == LIBBGP_FSM_OPEN_CONFIRM &&
        impl->peer_bgp_id == event->source_router_id) {
        if (handled != NULL) {
            *handled = true;
        }
        drop_old = fsm_router_id_cmp(impl->config.local_bgp_id, event->source_router_id) <= 0;
        if (drop_old) {
            fsm_snapshot_teardown(impl, &out, NULL, NULL, NULL, NULL);
        }
    }
    bgp_unlock(&impl->lock);
    if (drop_old) {
        change_count = fsm_drain_state_changes(impl, &cb, &ctx, changes);
        (void)fsm_send_notification(out, FSM_NOTIFY_CEASE, FSM_CEASE_ERR_COLLISION);
        fsm_dispatch_drained_state_changes(impl, cb, ctx, changes, change_count);
    }
}

static bool fsm_collision_reject_new_locked(
    fsm_impl_t *impl,
    uint32_t peer_bgp_id,
    libbgp_out_handler_t **out)
{
    libbgp_event_bus_t *bus;
    libbgp_event_t event;
    uint64_t publisher_id;
    uint32_t local_bgp_id;
    bool handled = false;

    if (out != NULL) {
        *out = NULL;
    }
    if (impl == NULL || impl->bus == NULL || impl->no_collision_detection) {
        return false;
    }
    bus = impl->bus;
    publisher_id = impl->collision_sub_id;
    local_bgp_id = impl->config.local_bgp_id;
    memset(&event, 0, sizeof(event));
    event.type = LIBBGP_EVENT_COLLISION;
    event.source_router_id = peer_bgp_id;
    event.user_data = &handled;
    bgp_unlock(&impl->lock);
    (void)libbgp_event_bus_publish_from(bus, publisher_id, &event);
    bgp_lock(&impl->lock);
    if (handled && fsm_router_id_cmp(local_bgp_id, peer_bgp_id) > 0) {
        fsm_snapshot_teardown(impl, out, NULL, NULL, NULL, NULL);
        return true;
    }
    return false;
}

static void fsm_route_event_cb(const libbgp_event_t *event, void *ctx)
{
    fsm_impl_t *impl = (fsm_impl_t *)ctx;
    libbgp_out_handler_t *out = NULL;
    const libbgp_filter_t *out_filter4 = NULL;
    const libbgp_filter_t *out_filter6 = NULL;
    uint32_t local_asn = 0u;
    uint32_t peer_bgp_id = 0u;
    uint32_t peer_asn = 0u;
    uint64_t session_generation = 0u;
    int32_t route_weight = 0;
    bool use_4b_asn = false;
    libbgp_prefix4_t peering_lan4;
    libbgp_prefix6_t peering_lan6;
    uint32_t default_nexthop4 = 0u;
    uint8_t default_nexthop6[16];
    uint8_t default_nexthop6_linklocal[16];
    bool force_default_nexthop4 = false;
    bool force_default_nexthop6 = false;
    bool ibgp_alter_nexthop = false;
    bool send_ipv4_routes = false;
    bool send_ipv6_routes = false;
    bool should_send = false;
    libbgp_err_t err;

    memset(&peering_lan4, 0, sizeof(peering_lan4));
    memset(&peering_lan6, 0, sizeof(peering_lan6));
    memset(default_nexthop6, 0, sizeof(default_nexthop6));
    memset(default_nexthop6_linklocal, 0, sizeof(default_nexthop6_linklocal));
    if (impl == NULL || event == NULL) {
        return;
    }
    if (event->type == LIBBGP_EVENT_COLLISION) {
        fsm_collision_event_cb(event, impl);
        return;
    }
    if (event->type != LIBBGP_EVENT_ROUTE_ADDED &&
        event->type != LIBBGP_EVENT_ROUTE_WITHDRAWN) {
        return;
    }

    bgp_lock(&impl->lock);
    if (impl->state == LIBBGP_FSM_ESTABLISHED) {
        peer_bgp_id = impl->peer_bgp_id;
        if (event->source_router_id == 0u || event->source_router_id != peer_bgp_id) {
            out = impl->out;
            out_filter4 = impl->out_filter4;
            out_filter6 = impl->out_filter6;
            local_asn = impl->config.local_asn;
            peer_asn = impl->peer_asn;
            route_weight = impl->route_weight;
            use_4b_asn = impl->peer_4byte_asn;
            peering_lan4 = impl->peering_lan4;
            peering_lan6 = impl->peering_lan6;
            default_nexthop4 = impl->default_nexthop4;
            memcpy(default_nexthop6, impl->default_nexthop6, sizeof(default_nexthop6));
            memcpy(
                default_nexthop6_linklocal,
                impl->default_nexthop6_linklocal,
                sizeof(default_nexthop6_linklocal));
            force_default_nexthop4 = impl->force_default_nexthop4;
            force_default_nexthop6 = impl->force_default_nexthop6;
            ibgp_alter_nexthop = impl->ibgp_alter_nexthop;
            send_ipv4_routes = impl->send_ipv4_routes;
            send_ipv6_routes = impl->send_ipv6_routes;
            session_generation = impl->session_generation;
            should_send = true;
        }
    }
    bgp_unlock(&impl->lock);

    if (!should_send) {
        return;
    }
    if (event->prefix4 != NULL && !send_ipv4_routes) {
        return;
    }
    if (event->prefix6 != NULL && !send_ipv6_routes) {
        return;
    }
    if (!fsm_out_filter4_permits(out_filter4, event, route_weight)) {
        return;
    }
    if (!fsm_out_filter6_permits(out_filter6, event, route_weight, peer_asn == local_asn)) {
        return;
    }
    err = fsm_send_route_event_update(
        out,
        event,
        local_asn,
        use_4b_asn,
        peer_asn == local_asn,
        &peering_lan4,
        &peering_lan6,
        default_nexthop4,
        default_nexthop6,
        default_nexthop6_linklocal,
        force_default_nexthop4,
        force_default_nexthop6,
        ibgp_alter_nexthop,
        route_weight);
    if (err != LIBBGP_OK) {
        fsm_teardown_current_established(impl, session_generation);
    }
}

libbgp_err_t libbgp_fsm_init(libbgp_fsm_t *fsm, const struct libbgp_fsm_config *config)
{
    fsm_impl_t *impl;
    libbgp_err_t err;

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
    impl->negotiated_hold_time = 0u;
    err = libbgp_rib4_init(&impl->internal_rib4);
    if (err != LIBBGP_OK) {
        bgp_free(impl);
        return err;
    }
    impl->internal_rib4_initialized = true;
    err = libbgp_rib6_init(&impl->internal_rib6);
    if (err != LIBBGP_OK) {
        libbgp_rib4_destroy(&impl->internal_rib4);
        bgp_free(impl);
        return err;
    }
    impl->internal_rib6_initialized = true;
    impl->rib4 = &impl->internal_rib4;
    impl->rib6 = &impl->internal_rib6;
    impl->refcount = 1u;
    bgp_lock_init(&impl->lock);
#ifdef BGP_THREADSAFE
    pthread_cond_init(&impl->state_change_cond, NULL);
#endif
    fsm->impl = impl;
    return LIBBGP_OK;
}

void libbgp_fsm_destroy(libbgp_fsm_t *fsm)
{
    fsm_impl_t *impl;
    libbgp_event_bus_t *attached_bus = NULL;
    libbgp_rib4_t *rib4 = NULL;
    libbgp_rib6_t *rib6 = NULL;
    uint32_t peer_bgp_id = 0u;
    uint64_t route_added_sub_id = 0u;
    uint64_t route_withdrawn_sub_id = 0u;
    uint64_t collision_sub_id = 0u;
    bool discard_routes = false;

    fsm_handle_global_lock();
    impl = fsm_impl_get(fsm);
    if (impl != NULL) {
        fsm->impl = NULL;
    }
    fsm_handle_global_unlock();
    if (impl == NULL) {
        return;
    }
    bgp_lock(&impl->lock);
    fsm_state_change_wait(impl);
    impl->state_change_cb = NULL;
    impl->state_change_ctx = NULL;
    impl->state_change_count = 0u;
    attached_bus = impl->bus;
    route_added_sub_id = impl->route_added_sub_id;
    route_withdrawn_sub_id = impl->route_withdrawn_sub_id;
    collision_sub_id = impl->collision_sub_id;
    impl->bus = NULL;
    impl->route_added_sub_id = 0u;
    impl->route_withdrawn_sub_id = 0u;
    impl->collision_sub_id = 0u;
    impl->destroy_started = true;
    if (impl->state == LIBBGP_FSM_ESTABLISHED && impl->peer_bgp_id != 0u) {
        rib4 = impl->rib4;
        rib6 = impl->rib6;
        peer_bgp_id = impl->peer_bgp_id;
        discard_routes = true;
    }
    bgp_unlock(&impl->lock);
    fsm_unsubscribe_route_events(attached_bus, route_added_sub_id, route_withdrawn_sub_id, collision_sub_id);
    if (discard_routes) {
        fsm_discard_peer_routes(rib4, rib6, peer_bgp_id);
    }
    fsm_impl_release_free(impl);
}

libbgp_fsm_state_t libbgp_fsm_state(const libbgp_fsm_t *fsm)
{
    fsm_impl_t *impl = fsm_handle_acquire((libbgp_fsm_t *)fsm);
    libbgp_fsm_state_t state;

    if (impl == NULL) {
        return LIBBGP_FSM_IDLE;
    }
    bgp_lock(&impl->lock);
    state = impl->state;
    bgp_unlock(&impl->lock);
    if (fsm_impl_release(impl)) {
        fsm_impl_free(impl);
    }
    return state;
}

void libbgp_fsm_set_rib4(libbgp_fsm_t *fsm, libbgp_rib4_t *rib4)
{
    fsm_impl_t *impl = fsm_handle_acquire(fsm);

    if (impl == NULL) {
        return;
    }
    bgp_lock(&impl->lock);
    impl->rib4 = rib4 == NULL ? &impl->internal_rib4 : rib4;
    bgp_unlock(&impl->lock);
    fsm_impl_release_free(impl);
}

void libbgp_fsm_set_rib6(libbgp_fsm_t *fsm, libbgp_rib6_t *rib6)
{
    fsm_impl_t *impl = fsm_handle_acquire(fsm);

    if (impl == NULL) {
        return;
    }
    bgp_lock(&impl->lock);
    impl->rib6 = rib6 == NULL ? &impl->internal_rib6 : rib6;
    bgp_unlock(&impl->lock);
    fsm_impl_release_free(impl);
}

libbgp_rib4_t *libbgp_fsm_get_rib4(libbgp_fsm_t *fsm)
{
    fsm_impl_t *impl = fsm_handle_acquire(fsm);
    libbgp_rib4_t *rib4;

    if (impl == NULL) {
        return NULL;
    }
    bgp_lock(&impl->lock);
    rib4 = impl->rib4;
    bgp_unlock(&impl->lock);
    fsm_impl_release_free(impl);
    return rib4;
}

libbgp_rib6_t *libbgp_fsm_get_rib6(libbgp_fsm_t *fsm)
{
    fsm_impl_t *impl = fsm_handle_acquire(fsm);
    libbgp_rib6_t *rib6;

    if (impl == NULL) {
        return NULL;
    }
    bgp_lock(&impl->lock);
    rib6 = impl->rib6;
    bgp_unlock(&impl->lock);
    fsm_impl_release_free(impl);
    return rib6;
}

void libbgp_fsm_set_event_bus(libbgp_fsm_t *fsm, libbgp_event_bus_t *bus)
{
    fsm_impl_t *impl = fsm_handle_acquire(fsm);
    libbgp_event_bus_t *old_bus;
    uint64_t old_route_added_sub_id;
    uint64_t old_route_withdrawn_sub_id;
    uint64_t old_collision_sub_id;
    uint64_t route_added_sub_id = 0u;
    uint64_t route_withdrawn_sub_id = 0u;
    uint64_t collision_sub_id = 0u;
    libbgp_err_t add_err = LIBBGP_OK;
    libbgp_err_t withdraw_err = LIBBGP_OK;
    libbgp_err_t collision_err = LIBBGP_OK;

    if (impl == NULL) {
        return;
    }
    bgp_lock(&impl->lock);
    old_bus = impl->bus;
    old_route_added_sub_id = impl->route_added_sub_id;
    old_route_withdrawn_sub_id = impl->route_withdrawn_sub_id;
    old_collision_sub_id = impl->collision_sub_id;
    impl->bus = NULL;
    impl->route_added_sub_id = 0u;
    impl->route_withdrawn_sub_id = 0u;
    impl->collision_sub_id = 0u;
    bgp_unlock(&impl->lock);

    fsm_unsubscribe_route_events(
        old_bus,
        old_route_added_sub_id,
        old_route_withdrawn_sub_id,
        old_collision_sub_id);
    if (bus != NULL) {
        add_err = bgp_event_bus_subscribe_retained(
            bus,
            LIBBGP_EVENT_ROUTE_ADDED,
            fsm_route_event_cb,
            impl,
            fsm_event_ctx_retain,
            fsm_event_ctx_release,
            &route_added_sub_id);
        if (add_err == LIBBGP_OK) {
            withdraw_err = bgp_event_bus_subscribe_retained(
                bus,
                LIBBGP_EVENT_ROUTE_WITHDRAWN,
                fsm_route_event_cb,
                impl,
                fsm_event_ctx_retain,
                fsm_event_ctx_release,
                &route_withdrawn_sub_id);
        }
        if (withdraw_err == LIBBGP_OK) {
            collision_err = bgp_event_bus_subscribe_retained(
                bus,
                LIBBGP_EVENT_COLLISION,
                fsm_route_event_cb,
                impl,
                fsm_event_ctx_retain,
                fsm_event_ctx_release,
                &collision_sub_id);
        }
        if (add_err != LIBBGP_OK || withdraw_err != LIBBGP_OK || collision_err != LIBBGP_OK) {
            fsm_unsubscribe_route_events(bus, route_added_sub_id, route_withdrawn_sub_id, collision_sub_id);
            route_added_sub_id = 0u;
            route_withdrawn_sub_id = 0u;
            collision_sub_id = 0u;
        }
    }

    bgp_lock(&impl->lock);
    if (impl->destroy_started) {
        bgp_unlock(&impl->lock);
        fsm_unsubscribe_route_events(bus, route_added_sub_id, route_withdrawn_sub_id, collision_sub_id);
        fsm_impl_release_free(impl);
        return;
    }
    impl->bus = bus;
    impl->route_added_sub_id = route_added_sub_id;
    impl->route_withdrawn_sub_id = route_withdrawn_sub_id;
    impl->collision_sub_id = collision_sub_id;
    bgp_unlock(&impl->lock);
    fsm_impl_release_free(impl);
}

void libbgp_fsm_set_out_handler(libbgp_fsm_t *fsm, libbgp_out_handler_t *out)
{
    fsm_impl_t *impl = fsm_handle_acquire(fsm);

    if (impl == NULL) {
        return;
    }
    bgp_lock(&impl->lock);
    impl->out = out;
    bgp_unlock(&impl->lock);
    fsm_impl_release_free(impl);
}

void libbgp_fsm_set_state_change_cb(
    libbgp_fsm_t *fsm,
    libbgp_fsm_state_change_fn cb,
    void *ctx)
{
    fsm_impl_t *impl = fsm_handle_acquire(fsm);

    if (impl == NULL) {
        return;
    }
    bgp_lock(&impl->lock);
    fsm_state_change_wait(impl);
    impl->state_change_cb = cb;
    impl->state_change_ctx = ctx;
    bgp_unlock(&impl->lock);
    fsm_impl_release_free(impl);
}

void libbgp_fsm_set_expected_peer_asn(libbgp_fsm_t *fsm, uint32_t peer_asn)
{
    fsm_impl_t *impl = fsm_handle_acquire(fsm);

    if (impl == NULL) {
        return;
    }
    bgp_lock(&impl->lock);
    impl->expected_peer_asn = peer_asn;
    bgp_unlock(&impl->lock);
    fsm_impl_release_free(impl);
}

void libbgp_fsm_set_mpbgp_ipv4(libbgp_fsm_t *fsm, bool enabled)
{
    fsm_impl_t *impl = fsm_handle_acquire(fsm);

    if (impl == NULL) {
        return;
    }
    bgp_lock(&impl->lock);
    impl->enable_mpbgp_ipv4 = enabled;
    bgp_unlock(&impl->lock);
    fsm_impl_release_free(impl);
}

void libbgp_fsm_set_no_collision_detection(libbgp_fsm_t *fsm, bool disabled)
{
    fsm_impl_t *impl = fsm_handle_acquire(fsm);

    if (impl == NULL) {
        return;
    }
    bgp_lock(&impl->lock);
    impl->no_collision_detection = disabled;
    bgp_unlock(&impl->lock);
    fsm_impl_release_free(impl);
}

void libbgp_fsm_set_allow_local_as(libbgp_fsm_t *fsm, uint8_t allow_count)
{
    fsm_impl_t *impl = fsm_handle_acquire(fsm);

    if (impl == NULL) {
        return;
    }
    bgp_lock(&impl->lock);
    impl->allow_local_as = allow_count;
    bgp_unlock(&impl->lock);
    fsm_impl_release_free(impl);
}

void libbgp_fsm_set_route_weight(libbgp_fsm_t *fsm, int32_t weight)
{
    fsm_impl_t *impl = fsm_handle_acquire(fsm);

    if (impl == NULL) {
        return;
    }
    bgp_lock(&impl->lock);
    impl->route_weight = weight;
    bgp_unlock(&impl->lock);
    fsm_impl_release_free(impl);
}

void libbgp_fsm_set_in_filter4(libbgp_fsm_t *fsm, const libbgp_filter_t *filter)
{
    fsm_impl_t *impl = fsm_handle_acquire(fsm);

    if (impl == NULL) {
        return;
    }
    bgp_lock(&impl->lock);
    impl->in_filter4 = filter;
    bgp_unlock(&impl->lock);
    fsm_impl_release_free(impl);
}

void libbgp_fsm_set_out_filter4(libbgp_fsm_t *fsm, const libbgp_filter_t *filter)
{
    fsm_impl_t *impl = fsm_handle_acquire(fsm);

    if (impl == NULL) {
        return;
    }
    bgp_lock(&impl->lock);
    impl->out_filter4 = filter;
    bgp_unlock(&impl->lock);
    fsm_impl_release_free(impl);
}

void libbgp_fsm_set_in_filter6(libbgp_fsm_t *fsm, const libbgp_filter_t *filter)
{
    fsm_impl_t *impl = fsm_handle_acquire(fsm);

    if (impl == NULL) {
        return;
    }
    bgp_lock(&impl->lock);
    impl->in_filter6 = filter;
    bgp_unlock(&impl->lock);
    fsm_impl_release_free(impl);
}

void libbgp_fsm_set_out_filter6(libbgp_fsm_t *fsm, const libbgp_filter_t *filter)
{
    fsm_impl_t *impl = fsm_handle_acquire(fsm);

    if (impl == NULL) {
        return;
    }
    bgp_lock(&impl->lock);
    impl->out_filter6 = filter;
    bgp_unlock(&impl->lock);
    fsm_impl_release_free(impl);
}

void libbgp_fsm_set_peering_lan4(libbgp_fsm_t *fsm, const libbgp_prefix4_t *prefix)
{
    fsm_impl_t *impl = fsm_handle_acquire(fsm);

    if (impl == NULL) {
        return;
    }
    bgp_lock(&impl->lock);
    if (prefix == NULL) {
        memset(&impl->peering_lan4, 0, sizeof(impl->peering_lan4));
    } else {
        impl->peering_lan4 = *prefix;
    }
    bgp_unlock(&impl->lock);
    fsm_impl_release_free(impl);
}

void libbgp_fsm_set_no_nexthop_check4(libbgp_fsm_t *fsm, bool disabled)
{
    fsm_impl_t *impl = fsm_handle_acquire(fsm);

    if (impl == NULL) {
        return;
    }
    bgp_lock(&impl->lock);
    impl->no_nexthop_check4 = disabled;
    bgp_unlock(&impl->lock);
    fsm_impl_release_free(impl);
}

void libbgp_fsm_set_default_nexthop4(libbgp_fsm_t *fsm, uint32_t next_hop)
{
    fsm_impl_t *impl = fsm_handle_acquire(fsm);

    if (impl == NULL) {
        return;
    }
    bgp_lock(&impl->lock);
    impl->default_nexthop4 = next_hop;
    bgp_unlock(&impl->lock);
    fsm_impl_release_free(impl);
}

void libbgp_fsm_set_force_default_nexthop4(libbgp_fsm_t *fsm, bool forced)
{
    fsm_impl_t *impl = fsm_handle_acquire(fsm);

    if (impl == NULL) {
        return;
    }
    bgp_lock(&impl->lock);
    impl->force_default_nexthop4 = forced;
    bgp_unlock(&impl->lock);
    fsm_impl_release_free(impl);
}

void libbgp_fsm_set_peering_lan6(libbgp_fsm_t *fsm, const libbgp_prefix6_t *prefix)
{
    fsm_impl_t *impl = fsm_handle_acquire(fsm);

    if (impl == NULL) {
        return;
    }
    bgp_lock(&impl->lock);
    if (prefix == NULL) {
        memset(&impl->peering_lan6, 0, sizeof(impl->peering_lan6));
    } else {
        impl->peering_lan6 = *prefix;
    }
    bgp_unlock(&impl->lock);
    fsm_impl_release_free(impl);
}

void libbgp_fsm_set_no_nexthop_check6(libbgp_fsm_t *fsm, bool disabled)
{
    fsm_impl_t *impl = fsm_handle_acquire(fsm);

    if (impl == NULL) {
        return;
    }
    bgp_lock(&impl->lock);
    impl->no_nexthop_check6 = disabled;
    bgp_unlock(&impl->lock);
    fsm_impl_release_free(impl);
}

void libbgp_fsm_set_default_nexthop6(libbgp_fsm_t *fsm, const uint8_t next_hop[16])
{
    fsm_impl_t *impl = fsm_handle_acquire(fsm);

    if (impl == NULL) {
        return;
    }
    bgp_lock(&impl->lock);
    if (next_hop == NULL) {
        memset(impl->default_nexthop6, 0, sizeof(impl->default_nexthop6));
    } else {
        memcpy(impl->default_nexthop6, next_hop, sizeof(impl->default_nexthop6));
    }
    bgp_unlock(&impl->lock);
    fsm_impl_release_free(impl);
}

void libbgp_fsm_set_default_nexthop6_linklocal(libbgp_fsm_t *fsm, const uint8_t next_hop[16])
{
    fsm_impl_t *impl = fsm_handle_acquire(fsm);

    if (impl == NULL) {
        return;
    }
    bgp_lock(&impl->lock);
    if (next_hop == NULL) {
        memset(impl->default_nexthop6_linklocal, 0, sizeof(impl->default_nexthop6_linklocal));
    } else {
        memcpy(
            impl->default_nexthop6_linklocal,
            next_hop,
            sizeof(impl->default_nexthop6_linklocal));
    }
    bgp_unlock(&impl->lock);
    fsm_impl_release_free(impl);
}

void libbgp_fsm_set_force_default_nexthop6(libbgp_fsm_t *fsm, bool forced)
{
    fsm_impl_t *impl = fsm_handle_acquire(fsm);

    if (impl == NULL) {
        return;
    }
    bgp_lock(&impl->lock);
    impl->force_default_nexthop6 = forced;
    bgp_unlock(&impl->lock);
    fsm_impl_release_free(impl);
}

void libbgp_fsm_set_ibgp_alter_nexthop(libbgp_fsm_t *fsm, bool enabled)
{
    fsm_impl_t *impl = fsm_handle_acquire(fsm);

    if (impl == NULL) {
        return;
    }
    bgp_lock(&impl->lock);
    impl->ibgp_alter_nexthop = enabled;
    bgp_unlock(&impl->lock);
    fsm_impl_release_free(impl);
}

static libbgp_err_t fsm_enter_pre_open_state(libbgp_fsm_t *fsm, libbgp_fsm_state_t state)
{
    fsm_impl_t *impl = fsm_handle_acquire(fsm);

    if (impl == NULL) {
        return LIBBGP_ERR_INVALID;
    }
    bgp_lock(&impl->lock);
    if (!fsm_state_pre_open(impl->state)) {
        bgp_unlock(&impl->lock);
        fsm_impl_release_free(impl);
        return LIBBGP_ERR_INVALID;
    }
    fsm_set_state(impl, state);
    impl->peer_asn = 0u;
    impl->peer_bgp_id = 0u;
    impl->negotiated_hold_time = 0u;
    impl->peer_mpbgp_ipv6 = false;
    impl->peer_4byte_asn = false;
    impl->peer_can_send_as4_path = false;
    impl->send_ipv4_routes = false;
    impl->send_ipv6_routes = false;
    impl->clock_initialized = false;
    impl->local_keepalive_send_pending = false;
    impl->local_keepalive_pending = false;
    impl->passive_open_send_pending = false;
    impl->passive_keepalive_pending = false;
    impl->session_generation++;
    bgp_unlock(&impl->lock);
    fsm_dispatch_state_changes_impl(impl);
    fsm_impl_release_free(impl);
    return LIBBGP_OK;
}

libbgp_err_t libbgp_fsm_enter_connect(libbgp_fsm_t *fsm)
{
    return fsm_enter_pre_open_state(fsm, LIBBGP_FSM_CONNECT);
}

libbgp_err_t libbgp_fsm_enter_active(libbgp_fsm_t *fsm)
{
    return fsm_enter_pre_open_state(fsm, LIBBGP_FSM_ACTIVE);
}

libbgp_err_t libbgp_fsm_start(libbgp_fsm_t *fsm)
{
    fsm_impl_t *impl = fsm_handle_acquire(fsm);
    struct libbgp_fsm_config config;
    libbgp_out_handler_t *out;
    libbgp_fsm_state_t start_state;
    uint64_t session_generation;
    bool enable_mpbgp_ipv4;
    libbgp_err_t err;

    if (impl == NULL) {
        return LIBBGP_ERR_INVALID;
    }
    bgp_lock(&impl->lock);
    if (!fsm_local_open_config_valid(&impl->config)) {
        bgp_unlock(&impl->lock);
        fsm_impl_release_free(impl);
        return LIBBGP_ERR_INVALID;
    }
    if (impl->state != LIBBGP_FSM_IDLE &&
        impl->state != LIBBGP_FSM_ACTIVE &&
        impl->state != LIBBGP_FSM_CONNECT) {
        bgp_unlock(&impl->lock);
        fsm_impl_release_free(impl);
        return LIBBGP_OK;
    }
    start_state = impl->state;
    fsm_set_state(impl, LIBBGP_FSM_OPEN_SENT);
    impl->session_generation++;
    session_generation = impl->session_generation;
    impl->peer_asn = 0u;
    impl->peer_bgp_id = 0u;
    impl->negotiated_hold_time = 0u;
    impl->peer_mpbgp_ipv6 = false;
    impl->peer_4byte_asn = false;
    impl->peer_can_send_as4_path = false;
    impl->send_ipv4_routes = false;
    impl->send_ipv6_routes = false;
    impl->clock_initialized = false;
    impl->local_keepalive_send_pending = false;
    impl->local_keepalive_pending = false;
    impl->passive_open_send_pending = false;
    impl->passive_keepalive_pending = false;
    config = impl->config;
    enable_mpbgp_ipv4 = impl->enable_mpbgp_ipv4;
    out = impl->out;
    bgp_unlock(&impl->lock);

    err = fsm_send_open(out, &config, enable_mpbgp_ipv4);
    bgp_lock(&impl->lock);
    if (err != LIBBGP_OK && impl->state == LIBBGP_FSM_OPEN_SENT &&
        impl->session_generation == session_generation) {
        fsm_set_state(impl, start_state);
        impl->local_keepalive_send_pending = false;
        impl->local_keepalive_pending = false;
        impl->passive_open_send_pending = false;
        impl->passive_keepalive_pending = false;
        impl->session_generation++;
    }
    bgp_unlock(&impl->lock);
    fsm_dispatch_state_changes_impl(impl);
    fsm_impl_release_free(impl);
    return err;
}

static libbgp_err_t fsm_reset_common(libbgp_fsm_t *fsm, bool send_notify, uint8_t cease_subcode)
{
    fsm_impl_t *impl = fsm_handle_acquire(fsm);
    libbgp_out_handler_t *out;
    libbgp_event_bus_t *bus = NULL;
    libbgp_rib4_t *rib4 = NULL;
    libbgp_rib6_t *rib6 = NULL;
    uint32_t peer_bgp_id = 0u;
    fsm_state_change_t changes[FSM_STATE_CHANGE_QUEUE_CAP];
    libbgp_fsm_state_change_fn cb = NULL;
    void *ctx = NULL;
    size_t change_count = 0u;
    bool notify;
    bool was_established;
    bool publish_routes_before_notify;
    libbgp_err_t err;

    if (impl == NULL) {
        return LIBBGP_ERR_INVALID;
    }
    bgp_lock(&impl->lock);
    notify = send_notify && impl->state != LIBBGP_FSM_IDLE;
    was_established = impl->state == LIBBGP_FSM_ESTABLISHED;
    fsm_snapshot_teardown(impl, &out, &bus, &rib4, &rib6, &peer_bgp_id);
    bgp_unlock(&impl->lock);
    change_count = fsm_drain_state_changes(impl, &cb, &ctx, changes);

    publish_routes_before_notify = was_established && notify &&
        cease_subcode == FSM_CEASE_ERR_ADMIN_SHUTDOWN;
    if (publish_routes_before_notify) {
        fsm_discard_peer_routes_publish(bus, rib4, rib6, peer_bgp_id);
    }
    err = notify ? fsm_send_notification(out, FSM_NOTIFY_CEASE, cease_subcode) : LIBBGP_OK;
    if (was_established) {
        if (!publish_routes_before_notify) {
            fsm_discard_peer_routes_publish(bus, rib4, rib6, peer_bgp_id);
        }
        fsm_publish_event(bus, 0u, LIBBGP_EVENT_SESSION_DOWN, 0u, NULL, NULL);
    }
    fsm_dispatch_drained_state_changes(impl, cb, ctx, changes, change_count);
    fsm_impl_release_free(impl);
    return err;
}

libbgp_err_t libbgp_fsm_stop(libbgp_fsm_t *fsm)
{
    return fsm_reset_common(fsm, true, FSM_CEASE_ERR_ADMIN_SHUTDOWN);
}

libbgp_err_t libbgp_fsm_reset_soft(libbgp_fsm_t *fsm)
{
    return fsm_reset_common(fsm, true, FSM_CEASE_ERR_ADMIN_RESET);
}

libbgp_err_t libbgp_fsm_reset_hard(libbgp_fsm_t *fsm)
{
    return fsm_reset_common(fsm, false, 0u);
}

static void fsm_rollback_failed_local_keepalive(fsm_impl_t *impl, uint64_t session_generation)
{
    bool same_attempt = impl->state == LIBBGP_FSM_OPEN_CONFIRM &&
        impl->session_generation == session_generation;
    bool reentrant_established = impl->state == LIBBGP_FSM_ESTABLISHED &&
        impl->session_generation == session_generation + 1u;

    if (!same_attempt && !reentrant_established) {
        return;
    }
    fsm_set_state(impl, LIBBGP_FSM_IDLE);
    impl->peer_asn = 0u;
    impl->peer_bgp_id = 0u;
    impl->negotiated_hold_time = 0u;
    impl->peer_mpbgp_ipv6 = false;
    impl->peer_4byte_asn = false;
    impl->peer_can_send_as4_path = false;
    impl->send_ipv4_routes = false;
    impl->send_ipv6_routes = false;
    impl->clock_initialized = false;
    impl->local_keepalive_send_pending = false;
    impl->local_keepalive_pending = false;
    impl->passive_open_send_pending = false;
    impl->passive_keepalive_pending = false;
    impl->session_generation++;
}

static bool fsm_establish_pending_keepalive(fsm_impl_t *impl, uint64_t session_generation)
{
    if (impl->state != LIBBGP_FSM_OPEN_CONFIRM ||
        impl->session_generation != session_generation ||
        !impl->local_keepalive_pending) {
        return false;
    }
    fsm_set_state(impl, LIBBGP_FSM_ESTABLISHED);
    impl->session_generation++;
    impl->local_keepalive_send_pending = false;
    impl->local_keepalive_pending = false;
    impl->passive_open_send_pending = false;
    impl->passive_keepalive_pending = false;
    return true;
}

static libbgp_err_t fsm_on_open_sent(fsm_impl_t *impl, const libbgp_packet_t *pkt)
{
    libbgp_out_handler_t *out;
    fsm_established_snapshot_t established;
    uint16_t local_hold;
    uint16_t peer_hold;
    uint32_t peer_asn;
    uint32_t peer_bgp_id;
    uint16_t negotiated_hold_time;
    bool send_ipv4_routes;
    bool send_ipv6_routes;
    uint64_t session_generation;
    libbgp_err_t err;

    if (pkt->type != LIBBGP_PACKET_OPEN) {
        fsm_snapshot_teardown(impl, &out, NULL, NULL, NULL, NULL);
        bgp_unlock(&impl->lock);
        (void)fsm_send_notification(out, FSM_NOTIFY_FSM_ERROR, FSM_ERR_OPEN_SENT);
        return LIBBGP_ERR_BAD_TYPE;
    }
    if (pkt->data.open.version != 4u) {
        fsm_snapshot_teardown(impl, &out, NULL, NULL, NULL, NULL);
        bgp_unlock(&impl->lock);
        (void)fsm_send_notification(out, FSM_NOTIFY_OPEN_MESSAGE_ERROR, FSM_OPEN_ERR_UNSUPPORTED_VERSION);
        return LIBBGP_ERR_BAD_LEN;
    }
    if (pkt->data.open.hold_time != 0u && pkt->data.open.hold_time < 3u) {
        fsm_snapshot_teardown(impl, &out, NULL, NULL, NULL, NULL);
        bgp_unlock(&impl->lock);
        (void)fsm_send_notification(out, FSM_NOTIFY_OPEN_MESSAGE_ERROR, FSM_OPEN_ERR_UNACCEPTABLE_HOLD_TIME);
        return LIBBGP_ERR_INVALID;
    }
    if (!fsm_valid_peer_bgp_id(pkt->data.open.bgp_id, impl->config.local_bgp_id)) {
        fsm_snapshot_teardown(impl, &out, NULL, NULL, NULL, NULL);
        bgp_unlock(&impl->lock);
        (void)fsm_send_notification(out, FSM_NOTIFY_OPEN_MESSAGE_ERROR, FSM_OPEN_ERR_BAD_BGP_ID);
        return LIBBGP_ERR_INVALID;
    }
    if (!fsm_local_open_config_valid(&impl->config)) {
        fsm_snapshot_teardown(impl, NULL, NULL, NULL, NULL, NULL);
        bgp_unlock(&impl->lock);
        return LIBBGP_ERR_INVALID;
    }
    local_hold = impl->config.hold_time;
    peer_hold = pkt->data.open.hold_time;
    peer_asn = libbgp_open_get_4b_asn(&pkt->data.open);
    if (impl->expected_peer_asn != 0u && peer_asn != impl->expected_peer_asn) {
        fsm_snapshot_teardown(impl, &out, NULL, NULL, NULL, NULL);
        bgp_unlock(&impl->lock);
        (void)fsm_send_notification(out, FSM_NOTIFY_OPEN_MESSAGE_ERROR, FSM_OPEN_ERR_BAD_PEER_AS);
        return LIBBGP_ERR_INVALID;
    }
    peer_bgp_id = pkt->data.open.bgp_id;
    fsm_negotiate_route_families(impl, &pkt->data.open, &send_ipv4_routes, &send_ipv6_routes);
    memset(&established, 0, sizeof(established));
    if (fsm_collision_reject_new_locked(impl, peer_bgp_id, &out)) {
        bgp_unlock(&impl->lock);
        (void)fsm_send_notification(out, FSM_NOTIFY_CEASE, FSM_CEASE_ERR_COLLISION);
        return LIBBGP_OK;
    }
    negotiated_hold_time = (local_hold == 0u || peer_hold == 0u) ? 0u :
        (local_hold < peer_hold ? local_hold : peer_hold);
    impl->peer_asn = peer_asn;
    impl->peer_bgp_id = peer_bgp_id;
    impl->negotiated_hold_time = negotiated_hold_time;
    impl->peer_mpbgp_ipv6 = send_ipv6_routes;
    impl->peer_4byte_asn = impl->config.enable_4byte_asn && libbgp_open_has_4b_asn(&pkt->data.open);
    impl->peer_can_send_as4_path = impl->config.enable_4byte_asn && !impl->peer_4byte_asn;
    impl->send_ipv4_routes = send_ipv4_routes;
    impl->send_ipv6_routes = send_ipv6_routes;
    fsm_set_state(impl, LIBBGP_FSM_OPEN_CONFIRM);
    impl->session_generation++;
    impl->last_rx_ms = 0u;
    impl->last_keepalive_ms = 0u;
    impl->clock_initialized = false;
    impl->local_keepalive_send_pending = true;
    impl->local_keepalive_pending = false;
    impl->passive_open_send_pending = false;
    impl->passive_keepalive_pending = false;
    session_generation = impl->session_generation;
    out = impl->out;
    bgp_unlock(&impl->lock);
    err = fsm_send_keepalive(out);
    bgp_lock(&impl->lock);
    if (err != LIBBGP_OK) {
        fsm_rollback_failed_local_keepalive(impl, session_generation);
    } else if (impl->state == LIBBGP_FSM_OPEN_CONFIRM &&
        impl->session_generation == session_generation) {
        impl->local_keepalive_send_pending = false;
        if (fsm_establish_pending_keepalive(impl, session_generation)) {
            fsm_snapshot_established_locked(impl, &established);
        }
    }
    bgp_unlock(&impl->lock);
    if (established.active) {
        err = fsm_run_established_actions(impl, &established);
    }
    return err;
}

static libbgp_err_t fsm_on_pre_open_open(fsm_impl_t *impl, const libbgp_packet_t *pkt)
{
    libbgp_out_handler_t *out;
    struct libbgp_fsm_config config;
    uint16_t local_hold;
    uint16_t peer_hold;
    uint32_t peer_asn;
    uint32_t peer_bgp_id;
    uint16_t negotiated_hold_time;
    uint64_t session_generation;
    bool send_ipv4_routes;
    bool send_ipv6_routes;
    bool still_current;
    bool enable_mpbgp_ipv4;
    fsm_established_snapshot_t established;
    libbgp_err_t err;

    if (pkt->data.open.version != 4u) {
        fsm_snapshot_teardown(impl, &out, NULL, NULL, NULL, NULL);
        bgp_unlock(&impl->lock);
        (void)fsm_send_notification(out, FSM_NOTIFY_OPEN_MESSAGE_ERROR, FSM_OPEN_ERR_UNSUPPORTED_VERSION);
        return LIBBGP_ERR_BAD_LEN;
    }
    if (pkt->data.open.hold_time != 0u && pkt->data.open.hold_time < 3u) {
        fsm_snapshot_teardown(impl, &out, NULL, NULL, NULL, NULL);
        bgp_unlock(&impl->lock);
        (void)fsm_send_notification(out, FSM_NOTIFY_OPEN_MESSAGE_ERROR, FSM_OPEN_ERR_UNACCEPTABLE_HOLD_TIME);
        return LIBBGP_ERR_INVALID;
    }
    if (!fsm_valid_peer_bgp_id(pkt->data.open.bgp_id, impl->config.local_bgp_id)) {
        fsm_snapshot_teardown(impl, &out, NULL, NULL, NULL, NULL);
        bgp_unlock(&impl->lock);
        (void)fsm_send_notification(out, FSM_NOTIFY_OPEN_MESSAGE_ERROR, FSM_OPEN_ERR_BAD_BGP_ID);
        return LIBBGP_ERR_INVALID;
    }
    if (!fsm_local_open_config_valid(&impl->config)) {
        fsm_snapshot_teardown(impl, NULL, NULL, NULL, NULL, NULL);
        bgp_unlock(&impl->lock);
        return LIBBGP_ERR_INVALID;
    }
    local_hold = impl->config.hold_time;
    peer_hold = pkt->data.open.hold_time;
    peer_asn = libbgp_open_get_4b_asn(&pkt->data.open);
    if (impl->expected_peer_asn != 0u && peer_asn != impl->expected_peer_asn) {
        fsm_snapshot_teardown(impl, &out, NULL, NULL, NULL, NULL);
        bgp_unlock(&impl->lock);
        (void)fsm_send_notification(out, FSM_NOTIFY_OPEN_MESSAGE_ERROR, FSM_OPEN_ERR_BAD_PEER_AS);
        return LIBBGP_ERR_INVALID;
    }
    peer_bgp_id = pkt->data.open.bgp_id;
    fsm_negotiate_route_families(impl, &pkt->data.open, &send_ipv4_routes, &send_ipv6_routes);
    memset(&established, 0, sizeof(established));
    if (fsm_collision_reject_new_locked(impl, peer_bgp_id, &out)) {
        bgp_unlock(&impl->lock);
        (void)fsm_send_notification(out, FSM_NOTIFY_CEASE, FSM_CEASE_ERR_COLLISION);
        return LIBBGP_OK;
    }
    negotiated_hold_time = (local_hold == 0u || peer_hold == 0u) ? 0u :
        (local_hold < peer_hold ? local_hold : peer_hold);
    config = impl->config;
    enable_mpbgp_ipv4 = impl->enable_mpbgp_ipv4;
    impl->peer_asn = peer_asn;
    impl->peer_bgp_id = peer_bgp_id;
    impl->negotiated_hold_time = negotiated_hold_time;
    impl->peer_mpbgp_ipv6 = send_ipv6_routes;
    impl->peer_4byte_asn = impl->config.enable_4byte_asn && libbgp_open_has_4b_asn(&pkt->data.open);
    impl->peer_can_send_as4_path = impl->config.enable_4byte_asn && !impl->peer_4byte_asn;
    impl->send_ipv4_routes = send_ipv4_routes;
    impl->send_ipv6_routes = send_ipv6_routes;
    fsm_set_state(impl, LIBBGP_FSM_OPEN_CONFIRM);
    impl->session_generation++;
    session_generation = impl->session_generation;
    impl->last_rx_ms = 0u;
    impl->last_keepalive_ms = 0u;
    impl->clock_initialized = false;
    impl->local_keepalive_send_pending = false;
    impl->local_keepalive_pending = false;
    impl->passive_open_send_pending = true;
    impl->passive_keepalive_pending = false;
    out = impl->out;
    bgp_unlock(&impl->lock);

    err = fsm_send_open(out, &config, enable_mpbgp_ipv4);
    if (err != LIBBGP_OK) {
        goto relock_after_send;
    }
    bgp_lock(&impl->lock);
    still_current = impl->state == LIBBGP_FSM_OPEN_CONFIRM &&
        impl->session_generation == session_generation;
    if (still_current) {
        impl->passive_open_send_pending = false;
    }
    bgp_unlock(&impl->lock);
    if (!still_current) {
        goto relock_after_send;
    }
    bgp_lock(&impl->lock);
    if (impl->state == LIBBGP_FSM_OPEN_CONFIRM &&
        impl->session_generation == session_generation) {
        impl->local_keepalive_send_pending = true;
    }
    still_current = impl->state == LIBBGP_FSM_OPEN_CONFIRM &&
        impl->session_generation == session_generation;
    bgp_unlock(&impl->lock);
    if (!still_current) {
        goto relock_after_send;
    }
    err = fsm_send_keepalive(out);
    if (err != LIBBGP_OK) {
        goto relock_after_send;
    }
    bgp_lock(&impl->lock);
    if (impl->state == LIBBGP_FSM_OPEN_CONFIRM &&
        impl->session_generation == session_generation &&
        (impl->passive_keepalive_pending || impl->local_keepalive_pending)) {
        impl->local_keepalive_pending = true;
        if (!fsm_establish_pending_keepalive(impl, session_generation)) {
            impl->local_keepalive_send_pending = false;
        }
        if (impl->state == LIBBGP_FSM_ESTABLISHED) {
            fsm_snapshot_established_locked(impl, &established);
        }
    } else if (impl->state == LIBBGP_FSM_OPEN_CONFIRM &&
        impl->session_generation == session_generation) {
        impl->local_keepalive_send_pending = false;
    }
    if (established.active) {
        bgp_unlock(&impl->lock);
        return fsm_run_established_actions(impl, &established);
    }
    bgp_unlock(&impl->lock);
    goto relock_after_send;

relock_after_send:
    bgp_lock(&impl->lock);
    if (err != LIBBGP_OK) {
        fsm_rollback_failed_local_keepalive(impl, session_generation);
    }
    bgp_unlock(&impl->lock);
    return err;
}

static libbgp_err_t fsm_on_open_confirm(fsm_impl_t *impl, const libbgp_packet_t *pkt)
{
    libbgp_out_handler_t *out = NULL;
    fsm_established_snapshot_t established;

    if (pkt->type == LIBBGP_PACKET_OPEN && impl->passive_open_send_pending) {
        if (pkt->data.open.version != 4u) {
            fsm_snapshot_teardown(impl, &out, NULL, NULL, NULL, NULL);
            bgp_unlock(&impl->lock);
            (void)fsm_send_notification(out, FSM_NOTIFY_OPEN_MESSAGE_ERROR, FSM_OPEN_ERR_UNSUPPORTED_VERSION);
            return LIBBGP_ERR_BAD_LEN;
        }
        if (pkt->data.open.hold_time != 0u && pkt->data.open.hold_time < 3u) {
            fsm_snapshot_teardown(impl, &out, NULL, NULL, NULL, NULL);
            bgp_unlock(&impl->lock);
            (void)fsm_send_notification(out, FSM_NOTIFY_OPEN_MESSAGE_ERROR, FSM_OPEN_ERR_UNACCEPTABLE_HOLD_TIME);
            return LIBBGP_ERR_INVALID;
        }
        if (!fsm_valid_peer_bgp_id(pkt->data.open.bgp_id, impl->config.local_bgp_id)) {
            fsm_snapshot_teardown(impl, &out, NULL, NULL, NULL, NULL);
            bgp_unlock(&impl->lock);
            (void)fsm_send_notification(out, FSM_NOTIFY_OPEN_MESSAGE_ERROR, FSM_OPEN_ERR_BAD_BGP_ID);
            return LIBBGP_ERR_INVALID;
        }
        bgp_unlock(&impl->lock);
        return LIBBGP_OK;
    }
    if (pkt->type == LIBBGP_PACKET_KEEPALIVE) {
        fsm_mark_rx_current(impl);
        if (impl->passive_open_send_pending) {
            impl->passive_keepalive_pending = true;
            bgp_unlock(&impl->lock);
            return LIBBGP_OK;
        }
        if (impl->local_keepalive_send_pending) {
            impl->local_keepalive_pending = true;
            bgp_unlock(&impl->lock);
            return LIBBGP_OK;
        }
        fsm_set_state(impl, LIBBGP_FSM_ESTABLISHED);
        impl->session_generation++;
        impl->local_keepalive_send_pending = false;
        impl->local_keepalive_pending = false;
        impl->passive_open_send_pending = false;
        impl->passive_keepalive_pending = false;
        fsm_snapshot_established_locked(impl, &established);
        bgp_unlock(&impl->lock);
        return fsm_run_established_actions(impl, &established);
    }
    if (pkt->type == LIBBGP_PACKET_NOTIFICATION) {
        fsm_snapshot_teardown(impl, NULL, NULL, NULL, NULL, NULL);
        bgp_unlock(&impl->lock);
        return LIBBGP_OK;
    }
    out = impl->out;
    fsm_snapshot_teardown(impl, NULL, NULL, NULL, NULL, NULL);
    bgp_unlock(&impl->lock);
    (void)fsm_send_notification(out, FSM_NOTIFY_FSM_ERROR, FSM_ERR_OPEN_CONFIRM);
    return LIBBGP_ERR_BAD_TYPE;
}

static libbgp_err_t fsm_on_established(fsm_impl_t *impl, const libbgp_packet_t *pkt)
{
    libbgp_event_bus_t *bus;
    libbgp_out_handler_t *out;
    libbgp_rib4_t *rib4;
    libbgp_rib6_t *rib6;
    uint32_t peer_bgp_id;
    bool peer_mpbgp_ipv6;
    uint64_t rx_ms;
    uint64_t session_generation;
    fsm_state_change_t changes[FSM_STATE_CHANGE_QUEUE_CAP];
    libbgp_fsm_state_change_fn cb = NULL;
    void *ctx = NULL;
    size_t change_count = 0u;
    fsm_update_journal_t journal;
    uint8_t update_err_subcode = FSM_UPDATE_ERR_MALFORMED_ATTR_LIST;
    bool advertisements_ignored = false;
    libbgp_err_t err;
    libbgp_err_t send_err;

    if (pkt->type == LIBBGP_PACKET_KEEPALIVE) {
        fsm_mark_rx_current(impl);
        bgp_unlock(&impl->lock);
        return LIBBGP_OK;
    }
    if (pkt->type == LIBBGP_PACKET_NOTIFICATION) {
        fsm_snapshot_teardown(impl, NULL, &bus, &rib4, &rib6, &peer_bgp_id);
        bgp_unlock(&impl->lock);
        change_count = fsm_drain_state_changes(impl, &cb, &ctx, changes);
        fsm_discard_peer_routes_publish(bus, rib4, rib6, peer_bgp_id);
        fsm_publish_event(bus, 0u, LIBBGP_EVENT_SESSION_DOWN, 0u, NULL, NULL);
        fsm_dispatch_drained_state_changes(impl, cb, ctx, changes, change_count);
        return LIBBGP_OK;
    }
    if (pkt->type != LIBBGP_PACKET_UPDATE) {
        fsm_snapshot_teardown(impl, &out, &bus, &rib4, &rib6, &peer_bgp_id);
        bgp_unlock(&impl->lock);
        change_count = fsm_drain_state_changes(impl, &cb, &ctx, changes);
        (void)fsm_send_notification(out, FSM_NOTIFY_FSM_ERROR, FSM_ERR_ESTABLISHED);
        fsm_discard_peer_routes_publish(bus, rib4, rib6, peer_bgp_id);
        fsm_publish_event(bus, 0u, LIBBGP_EVENT_SESSION_DOWN, 0u, NULL, NULL);
        fsm_dispatch_drained_state_changes(impl, cb, ctx, changes, change_count);
        return LIBBGP_ERR_BAD_TYPE;
    }
    rx_ms = impl->current_ms;
    rib4 = impl->rib4;
    rib6 = impl->rib6;
    bus = impl->bus;
    peer_bgp_id = impl->peer_bgp_id;
    peer_mpbgp_ipv6 = impl->peer_mpbgp_ipv6;
    session_generation = impl->session_generation;
    if (!peer_mpbgp_ipv6 && pkt->data.update.attrs != NULL) {
        size_t i;

        for (i = 0u; i < pkt->data.update.attr_count; i++) {
            const libbgp_pattr_t *attr = pkt->data.update.attrs[i];

            if (attr != NULL &&
                (attr->type == LIBBGP_PATTR_MP_REACH_IPV6 ||
                 attr->type == LIBBGP_PATTR_MP_UNREACH_IPV6)) {
                fsm_snapshot_teardown(impl, &out, &bus, &rib4, &rib6, &peer_bgp_id);
                bgp_unlock(&impl->lock);
                change_count = fsm_drain_state_changes(impl, &cb, &ctx, changes);
                send_err = fsm_send_notification(
                    out,
                    FSM_NOTIFY_UPDATE_MESSAGE_ERROR,
                    FSM_UPDATE_ERR_MALFORMED_ATTR_LIST);
                fsm_discard_peer_routes_publish(bus, rib4, rib6, peer_bgp_id);
                fsm_publish_event(bus, 0u, LIBBGP_EVENT_SESSION_DOWN, 0u, NULL, NULL);
                fsm_dispatch_drained_state_changes(impl, cb, ctx, changes, change_count);
                return send_err == LIBBGP_OK ? LIBBGP_ERR_INVALID : send_err;
            }
        }
    }
    memset(&journal, 0, sizeof(journal));
    err = fsm_apply_update(
        impl,
        session_generation,
        rib4,
        rib6,
        peer_bgp_id,
        &pkt->data.update,
        &journal,
        &advertisements_ignored,
        &update_err_subcode);
    if (impl->state != LIBBGP_FSM_ESTABLISHED ||
        impl->session_generation != session_generation) {
        bgp_unlock(&impl->lock);
        fsm_cleanup_stale_update_journal(&journal, rib4, rib6, peer_bgp_id);
        fsm_update_journal_destroy(&journal);
        return err;
    }
    if (err != LIBBGP_OK && err != LIBBGP_ERR_INVALID) {
        bgp_unlock(&impl->lock);
        fsm_rollback_update_journal(&journal, rib4, rib6, peer_bgp_id);
        fsm_update_journal_destroy(&journal);
        return err;
    }
    if (err == LIBBGP_ERR_INVALID) {
        fsm_snapshot_teardown(impl, &out, &bus, &rib4, &rib6, &peer_bgp_id);
        bgp_unlock(&impl->lock);
        change_count = fsm_drain_state_changes(impl, &cb, &ctx, changes);
        fsm_rollback_update_journal(&journal, rib4, rib6, peer_bgp_id);
        send_err = fsm_send_notification(out, FSM_NOTIFY_UPDATE_MESSAGE_ERROR, update_err_subcode);
        fsm_discard_peer_routes_publish(bus, rib4, rib6, peer_bgp_id);
        fsm_publish_event(bus, 0u, LIBBGP_EVENT_SESSION_DOWN, 0u, NULL, NULL);
        fsm_update_journal_destroy(&journal);
        fsm_dispatch_drained_state_changes(impl, cb, ctx, changes, change_count);
        return send_err == LIBBGP_OK ? err : send_err;
    }
    if (err == LIBBGP_OK && impl->clock_initialized) {
        impl->last_rx_ms = rx_ms;
    }
    bgp_unlock(&impl->lock);
    if (err == LIBBGP_OK) {
        fsm_publish_update_events(
            impl,
            session_generation,
            bus,
            peer_bgp_id,
            &journal);
    }
    fsm_update_journal_destroy(&journal);
    return err;
}

libbgp_err_t libbgp_fsm_on_packet(libbgp_fsm_t *fsm, const libbgp_packet_t *pkt)
{
    fsm_impl_t *impl;
    libbgp_fsm_state_t state;
    libbgp_err_t err;

    if (fsm == NULL || pkt == NULL) {
        return LIBBGP_ERR_INVALID;
    }
    impl = fsm_handle_acquire(fsm);
    if (impl == NULL) {
        return LIBBGP_ERR_INVALID;
    }
    bgp_lock(&impl->lock);
    state = impl->state;
    if (pkt->type == LIBBGP_PACKET_NOTIFICATION) {
        libbgp_event_bus_t *bus = NULL;
        libbgp_rib4_t *rib4 = NULL;
        libbgp_rib6_t *rib6 = NULL;
        uint32_t peer_bgp_id = 0u;

        fsm_snapshot_teardown(impl, NULL, &bus, &rib4, &rib6, &peer_bgp_id);
        bgp_unlock(&impl->lock);
        if (state == LIBBGP_FSM_ESTABLISHED) {
            fsm_state_change_t changes[FSM_STATE_CHANGE_QUEUE_CAP];
            libbgp_fsm_state_change_fn cb = NULL;
            void *ctx = NULL;
            size_t change_count = fsm_drain_state_changes(impl, &cb, &ctx, changes);

            fsm_discard_peer_routes_publish(bus, rib4, rib6, peer_bgp_id);
            fsm_publish_event(bus, 0u, LIBBGP_EVENT_SESSION_DOWN, 0u, NULL, NULL);
            fsm_dispatch_drained_state_changes(impl, cb, ctx, changes, change_count);
        } else {
            fsm_dispatch_state_changes_impl(impl);
        }
        if (fsm_impl_release(impl)) {
            fsm_impl_free(impl);
        }
        return LIBBGP_OK;
    }

    switch (state) {
    case LIBBGP_FSM_IDLE:
        if (pkt->type == LIBBGP_PACKET_OPEN) {
            err = fsm_on_pre_open_open(impl, pkt);
        } else {
            bgp_unlock(&impl->lock);
            err = LIBBGP_OK;
        }
        break;
    case LIBBGP_FSM_CONNECT:
    case LIBBGP_FSM_ACTIVE:
        if (pkt->type == LIBBGP_PACKET_OPEN) {
            err = fsm_on_pre_open_open(impl, pkt);
        } else {
            bgp_unlock(&impl->lock);
            err = LIBBGP_OK;
        }
        break;
    case LIBBGP_FSM_OPEN_SENT:
        err = fsm_on_open_sent(impl, pkt);
        break;
    case LIBBGP_FSM_OPEN_CONFIRM:
        err = fsm_on_open_confirm(impl, pkt);
        break;
    case LIBBGP_FSM_ESTABLISHED:
        err = fsm_on_established(impl, pkt);
        break;
    default:
        bgp_unlock(&impl->lock);
        err = LIBBGP_OK;
        break;
    }
    if (fsm_impl_release(impl)) {
        fsm_impl_free(impl);
    }
    return err;
}

libbgp_err_t libbgp_fsm_on_raw_packet(libbgp_fsm_t *fsm, const uint8_t *buf, size_t len)
{
    fsm_impl_t *impl;
    libbgp_packet_t pkt;
    bgp_parse_error_detail_t detail;
    libbgp_out_handler_t *out = NULL;
    libbgp_event_bus_t *bus = NULL;
    libbgp_rib4_t *rib4 = NULL;
    libbgp_rib6_t *rib6 = NULL;
    uint32_t peer_bgp_id = 0u;
    fsm_state_change_t changes[FSM_STATE_CHANGE_QUEUE_CAP];
    libbgp_fsm_state_change_fn cb = NULL;
    void *ctx = NULL;
    size_t change_count = 0u;
    libbgp_fsm_state_t state;
    size_t consumed = 0u;
    bool use_4b_asn;
    libbgp_err_t err;
    libbgp_err_t send_err;

    if (fsm == NULL || buf == NULL) {
        return LIBBGP_ERR_INVALID;
    }
    impl = fsm_handle_acquire(fsm);
    if (impl == NULL) {
        return LIBBGP_ERR_INVALID;
    }

    bgp_lock(&impl->lock);
    if (impl->state == LIBBGP_FSM_ESTABLISHED) {
        use_4b_asn = impl->peer_4byte_asn;
    } else {
        use_4b_asn = impl->config.enable_4byte_asn;
    }
    bgp_unlock(&impl->lock);

    libbgp_packet_init(&pkt);
    err = bgp_packet_parse_as4_detail(&pkt, buf, len, use_4b_asn, &consumed, &detail);
    if (err == LIBBGP_OK && consumed != len) {
        libbgp_packet_destroy(&pkt);
        detail.err = LIBBGP_ERR_BAD_LEN;
        detail.notify_code = 1u;
        detail.notify_subcode = 2u;
        err = LIBBGP_ERR_BAD_LEN;
    } else if (err == LIBBGP_OK) {
        err = libbgp_fsm_on_packet(fsm, &pkt);
        libbgp_packet_destroy(&pkt);
        if (fsm_impl_release(impl)) {
            fsm_impl_free(impl);
        }
        return err;
    } else {
        libbgp_packet_destroy(&pkt);
    }
    if (detail.notify_code == 0u) {
        if (fsm_impl_release(impl)) {
            fsm_impl_free(impl);
        }
        return err;
    }

    bgp_lock(&impl->lock);
    state = impl->state;
    fsm_snapshot_teardown(impl, &out, &bus, &rib4, &rib6, &peer_bgp_id);
    bgp_unlock(&impl->lock);
    change_count = fsm_drain_state_changes(impl, &cb, &ctx, changes);
    if (state == LIBBGP_FSM_ESTABLISHED) {
        fsm_discard_peer_routes_publish(bus, rib4, rib6, peer_bgp_id);
        fsm_publish_event(bus, 0u, LIBBGP_EVENT_SESSION_DOWN, 0u, NULL, NULL);
    }
    send_err = fsm_send_notification(out, detail.notify_code, detail.notify_subcode);
    fsm_dispatch_drained_state_changes(impl, cb, ctx, changes, change_count);
    if (fsm_impl_release(impl)) {
        fsm_impl_free(impl);
    }
    return send_err == LIBBGP_OK ? detail.err : send_err;
}

libbgp_err_t libbgp_fsm_tick(libbgp_fsm_t *fsm, uint64_t now_ms)
{
    fsm_impl_t *impl;
    libbgp_out_handler_t *out = NULL;
    libbgp_event_bus_t *bus = NULL;
    libbgp_rib4_t *rib4 = NULL;
    libbgp_rib6_t *rib6 = NULL;
    uint32_t peer_bgp_id = 0u;
    fsm_state_change_t changes[FSM_STATE_CHANGE_QUEUE_CAP];
    libbgp_fsm_state_change_fn cb = NULL;
    void *ctx = NULL;
    size_t change_count = 0u;
    bool send_keepalive = false;
    bool send_hold_expired = false;
    bool was_established = false;
    libbgp_fsm_state_t keepalive_state = LIBBGP_FSM_IDLE;
    uint64_t keepalive_generation = 0u;
    uint16_t keepalive_time = 0u;

    if (fsm == NULL) {
        return LIBBGP_ERR_INVALID;
    }
    impl = fsm_handle_acquire(fsm);
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
        if (fsm_impl_release(impl)) {
            fsm_impl_free(impl);
        }
        return LIBBGP_OK;
    }
    impl->current_ms = now_ms;
    if (impl->negotiated_hold_time > 0u &&
        fsm_state_hold_timer_active(impl->state) &&
        now_ms - impl->last_rx_ms >= (uint64_t)impl->negotiated_hold_time * 1000u) {
        send_hold_expired = true;
        was_established = impl->state == LIBBGP_FSM_ESTABLISHED;
        fsm_snapshot_teardown(impl, &out, &bus, &rib4, &rib6, &peer_bgp_id);
        bgp_unlock(&impl->lock);
        change_count = fsm_drain_state_changes(impl, &cb, &ctx, changes);
        (void)fsm_send_notification(out, FSM_NOTIFY_HOLD_TIMER_EXPIRED, 0u);
        if (was_established) {
            fsm_discard_peer_routes_publish(bus, rib4, rib6, peer_bgp_id);
            fsm_publish_event(bus, 0u, LIBBGP_EVENT_SESSION_DOWN, 0u, NULL, NULL);
        }
        fsm_dispatch_drained_state_changes(impl, cb, ctx, changes, change_count);
        if (fsm_impl_release(impl)) {
            fsm_impl_free(impl);
        }
        return LIBBGP_OK;
    }
    keepalive_time = fsm_effective_keepalive_time(impl);
    if ((impl->state == LIBBGP_FSM_ESTABLISHED || impl->state == LIBBGP_FSM_OPEN_CONFIRM) &&
        keepalive_time > 0u &&
        now_ms - impl->last_keepalive_ms >= (uint64_t)keepalive_time * 1000u) {
        send_keepalive = true;
        keepalive_state = impl->state;
        keepalive_generation = impl->session_generation;
        out = impl->out;
    }
    bgp_unlock(&impl->lock);

    if (send_keepalive) {
        libbgp_err_t err = fsm_send_keepalive(out);
        if (err == LIBBGP_OK) {
            bgp_lock(&impl->lock);
            if (impl->state == keepalive_state &&
                impl->session_generation == keepalive_generation) {
                impl->last_keepalive_ms = now_ms;
            }
            bgp_unlock(&impl->lock);
        } else {
            bgp_lock(&impl->lock);
            if (impl->state == keepalive_state &&
                impl->session_generation == keepalive_generation) {
                was_established = impl->state == LIBBGP_FSM_ESTABLISHED;
                fsm_snapshot_teardown(impl, NULL, &bus, &rib4, &rib6, &peer_bgp_id);
            } else {
                was_established = false;
            }
            bgp_unlock(&impl->lock);
            change_count = fsm_drain_state_changes(impl, &cb, &ctx, changes);
            if (was_established) {
                fsm_discard_peer_routes_publish(bus, rib4, rib6, peer_bgp_id);
                fsm_publish_event(bus, 0u, LIBBGP_EVENT_SESSION_DOWN, 0u, NULL, NULL);
            }
            fsm_dispatch_drained_state_changes(impl, cb, ctx, changes, change_count);
        }
        if (fsm_impl_release(impl)) {
            fsm_impl_free(impl);
        }
        return err;
    }
    BGP_UNUSED(send_hold_expired);
    if (fsm_impl_release(impl)) {
        fsm_impl_free(impl);
    }
    return LIBBGP_OK;
}

uint32_t libbgp_fsm_peer_asn(const libbgp_fsm_t *fsm)
{
    fsm_impl_t *impl = fsm_handle_acquire(fsm);
    uint32_t peer_asn;

    if (impl == NULL) {
        return 0u;
    }
    bgp_lock(&impl->lock);
    peer_asn = impl->peer_asn;
    bgp_unlock(&impl->lock);
    fsm_impl_release_free(impl);
    return peer_asn;
}

uint32_t libbgp_fsm_peer_bgp_id(const libbgp_fsm_t *fsm)
{
    fsm_impl_t *impl = fsm_handle_acquire(fsm);
    uint32_t peer_bgp_id;

    if (impl == NULL) {
        return 0u;
    }
    bgp_lock(&impl->lock);
    peer_bgp_id = impl->peer_bgp_id;
    bgp_unlock(&impl->lock);
    fsm_impl_release_free(impl);
    return peer_bgp_id;
}

uint16_t libbgp_fsm_negotiated_hold_time(const libbgp_fsm_t *fsm)
{
    fsm_impl_t *impl = fsm_handle_acquire(fsm);
    uint16_t hold_time;

    if (impl == NULL) {
        return 0u;
    }
    bgp_lock(&impl->lock);
    hold_time = impl->negotiated_hold_time;
    bgp_unlock(&impl->lock);
    fsm_impl_release_free(impl);
    return hold_time;
}
