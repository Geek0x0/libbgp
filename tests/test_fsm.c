#include "test_main.h"

#include "libbgp/alloc.h"
#include "libbgp/capability.h"
#include "libbgp/event.h"
#include "libbgp/fsm.h"
#include "libbgp/pattr.h"
#include "libbgp/rib4.h"
#include "libbgp/rib6.h"

#include <stdbool.h>

typedef struct sent_packet {
    uint8_t bytes[LIBBGP_BGP_MAX_PACKET_LEN];
    size_t len;
    libbgp_packet_type_t type;
} sent_packet_t;

typedef struct out_ctx {
    sent_packet_t sent[16];
    size_t count;
} out_ctx_t;

typedef struct event_ctx {
    libbgp_event_type_t types[16];
    libbgp_prefix4_t prefixes[16];
    libbgp_prefix6_t prefixes6[16];
    const libbgp_update_msg_t *updates[16];
    uint32_t sources[16];
    bool has_prefix4[16];
    bool has_prefix6[16];
    size_t count;
} event_ctx_t;

typedef struct reentrant_start_ctx {
    libbgp_fsm_t *fsm;
    out_ctx_t out;
    size_t calls;
} reentrant_start_ctx_t;

typedef struct reentrant_restart_fail_ctx {
    libbgp_fsm_t *fsm;
    out_ctx_t out;
    size_t calls;
    libbgp_err_t stop_err;
    libbgp_err_t start_err;
} reentrant_restart_fail_ctx_t;

typedef struct short_send_ctx {
    uint8_t bytes[LIBBGP_BGP_MAX_PACKET_LEN];
    size_t len;
    size_t calls;
} short_send_ctx_t;

typedef struct fail_after_send_ctx {
    out_ctx_t out;
    size_t calls;
    size_t fail_on_call;
} fail_after_send_ctx_t;

typedef struct reentrant_packet_ctx {
    libbgp_fsm_t *fsm;
    const libbgp_packet_t *packet;
    out_ctx_t out;
    size_t calls;
    libbgp_err_t packet_err;
} reentrant_packet_ctx_t;

typedef struct reentrant_packet_fail_on_keepalive_ctx {
    libbgp_fsm_t *fsm;
    const libbgp_packet_t *packet;
    out_ctx_t out;
    size_t calls;
    libbgp_err_t packet_err;
} reentrant_packet_fail_on_keepalive_ctx_t;

typedef struct reentrant_restart_on_keepalive_ctx {
    libbgp_fsm_t *fsm;
    out_ctx_t out;
    size_t calls;
    bool restarted;
    libbgp_err_t stop_err;
    libbgp_err_t start_err;
} reentrant_restart_on_keepalive_ctx_t;

typedef struct restart_on_session_down_ctx {
    libbgp_fsm_t *fsm;
    size_t calls;
    libbgp_err_t start_err;
} restart_on_session_down_ctx_t;

typedef struct session_up_insert_local_ctx {
    libbgp_rib4_t *rib;
    size_t calls;
    libbgp_err_t insert_err;
} session_up_insert_local_ctx_t;

typedef struct stop_on_route_ctx {
    libbgp_fsm_t *fsm;
    size_t route_events;
    libbgp_err_t stop_err;
} stop_on_route_ctx_t;

typedef struct tick_on_route_ctx {
    libbgp_fsm_t *fsm;
    uint64_t now_ms;
    size_t route_events;
    libbgp_err_t tick_err;
} tick_on_route_ctx_t;

typedef struct restart_on_route_ctx {
    libbgp_fsm_t *fsm;
    size_t route_events;
    libbgp_err_t stop_err;
    libbgp_err_t start_err;
    libbgp_err_t open_err;
    libbgp_err_t keepalive_err;
} restart_on_route_ctx_t;

typedef struct reentrant_replace_route_ctx {
    libbgp_fsm_t *fsm;
    const libbgp_packet_t *replacement;
    size_t calls;
    libbgp_err_t stop_err;
    libbgp_err_t start_err;
    libbgp_err_t open_err;
    libbgp_err_t keepalive_err;
    libbgp_err_t update_err;
} reentrant_replace_route_ctx_t;

typedef struct fail_rib6_route_alloc_ctx {
    size_t rib6_route_calloc_calls;
    size_t failed_calloc_calls;
    size_t fail_on_rib6_route_calloc;
} fail_rib6_route_alloc_ctx_t;

static void *fail_rib6_route_alloc_malloc(size_t size, void *ctx)
{
    (void)ctx;
    return malloc(size);
}

static void *fail_rib6_route_alloc_calloc(size_t nmemb, size_t size, void *ctx)
{
    fail_rib6_route_alloc_ctx_t *fail_ctx = (fail_rib6_route_alloc_ctx_t *)ctx;

    if (nmemb == 1u && size == sizeof(libbgp_rib6_route_t)) {
        fail_ctx->rib6_route_calloc_calls++;
        if (fail_ctx->failed_calloc_calls == 0u &&
            fail_ctx->rib6_route_calloc_calls == (fail_ctx->fail_on_rib6_route_calloc == 0u ? 1u : fail_ctx->fail_on_rib6_route_calloc)) {
            fail_ctx->failed_calloc_calls++;
            return NULL;
        }
    }
    return calloc(nmemb, size);
}

static void *fail_rib6_route_alloc_realloc(void *ptr, size_t size, void *ctx)
{
    (void)ctx;
    return realloc(ptr, size);
}

static void fail_rib6_route_alloc_free(void *ptr, void *ctx)
{
    (void)ctx;
    free(ptr);
}

static libbgp_alloc_t fail_rib6_route_alloc_make(fail_rib6_route_alloc_ctx_t *ctx)
{
    libbgp_alloc_t alloc;

    alloc.malloc = fail_rib6_route_alloc_malloc;
    alloc.calloc = fail_rib6_route_alloc_calloc;
    alloc.realloc = fail_rib6_route_alloc_realloc;
    alloc.free = fail_rib6_route_alloc_free;
    alloc.ctx = ctx;
    return alloc;
}

static uint32_t ip4(uint8_t a, uint8_t b, uint8_t c, uint8_t d)
{
    uint8_t bytes[4];
    uint32_t value;

    bytes[0] = a;
    bytes[1] = b;
    bytes[2] = c;
    bytes[3] = d;
    memcpy(&value, bytes, sizeof(value));
    return value;
}

static libbgp_prefix4_t p4(uint8_t a, uint8_t b, uint8_t c, uint8_t d, uint8_t len)
{
    libbgp_prefix4_t p;

    p.addr = ip4(a, b, c, d) & libbgp_cidr_to_mask(len);
    p.len = len;
    return p;
}

static libbgp_prefix6_t p6(const uint8_t addr[16], uint8_t len)
{
    libbgp_prefix6_t p;
    uint8_t mask[16];
    size_t i;

    memcpy(p.addr, addr, 16u);
    libbgp_cidr6_to_mask(len, mask);
    for (i = 0u; i < 16u; i++) {
        p.addr[i] &= mask[i];
    }
    p.len = len;
    return p;
}

static struct libbgp_fsm_config test_fsm_config(void)
{
    struct libbgp_fsm_config config;

    config.local_asn = 65000u;
    config.local_bgp_id = ip4(192u, 0u, 2u, 1u);
    config.hold_time = 90u;
    config.keepalive_time = 30u;
    config.enable_4byte_asn = true;
    config.enable_mpbgp_ipv6 = true;
    return config;
}

static libbgp_err_t init_test_fsm(libbgp_fsm_t *fsm)
{
    struct libbgp_fsm_config config = test_fsm_config();

    return libbgp_fsm_init(fsm, &config);
}

static libbgp_packet_t make_open_packet(uint32_t asn, uint16_t hold, uint32_t bgp_id, bool cap4);
static libbgp_packet_t make_keepalive_packet(void);

static ssize_t capture_send(void *ctx, const uint8_t *buf, size_t len)
{
    out_ctx_t *out = (out_ctx_t *)ctx;
    libbgp_packet_t pkt;
    size_t used = 0u;

    LIBBGP_ASSERT(out->count < LIBBGP_ARRAY_LEN(out->sent));
    LIBBGP_ASSERT(len <= sizeof(out->sent[out->count].bytes));
    memcpy(out->sent[out->count].bytes, buf, len);
    out->sent[out->count].len = len;

    libbgp_packet_init(&pkt);
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_packet_parse(&pkt, buf, len, &used));
    LIBBGP_ASSERT_EQ_U64(len, used);
    out->sent[out->count].type = pkt.type;
    libbgp_packet_destroy(&pkt);
    out->count++;
    return (ssize_t)len;
}

static ssize_t fail_send(void *ctx, const uint8_t *buf, size_t len)
{
    (void)ctx;
    (void)buf;
    (void)len;
    return -1;
}

static ssize_t reentrant_start_send(void *ctx, const uint8_t *buf, size_t len)
{
    reentrant_start_ctx_t *reentrant = (reentrant_start_ctx_t *)ctx;

    LIBBGP_ASSERT(reentrant->calls < 4u);
    reentrant->calls++;
    LIBBGP_ASSERT_EQ_I64((ssize_t)len, capture_send(&reentrant->out, buf, len));
    if (reentrant->calls == 1u) {
        LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_fsm_start(reentrant->fsm));
    }
    return (ssize_t)len;
}

static ssize_t reentrant_restart_then_fail_send(void *ctx, const uint8_t *buf, size_t len)
{
    reentrant_restart_fail_ctx_t *reentrant = (reentrant_restart_fail_ctx_t *)ctx;

    LIBBGP_ASSERT(reentrant->calls < 4u);
    reentrant->calls++;
    LIBBGP_ASSERT_EQ_I64((ssize_t)len, capture_send(&reentrant->out, buf, len));
    if (reentrant->calls == 1u) {
        reentrant->stop_err = libbgp_fsm_stop(reentrant->fsm);
        reentrant->start_err = libbgp_fsm_start(reentrant->fsm);
        return -1;
    }
    return (ssize_t)len;
}

static ssize_t zero_progress_send(void *ctx, const uint8_t *buf, size_t len)
{
    short_send_ctx_t *short_send = (short_send_ctx_t *)ctx;

    LIBBGP_ASSERT(short_send->calls < 4u);
    LIBBGP_ASSERT(short_send->len + len <= sizeof(short_send->bytes));
    memcpy(short_send->bytes + short_send->len, buf, len);
    short_send->len += len;
    short_send->calls++;
    return 0;
}

static ssize_t fail_after_send(void *ctx, const uint8_t *buf, size_t len)
{
    fail_after_send_ctx_t *fail_after = (fail_after_send_ctx_t *)ctx;

    fail_after->calls++;
    if (fail_after->calls == fail_after->fail_on_call) {
        (void)buf;
        (void)len;
        return -1;
    }
    return capture_send(&fail_after->out, buf, len);
}

static ssize_t reentrant_packet_send(void *ctx, const uint8_t *buf, size_t len)
{
    reentrant_packet_ctx_t *reentrant = (reentrant_packet_ctx_t *)ctx;

    LIBBGP_ASSERT(reentrant->calls < 8u);
    reentrant->calls++;
    LIBBGP_ASSERT_EQ_I64((ssize_t)len, capture_send(&reentrant->out, buf, len));
    if (reentrant->calls == 1u) {
        reentrant->packet_err = libbgp_fsm_on_packet(reentrant->fsm, reentrant->packet);
    }
    return (ssize_t)len;
}

static ssize_t reentrant_packet_on_keepalive_send(void *ctx, const uint8_t *buf, size_t len)
{
    reentrant_packet_ctx_t *reentrant = (reentrant_packet_ctx_t *)ctx;
    libbgp_packet_t pkt;
    size_t used = 0u;

    LIBBGP_ASSERT(reentrant->calls < 8u);
    reentrant->calls++;
    LIBBGP_ASSERT_EQ_I64((ssize_t)len, capture_send(&reentrant->out, buf, len));

    libbgp_packet_init(&pkt);
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_packet_parse(&pkt, buf, len, &used));
    if (pkt.type == LIBBGP_PACKET_KEEPALIVE && reentrant->packet_err == 0) {
        reentrant->packet_err = libbgp_fsm_on_packet(reentrant->fsm, reentrant->packet);
    }
    libbgp_packet_destroy(&pkt);
    return (ssize_t)len;
}

static ssize_t reentrant_packet_fail_on_keepalive_send(void *ctx, const uint8_t *buf, size_t len)
{
    reentrant_packet_fail_on_keepalive_ctx_t *reentrant = (reentrant_packet_fail_on_keepalive_ctx_t *)ctx;
    libbgp_packet_t pkt;
    libbgp_packet_type_t type;
    size_t used = 0u;

    LIBBGP_ASSERT(reentrant->calls < 8u);
    reentrant->calls++;
    LIBBGP_ASSERT_EQ_I64((ssize_t)len, capture_send(&reentrant->out, buf, len));

    libbgp_packet_init(&pkt);
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_packet_parse(&pkt, buf, len, &used));
    type = pkt.type;
    if (type == LIBBGP_PACKET_KEEPALIVE && reentrant->packet_err == 0) {
        reentrant->packet_err = libbgp_fsm_on_packet(reentrant->fsm, reentrant->packet);
    }
    libbgp_packet_destroy(&pkt);
    return type == LIBBGP_PACKET_KEEPALIVE ? -1 : (ssize_t)len;
}

static ssize_t reentrant_packet_on_open_send(void *ctx, const uint8_t *buf, size_t len)
{
    reentrant_packet_ctx_t *reentrant = (reentrant_packet_ctx_t *)ctx;
    libbgp_packet_t pkt;
    size_t used = 0u;

    LIBBGP_ASSERT(reentrant->calls < 8u);
    reentrant->calls++;
    LIBBGP_ASSERT_EQ_I64((ssize_t)len, capture_send(&reentrant->out, buf, len));

    libbgp_packet_init(&pkt);
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_packet_parse(&pkt, buf, len, &used));
    if (pkt.type == LIBBGP_PACKET_OPEN && reentrant->packet_err == 0) {
        reentrant->packet_err = libbgp_fsm_on_packet(reentrant->fsm, reentrant->packet);
    }
    libbgp_packet_destroy(&pkt);
    return (ssize_t)len;
}

static ssize_t reentrant_restart_on_keepalive_send(void *ctx, const uint8_t *buf, size_t len)
{
    reentrant_restart_on_keepalive_ctx_t *reentrant = (reentrant_restart_on_keepalive_ctx_t *)ctx;
    libbgp_packet_t pkt;
    size_t used = 0u;

    LIBBGP_ASSERT(reentrant->calls < 8u);
    reentrant->calls++;
    LIBBGP_ASSERT_EQ_I64((ssize_t)len, capture_send(&reentrant->out, buf, len));

    libbgp_packet_init(&pkt);
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_packet_parse(&pkt, buf, len, &used));
    if (pkt.type == LIBBGP_PACKET_KEEPALIVE && !reentrant->restarted) {
        reentrant->restarted = true;
        reentrant->stop_err = libbgp_fsm_stop(reentrant->fsm);
        reentrant->start_err = libbgp_fsm_start(reentrant->fsm);
        libbgp_packet_destroy(&pkt);
        return -1;
    }
    libbgp_packet_destroy(&pkt);
    return (ssize_t)len;
}

static void event_capture(const libbgp_event_t *event, void *ctx)
{
    event_ctx_t *events = (event_ctx_t *)ctx;

    LIBBGP_ASSERT(events->count < LIBBGP_ARRAY_LEN(events->types));
    events->types[events->count] = event->type;
    events->sources[events->count] = event->source_router_id;
    events->updates[events->count] = event->update;
    if (event->prefix4 != NULL) {
        events->prefixes[events->count] = *event->prefix4;
        events->has_prefix4[events->count] = true;
    } else {
        memset(&events->prefixes[events->count], 0, sizeof(events->prefixes[events->count]));
    }
    if (event->prefix6 != NULL) {
        events->prefixes6[events->count] = *event->prefix6;
        events->has_prefix6[events->count] = true;
    } else {
        memset(&events->prefixes6[events->count], 0, sizeof(events->prefixes6[events->count]));
    }
    events->count++;
}

static void restart_on_session_down(const libbgp_event_t *event, void *ctx)
{
    restart_on_session_down_ctx_t *restart = (restart_on_session_down_ctx_t *)ctx;

    if (event->type != LIBBGP_EVENT_SESSION_DOWN || restart->calls != 0u) {
        return;
    }
    restart->calls++;
    restart->start_err = libbgp_fsm_start(restart->fsm);
}

static void insert_local_on_session_up(const libbgp_event_t *event, void *ctx)
{
    session_up_insert_local_ctx_t *insert = (session_up_insert_local_ctx_t *)ctx;
    libbgp_prefix4_t prefix;

    if (event->type != LIBBGP_EVENT_SESSION_UP) {
        return;
    }
    insert->calls++;
    prefix = p4(10u, 0u, 0u, 0u, 24u);
    insert->insert_err = libbgp_rib4_insert_local(insert->rib, &prefix, ip4(192u, 0u, 2u, 254u), 100);
}

static void tick_on_first_route_added(const libbgp_event_t *event, void *ctx)
{
    tick_on_route_ctx_t *tick = (tick_on_route_ctx_t *)ctx;

    if (event->type != LIBBGP_EVENT_ROUTE_ADDED) {
        return;
    }
    tick->route_events++;
    if (tick->route_events == 1u) {
        tick->tick_err = libbgp_fsm_tick(tick->fsm, tick->now_ms);
    }
}

static void stop_on_first_route_added(const libbgp_event_t *event, void *ctx)
{
    stop_on_route_ctx_t *stop = (stop_on_route_ctx_t *)ctx;

    if (event->type != LIBBGP_EVENT_ROUTE_ADDED) {
        return;
    }
    stop->route_events++;
    if (stop->route_events == 1u) {
        stop->stop_err = libbgp_fsm_stop(stop->fsm);
    }
}

static void restart_on_first_route_withdrawn(const libbgp_event_t *event, void *ctx)
{
    restart_on_route_ctx_t *restart = (restart_on_route_ctx_t *)ctx;
    libbgp_packet_t open;
    libbgp_packet_t keepalive;

    if (event->type != LIBBGP_EVENT_ROUTE_WITHDRAWN) {
        return;
    }
    restart->route_events++;
    if (restart->route_events != 1u) {
        return;
    }
    open = make_open_packet(65010u, 45u, ip4(198u, 51u, 100u, 10u), true);
    keepalive = make_keepalive_packet();
    restart->stop_err = libbgp_fsm_stop(restart->fsm);
    restart->start_err = libbgp_fsm_start(restart->fsm);
    restart->open_err = libbgp_fsm_on_packet(restart->fsm, &open);
    restart->keepalive_err = libbgp_fsm_on_packet(restart->fsm, &keepalive);
    libbgp_packet_destroy(&keepalive);
    libbgp_packet_destroy(&open);
}

static void setup_out(libbgp_out_handler_t *handler, out_ctx_t *ctx)
{
    libbgp_io_ops_t ops;

    memset(ctx, 0, sizeof(*ctx));
    ops.send_fn = capture_send;
    ops.recv_fn = NULL;
    ops.ctx = ctx;
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_out_handler_init(handler));
    libbgp_out_handler_set_ops(handler, &ops);
}

static void set_out_send_fn(libbgp_out_handler_t *handler, libbgp_io_send_fn send_fn, void *ctx)
{
    libbgp_io_ops_t ops;

    ops.send_fn = send_fn;
    ops.recv_fn = NULL;
    ops.ctx = ctx;
    libbgp_out_handler_set_ops(handler, &ops);
}

static void assert_sent_notification(const out_ctx_t *out, size_t idx, uint8_t code, uint8_t subcode)
{
    libbgp_packet_t pkt;
    size_t used = 0u;

    LIBBGP_ASSERT(idx < out->count);
    libbgp_packet_init(&pkt);
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_packet_parse(&pkt, out->sent[idx].bytes, out->sent[idx].len, &used));
    LIBBGP_ASSERT_EQ_U64(out->sent[idx].len, used);
    LIBBGP_ASSERT_EQ_U64(LIBBGP_PACKET_NOTIFICATION, pkt.type);
    LIBBGP_ASSERT_EQ_U64(code, pkt.data.notification.err_code);
    LIBBGP_ASSERT_EQ_U64(subcode, pkt.data.notification.err_subcode);
    libbgp_packet_destroy(&pkt);
}

static libbgp_packet_t make_open_packet(uint32_t asn, uint16_t hold, uint32_t bgp_id, bool cap4)
{
    libbgp_packet_t pkt;

    libbgp_packet_init(&pkt);
    pkt.type = LIBBGP_PACKET_OPEN;
    libbgp_open_init(&pkt.data.open);
    pkt.data.open.version = 4u;
    pkt.data.open.my_asn = asn > 65535u ? LIBBGP_AS_TRANS : (uint16_t)asn;
    pkt.data.open.hold_time = hold;
    pkt.data.open.bgp_id = bgp_id;
    if (cap4) {
        libbgp_capability_t *cap = libbgp_capability_new(LIBBGP_CAP_4B_ASN);
        LIBBGP_ASSERT(cap != NULL);
        cap->data.asn_4b.asn = asn;
        LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_open_add_capability(&pkt.data.open, cap));
        libbgp_capability_unref(cap);
    }
    return pkt;
}

static libbgp_packet_t make_open_packet_with_mpbgp6(
    uint32_t asn,
    uint16_t hold,
    uint32_t bgp_id,
    bool cap4,
    bool mpbgp6)
{
    libbgp_packet_t pkt = make_open_packet(asn, hold, bgp_id, cap4);

    if (mpbgp6) {
        libbgp_capability_t *cap = libbgp_capability_new(LIBBGP_CAP_MP_BGP);

        LIBBGP_ASSERT(cap != NULL);
        cap->data.mp_bgp.afi = LIBBGP_AFI_IPV6;
        cap->data.mp_bgp.safi = LIBBGP_SAFI_UNICAST;
        LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_open_add_capability(&pkt.data.open, cap));
        libbgp_capability_unref(cap);
    }
    return pkt;
}

static libbgp_packet_t make_keepalive_packet(void)
{
    libbgp_packet_t pkt;

    libbgp_packet_init(&pkt);
    pkt.type = LIBBGP_PACKET_KEEPALIVE;
    return pkt;
}

static libbgp_packet_t make_notification_packet(uint8_t code, uint8_t subcode)
{
    libbgp_packet_t pkt;

    libbgp_packet_init(&pkt);
    pkt.type = LIBBGP_PACKET_NOTIFICATION;
    libbgp_notification_init(&pkt.data.notification);
    pkt.data.notification.err_code = code;
    pkt.data.notification.err_subcode = subcode;
    return pkt;
}

static libbgp_pattr_t *origin_attr(uint8_t origin)
{
    libbgp_pattr_t *attr = libbgp_pattr_new(LIBBGP_PATTR_ORIGIN);
    LIBBGP_ASSERT(attr != NULL);
    attr->data.origin.origin = origin;
    return attr;
}

static libbgp_pattr_t *next_hop_attr(uint32_t next_hop)
{
    libbgp_pattr_t *attr = libbgp_pattr_new(LIBBGP_PATTR_NEXT_HOP);
    LIBBGP_ASSERT(attr != NULL);
    attr->data.next_hop.next_hop = next_hop;
    return attr;
}

static libbgp_pattr_t *local_pref_attr(uint32_t local_pref)
{
    libbgp_pattr_t *attr = libbgp_pattr_new(LIBBGP_PATTR_LOCAL_PREF);
    LIBBGP_ASSERT(attr != NULL);
    attr->data.local_pref.value = local_pref;
    return attr;
}

static libbgp_pattr_t *med_attr(uint32_t med)
{
    libbgp_pattr_t *attr = libbgp_pattr_new(LIBBGP_PATTR_MED);
    LIBBGP_ASSERT(attr != NULL);
    attr->data.med.value = med;
    return attr;
}

static libbgp_pattr_t *as_path_attr(uint32_t asn)
{
    libbgp_pattr_t *attr = libbgp_pattr_new(LIBBGP_PATTR_AS_PATH);
    libbgp_as_path_segment_t *segment;
    uint32_t *asns;

    LIBBGP_ASSERT(attr != NULL);
    segment = (libbgp_as_path_segment_t *)calloc(1u, sizeof(*segment));
    asns = (uint32_t *)calloc(1u, sizeof(*asns));
    LIBBGP_ASSERT(segment != NULL);
    LIBBGP_ASSERT(asns != NULL);
    asns[0] = asn;
    segment->type = 2u;
    segment->asn_count = 1u;
    segment->asns = asns;
    attr->data.as_path.segments = segment;
    attr->data.as_path.segment_count = 1u;
    attr->data.as_path.is_4b = true;
    return attr;
}

static libbgp_packet_t make_update_add(libbgp_prefix4_t prefix, uint32_t next_hop)
{
    libbgp_packet_t pkt;
    libbgp_pattr_t *origin = origin_attr(0u);
    libbgp_pattr_t *path = as_path_attr(65010u);
    libbgp_pattr_t *nh = next_hop_attr(next_hop);
    libbgp_pattr_t *lp = local_pref_attr(200u);
    libbgp_pattr_t *med = med_attr(9u);

    libbgp_packet_init(&pkt);
    pkt.type = LIBBGP_PACKET_UPDATE;
    libbgp_update_init(&pkt.data.update);
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_update_add_attr(&pkt.data.update, origin));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_update_add_attr(&pkt.data.update, path));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_update_add_attr(&pkt.data.update, nh));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_update_add_attr(&pkt.data.update, lp));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_update_add_attr(&pkt.data.update, med));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_update_add_nlri(&pkt.data.update, &prefix));
    libbgp_pattr_unref(origin);
    libbgp_pattr_unref(path);
    libbgp_pattr_unref(nh);
    libbgp_pattr_unref(lp);
    libbgp_pattr_unref(med);
    return pkt;
}

static libbgp_packet_t make_update_add_with_attrs(
    libbgp_prefix4_t prefix,
    bool add_origin,
    bool add_as_path,
    bool add_next_hop)
{
    libbgp_packet_t pkt;

    libbgp_packet_init(&pkt);
    pkt.type = LIBBGP_PACKET_UPDATE;
    libbgp_update_init(&pkt.data.update);
    if (add_origin) {
        libbgp_pattr_t *origin = origin_attr(0u);

        LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_update_add_attr(&pkt.data.update, origin));
        libbgp_pattr_unref(origin);
    }
    if (add_as_path) {
        libbgp_pattr_t *path = as_path_attr(65010u);

        LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_update_add_attr(&pkt.data.update, path));
        libbgp_pattr_unref(path);
    }
    if (add_next_hop) {
        libbgp_pattr_t *nh = next_hop_attr(ip4(192u, 0u, 2u, 254u));

        LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_update_add_attr(&pkt.data.update, nh));
        libbgp_pattr_unref(nh);
    }
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_update_add_nlri(&pkt.data.update, &prefix));
    return pkt;
}

static libbgp_packet_t make_update_add_duplicate_attr(libbgp_prefix4_t prefix, libbgp_pattr_type_t duplicate_type)
{
    libbgp_packet_t pkt = make_update_add(prefix, ip4(192u, 0u, 2u, 254u));
    libbgp_pattr_t *dup = NULL;

    if (duplicate_type == LIBBGP_PATTR_ORIGIN) {
        dup = origin_attr(1u);
    } else if (duplicate_type == LIBBGP_PATTR_NEXT_HOP) {
        dup = next_hop_attr(ip4(192u, 0u, 2u, 253u));
    }
    LIBBGP_ASSERT(dup != NULL);
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_update_add_attr(&pkt.data.update, dup));
    libbgp_pattr_unref(dup);
    return pkt;
}

static libbgp_packet_t make_update_add_multi(const libbgp_prefix4_t *prefixes, size_t prefix_count, uint32_t next_hop)
{
    libbgp_packet_t pkt;
    libbgp_pattr_t *origin = origin_attr(0u);
    libbgp_pattr_t *path = as_path_attr(65010u);
    libbgp_pattr_t *nh = next_hop_attr(next_hop);
    libbgp_pattr_t *lp = local_pref_attr(200u);
    libbgp_pattr_t *med = med_attr(9u);
    size_t i;

    libbgp_packet_init(&pkt);
    pkt.type = LIBBGP_PACKET_UPDATE;
    libbgp_update_init(&pkt.data.update);
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_update_add_attr(&pkt.data.update, origin));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_update_add_attr(&pkt.data.update, path));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_update_add_attr(&pkt.data.update, nh));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_update_add_attr(&pkt.data.update, lp));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_update_add_attr(&pkt.data.update, med));
    for (i = 0u; i < prefix_count; i++) {
        LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_update_add_nlri(&pkt.data.update, &prefixes[i]));
    }
    libbgp_pattr_unref(origin);
    libbgp_pattr_unref(path);
    libbgp_pattr_unref(nh);
    libbgp_pattr_unref(lp);
    libbgp_pattr_unref(med);
    return pkt;
}

static libbgp_packet_t make_update_withdraw(libbgp_prefix4_t prefix)
{
    libbgp_packet_t pkt;

    libbgp_packet_init(&pkt);
    pkt.type = LIBBGP_PACKET_UPDATE;
    libbgp_update_init(&pkt.data.update);
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_update_add_withdrawn(&pkt.data.update, &prefix));
    return pkt;
}

static libbgp_packet_t make_update_mp_reach6(libbgp_prefix6_t prefix, const uint8_t next_hop[16])
{
    libbgp_packet_t pkt;
    libbgp_pattr_t *origin = origin_attr(0u);
    libbgp_pattr_t *path = as_path_attr(65010u);
    libbgp_pattr_t *lp = local_pref_attr(200u);
    libbgp_pattr_t *med = med_attr(9u);
    libbgp_pattr_t *mp = libbgp_pattr_new(LIBBGP_PATTR_MP_REACH_IPV6);

    LIBBGP_ASSERT(mp != NULL);
    libbgp_packet_init(&pkt);
    pkt.type = LIBBGP_PACKET_UPDATE;
    libbgp_update_init(&pkt.data.update);
    memcpy(mp->data.mp_reach_ipv6.nexthop, next_hop, 16u);
    mp->data.mp_reach_ipv6.nexthop_len = 16u;
    mp->data.mp_reach_ipv6.nlri = (libbgp_prefix6_t *)calloc(1u, sizeof(*mp->data.mp_reach_ipv6.nlri));
    LIBBGP_ASSERT(mp->data.mp_reach_ipv6.nlri != NULL);
    mp->data.mp_reach_ipv6.nlri[0] = prefix;
    mp->data.mp_reach_ipv6.nlri_count = 1u;
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_update_add_attr(&pkt.data.update, origin));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_update_add_attr(&pkt.data.update, path));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_update_add_attr(&pkt.data.update, lp));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_update_add_attr(&pkt.data.update, med));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_update_add_attr(&pkt.data.update, mp));
    libbgp_pattr_unref(origin);
    libbgp_pattr_unref(path);
    libbgp_pattr_unref(lp);
    libbgp_pattr_unref(med);
    libbgp_pattr_unref(mp);
    return pkt;
}

static libbgp_packet_t make_update_mp_reach6_multi(
    const libbgp_prefix6_t *prefixes,
    size_t prefix_count,
    const uint8_t next_hop[16])
{
    libbgp_packet_t pkt;
    libbgp_pattr_t *origin = origin_attr(0u);
    libbgp_pattr_t *path = as_path_attr(65010u);
    libbgp_pattr_t *lp = local_pref_attr(200u);
    libbgp_pattr_t *med = med_attr(9u);
    libbgp_pattr_t *mp = libbgp_pattr_new(LIBBGP_PATTR_MP_REACH_IPV6);
    size_t i;

    LIBBGP_ASSERT(mp != NULL);
    libbgp_packet_init(&pkt);
    pkt.type = LIBBGP_PACKET_UPDATE;
    libbgp_update_init(&pkt.data.update);
    memcpy(mp->data.mp_reach_ipv6.nexthop, next_hop, 16u);
    mp->data.mp_reach_ipv6.nexthop_len = 16u;
    if (prefix_count != 0u) {
        mp->data.mp_reach_ipv6.nlri =
            (libbgp_prefix6_t *)calloc(prefix_count, sizeof(*mp->data.mp_reach_ipv6.nlri));
        LIBBGP_ASSERT(mp->data.mp_reach_ipv6.nlri != NULL);
    }
    for (i = 0u; i < prefix_count; i++) {
        mp->data.mp_reach_ipv6.nlri[i] = prefixes[i];
    }
    mp->data.mp_reach_ipv6.nlri_count = prefix_count;
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_update_add_attr(&pkt.data.update, origin));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_update_add_attr(&pkt.data.update, path));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_update_add_attr(&pkt.data.update, lp));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_update_add_attr(&pkt.data.update, med));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_update_add_attr(&pkt.data.update, mp));
    libbgp_pattr_unref(origin);
    libbgp_pattr_unref(path);
    libbgp_pattr_unref(lp);
    libbgp_pattr_unref(med);
    libbgp_pattr_unref(mp);
    return pkt;
}

static libbgp_packet_t make_update_mp_reach6_with_attrs(
    libbgp_prefix6_t prefix,
    const uint8_t next_hop[16],
    bool add_origin,
    bool add_as_path)
{
    libbgp_packet_t pkt;
    libbgp_pattr_t *mp = libbgp_pattr_new(LIBBGP_PATTR_MP_REACH_IPV6);

    LIBBGP_ASSERT(mp != NULL);
    libbgp_packet_init(&pkt);
    pkt.type = LIBBGP_PACKET_UPDATE;
    libbgp_update_init(&pkt.data.update);
    memcpy(mp->data.mp_reach_ipv6.nexthop, next_hop, 16u);
    mp->data.mp_reach_ipv6.nexthop_len = 16u;
    mp->data.mp_reach_ipv6.nlri = (libbgp_prefix6_t *)calloc(1u, sizeof(*mp->data.mp_reach_ipv6.nlri));
    LIBBGP_ASSERT(mp->data.mp_reach_ipv6.nlri != NULL);
    mp->data.mp_reach_ipv6.nlri[0] = prefix;
    mp->data.mp_reach_ipv6.nlri_count = 1u;
    if (add_origin) {
        libbgp_pattr_t *origin = origin_attr(0u);

        LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_update_add_attr(&pkt.data.update, origin));
        libbgp_pattr_unref(origin);
    }
    if (add_as_path) {
        libbgp_pattr_t *path = as_path_attr(65010u);

        LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_update_add_attr(&pkt.data.update, path));
        libbgp_pattr_unref(path);
    }
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_update_add_attr(&pkt.data.update, mp));
    libbgp_pattr_unref(mp);
    return pkt;
}

static libbgp_packet_t make_update_add_then_invalid_mp_reach6(libbgp_prefix4_t prefix4, libbgp_prefix6_t prefix6)
{
    libbgp_packet_t pkt = make_update_add(prefix4, ip4(192u, 0u, 2u, 254u));
    libbgp_pattr_t *mp = libbgp_pattr_new(LIBBGP_PATTR_MP_REACH_IPV6);

    LIBBGP_ASSERT(mp != NULL);
    mp->data.mp_reach_ipv6.nexthop_len = 15u;
    mp->data.mp_reach_ipv6.nlri = (libbgp_prefix6_t *)calloc(1u, sizeof(*mp->data.mp_reach_ipv6.nlri));
    LIBBGP_ASSERT(mp->data.mp_reach_ipv6.nlri != NULL);
    mp->data.mp_reach_ipv6.nlri[0] = prefix6;
    mp->data.mp_reach_ipv6.nlri_count = 1u;
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_update_add_attr(&pkt.data.update, mp));
    libbgp_pattr_unref(mp);
    return pkt;
}

static libbgp_packet_t make_update_add_then_mp_reach6(
    libbgp_prefix4_t prefix4,
    libbgp_prefix6_t prefix6,
    const uint8_t next_hop6[16])
{
    libbgp_packet_t pkt = make_update_add(prefix4, ip4(192u, 0u, 2u, 254u));
    libbgp_pattr_t *mp = libbgp_pattr_new(LIBBGP_PATTR_MP_REACH_IPV6);

    LIBBGP_ASSERT(mp != NULL);
    memcpy(mp->data.mp_reach_ipv6.nexthop, next_hop6, 16u);
    mp->data.mp_reach_ipv6.nexthop_len = 16u;
    mp->data.mp_reach_ipv6.nlri = (libbgp_prefix6_t *)calloc(1u, sizeof(*mp->data.mp_reach_ipv6.nlri));
    LIBBGP_ASSERT(mp->data.mp_reach_ipv6.nlri != NULL);
    mp->data.mp_reach_ipv6.nlri[0] = prefix6;
    mp->data.mp_reach_ipv6.nlri_count = 1u;
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_update_add_attr(&pkt.data.update, mp));
    libbgp_pattr_unref(mp);
    return pkt;
}

static libbgp_packet_t make_update_withdraw4_unreach6_then_mp_reach6(
    libbgp_prefix4_t withdraw4,
    libbgp_prefix6_t withdraw6,
    libbgp_prefix6_t prefix6,
    const uint8_t next_hop6[16])
{
    libbgp_packet_t pkt;
    libbgp_pattr_t *origin = origin_attr(0u);
    libbgp_pattr_t *path = as_path_attr(65010u);
    libbgp_pattr_t *lp = local_pref_attr(200u);
    libbgp_pattr_t *med = med_attr(9u);
    libbgp_pattr_t *mp_unreach = libbgp_pattr_new(LIBBGP_PATTR_MP_UNREACH_IPV6);
    libbgp_pattr_t *mp_reach = libbgp_pattr_new(LIBBGP_PATTR_MP_REACH_IPV6);

    LIBBGP_ASSERT(mp_unreach != NULL);
    LIBBGP_ASSERT(mp_reach != NULL);
    libbgp_packet_init(&pkt);
    pkt.type = LIBBGP_PACKET_UPDATE;
    libbgp_update_init(&pkt.data.update);
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_update_add_withdrawn(&pkt.data.update, &withdraw4));
    mp_unreach->data.mp_unreach_ipv6.withdrawn =
        (libbgp_prefix6_t *)calloc(1u, sizeof(*mp_unreach->data.mp_unreach_ipv6.withdrawn));
    LIBBGP_ASSERT(mp_unreach->data.mp_unreach_ipv6.withdrawn != NULL);
    mp_unreach->data.mp_unreach_ipv6.withdrawn[0] = withdraw6;
    mp_unreach->data.mp_unreach_ipv6.withdrawn_count = 1u;
    memcpy(mp_reach->data.mp_reach_ipv6.nexthop, next_hop6, 16u);
    mp_reach->data.mp_reach_ipv6.nexthop_len = 16u;
    mp_reach->data.mp_reach_ipv6.nlri =
        (libbgp_prefix6_t *)calloc(1u, sizeof(*mp_reach->data.mp_reach_ipv6.nlri));
    LIBBGP_ASSERT(mp_reach->data.mp_reach_ipv6.nlri != NULL);
    mp_reach->data.mp_reach_ipv6.nlri[0] = prefix6;
    mp_reach->data.mp_reach_ipv6.nlri_count = 1u;
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_update_add_attr(&pkt.data.update, origin));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_update_add_attr(&pkt.data.update, path));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_update_add_attr(&pkt.data.update, lp));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_update_add_attr(&pkt.data.update, med));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_update_add_attr(&pkt.data.update, mp_unreach));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_update_add_attr(&pkt.data.update, mp_reach));
    libbgp_pattr_unref(origin);
    libbgp_pattr_unref(path);
    libbgp_pattr_unref(lp);
    libbgp_pattr_unref(med);
    libbgp_pattr_unref(mp_unreach);
    libbgp_pattr_unref(mp_reach);
    return pkt;
}

static libbgp_packet_t make_update_mp_unreach6(libbgp_prefix6_t prefix)
{
    libbgp_packet_t pkt;
    libbgp_pattr_t *mp = libbgp_pattr_new(LIBBGP_PATTR_MP_UNREACH_IPV6);

    LIBBGP_ASSERT(mp != NULL);
    libbgp_packet_init(&pkt);
    pkt.type = LIBBGP_PACKET_UPDATE;
    libbgp_update_init(&pkt.data.update);
    mp->data.mp_unreach_ipv6.withdrawn = (libbgp_prefix6_t *)calloc(1u, sizeof(*mp->data.mp_unreach_ipv6.withdrawn));
    LIBBGP_ASSERT(mp->data.mp_unreach_ipv6.withdrawn != NULL);
    mp->data.mp_unreach_ipv6.withdrawn[0] = prefix;
    mp->data.mp_unreach_ipv6.withdrawn_count = 1u;
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_update_add_attr(&pkt.data.update, mp));
    libbgp_pattr_unref(mp);
    return pkt;
}

static void establish(libbgp_fsm_t *fsm, out_ctx_t *out, event_ctx_t *events)
{
    libbgp_packet_t open = make_open_packet_with_mpbgp6(65010u, 45u, ip4(198u, 51u, 100u, 10u), true, true);
    libbgp_packet_t keepalive = make_keepalive_packet();

    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_fsm_start(fsm));
    LIBBGP_ASSERT_EQ_U64(1u, out->count);
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_fsm_on_packet(fsm, &open));
    LIBBGP_ASSERT_EQ_U64(2u, out->count);
    LIBBGP_ASSERT_EQ_U64(LIBBGP_PACKET_KEEPALIVE, out->sent[1].type);
    LIBBGP_ASSERT_EQ_U64(LIBBGP_FSM_OPEN_CONFIRM, libbgp_fsm_state(fsm));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_fsm_on_packet(fsm, &keepalive));
    LIBBGP_ASSERT_EQ_U64(LIBBGP_FSM_ESTABLISHED, libbgp_fsm_state(fsm));
    LIBBGP_ASSERT_EQ_U64(1u, events->count);
    LIBBGP_ASSERT_EQ_U64(LIBBGP_EVENT_SESSION_UP, events->types[0]);
    libbgp_packet_destroy(&keepalive);
    libbgp_packet_destroy(&open);
}

static void restart_and_replace_on_first_route_added(const libbgp_event_t *event, void *ctx)
{
    reentrant_replace_route_ctx_t *replace = (reentrant_replace_route_ctx_t *)ctx;
    libbgp_packet_t open;
    libbgp_packet_t keepalive;

    if (event->type != LIBBGP_EVENT_ROUTE_ADDED || replace->calls != 0u) {
        return;
    }
    replace->calls++;
    open = make_open_packet(65010u, 45u, ip4(198u, 51u, 100u, 10u), true);
    keepalive = make_keepalive_packet();
    replace->stop_err = libbgp_fsm_stop(replace->fsm);
    replace->start_err = libbgp_fsm_start(replace->fsm);
    replace->open_err = libbgp_fsm_on_packet(replace->fsm, &open);
    replace->keepalive_err = libbgp_fsm_on_packet(replace->fsm, &keepalive);
    replace->update_err = libbgp_fsm_on_packet(replace->fsm, replace->replacement);
    libbgp_packet_destroy(&keepalive);
    libbgp_packet_destroy(&open);
}

static void establish_with_peer_hold(libbgp_fsm_t *fsm, out_ctx_t *out, event_ctx_t *events, uint16_t hold_time)
{
    libbgp_packet_t open = make_open_packet_with_mpbgp6(65010u, hold_time, ip4(198u, 51u, 100u, 10u), true, true);
    libbgp_packet_t keepalive = make_keepalive_packet();

    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_fsm_start(fsm));
    LIBBGP_ASSERT_EQ_U64(1u, out->count);
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_fsm_on_packet(fsm, &open));
    LIBBGP_ASSERT_EQ_U64(2u, out->count);
    LIBBGP_ASSERT_EQ_U64(LIBBGP_FSM_OPEN_CONFIRM, libbgp_fsm_state(fsm));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_fsm_on_packet(fsm, &keepalive));
    LIBBGP_ASSERT_EQ_U64(LIBBGP_FSM_ESTABLISHED, libbgp_fsm_state(fsm));
    LIBBGP_ASSERT_EQ_U64(1u, events->count);
    LIBBGP_ASSERT_EQ_U64(LIBBGP_EVENT_SESSION_UP, events->types[0]);
    libbgp_packet_destroy(&keepalive);
    libbgp_packet_destroy(&open);
}

static void assert_invalid_update_no_route_effects(libbgp_packet_t *update, uint8_t expected_subcode)
{
    struct libbgp_fsm_config config;
    libbgp_fsm_t fsm;
    libbgp_out_handler_t out_handler;
    libbgp_event_bus_t bus;
    libbgp_rib4_t rib4;
    libbgp_rib6_t rib6;
    out_ctx_t out;
    event_ctx_t events;

    config.local_asn = 65000u;
    config.local_bgp_id = ip4(192u, 0u, 2u, 1u);
    config.hold_time = 3u;
    config.keepalive_time = 0u;
    config.enable_4byte_asn = true;
    config.enable_mpbgp_ipv6 = true;
    setup_out(&out_handler, &out);
    memset(&events, 0, sizeof(events));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_event_bus_init(&bus));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_event_bus_subscribe(&bus, LIBBGP_EVENT_SESSION_UP, event_capture, &events, NULL));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_event_bus_subscribe(&bus, LIBBGP_EVENT_SESSION_DOWN, event_capture, &events, NULL));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_event_bus_subscribe(&bus, LIBBGP_EVENT_ROUTE_ADDED, event_capture, &events, NULL));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_event_bus_subscribe(&bus, LIBBGP_EVENT_ROUTE_WITHDRAWN, event_capture, &events, NULL));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_rib4_init(&rib4));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_rib6_init(&rib6));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_fsm_init(&fsm, &config));
    libbgp_fsm_set_out_handler(&fsm, &out_handler);
    libbgp_fsm_set_event_bus(&fsm, &bus);
    libbgp_fsm_set_rib4(&fsm, &rib4);
    libbgp_fsm_set_rib6(&fsm, &rib6);
    establish(&fsm, &out, &events);

    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_fsm_tick(&fsm, 1000u));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_fsm_tick(&fsm, 3500u));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_INVALID, libbgp_fsm_on_packet(&fsm, update));
    LIBBGP_ASSERT_EQ_U64(LIBBGP_FSM_IDLE, libbgp_fsm_state(&fsm));
    LIBBGP_ASSERT_EQ_U64(0u, libbgp_rib4_route_count(&rib4));
    LIBBGP_ASSERT_EQ_U64(0u, libbgp_rib6_route_count(&rib6));
    LIBBGP_ASSERT_EQ_U64(2u, events.count);
    LIBBGP_ASSERT_EQ_U64(LIBBGP_EVENT_SESSION_UP, events.types[0]);
    LIBBGP_ASSERT_EQ_U64(LIBBGP_EVENT_SESSION_DOWN, events.types[1]);
    LIBBGP_ASSERT_EQ_U64(4u, out.count);
    assert_sent_notification(&out, 3u, 3u, expected_subcode);
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_fsm_tick(&fsm, 4501u));
    LIBBGP_ASSERT_EQ_U64(LIBBGP_FSM_IDLE, libbgp_fsm_state(&fsm));
    LIBBGP_ASSERT_EQ_U64(4u, out.count);
    LIBBGP_ASSERT_EQ_U64(2u, events.count);
    LIBBGP_ASSERT_EQ_U64(0u, libbgp_rib4_route_count(&rib4));
    LIBBGP_ASSERT_EQ_U64(0u, libbgp_rib6_route_count(&rib6));

    libbgp_fsm_destroy(&fsm);
    libbgp_rib6_destroy(&rib6);
    libbgp_rib4_destroy(&rib4);
    libbgp_event_bus_destroy(&bus);
    libbgp_out_handler_destroy(&out_handler);
}

LIBBGP_TEST(fsm_init_defaults_and_custom_config)
{
    struct libbgp_fsm_config config;
    libbgp_fsm_t fsm;

    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_fsm_init(&fsm, NULL));
    LIBBGP_ASSERT_EQ_U64(LIBBGP_FSM_IDLE, libbgp_fsm_state(&fsm));
    LIBBGP_ASSERT_EQ_U64(0u, libbgp_fsm_peer_asn(&fsm));
    libbgp_fsm_destroy(&fsm);

    config.local_asn = 65551u;
    config.local_bgp_id = ip4(192u, 0u, 2u, 1u);
    config.hold_time = 12u;
    config.keepalive_time = 4u;
    config.enable_4byte_asn = true;
    config.enable_mpbgp_ipv6 = true;
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_fsm_init(&fsm, &config));
    LIBBGP_ASSERT_EQ_U64(LIBBGP_FSM_IDLE, libbgp_fsm_state(&fsm));
    libbgp_fsm_destroy(&fsm);
}

LIBBGP_TEST(fsm_start_sends_open_and_moves_open_sent)
{
    struct libbgp_fsm_config config;
    libbgp_fsm_t fsm;
    libbgp_out_handler_t out_handler;
    out_ctx_t out;
    libbgp_packet_t sent;
    size_t used = 0u;

    config.local_asn = 65551u;
    config.local_bgp_id = ip4(192u, 0u, 2u, 1u);
    config.hold_time = 12u;
    config.keepalive_time = 4u;
    config.enable_4byte_asn = true;
    config.enable_mpbgp_ipv6 = true;
    setup_out(&out_handler, &out);
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_fsm_init(&fsm, &config));
    libbgp_fsm_set_out_handler(&fsm, &out_handler);

    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_fsm_start(&fsm));
    LIBBGP_ASSERT_EQ_U64(LIBBGP_FSM_OPEN_SENT, libbgp_fsm_state(&fsm));
    LIBBGP_ASSERT_EQ_U64(1u, out.count);
    LIBBGP_ASSERT_EQ_U64(LIBBGP_PACKET_OPEN, out.sent[0].type);
    libbgp_packet_init(&sent);
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_packet_parse(&sent, out.sent[0].bytes, out.sent[0].len, &used));
    LIBBGP_ASSERT_EQ_U64(4u, sent.data.open.version);
    LIBBGP_ASSERT_EQ_U64(LIBBGP_AS_TRANS, sent.data.open.my_asn);
    LIBBGP_ASSERT_EQ_U64(12u, sent.data.open.hold_time);
    LIBBGP_ASSERT_EQ_U64(ip4(192u, 0u, 2u, 1u), sent.data.open.bgp_id);
    LIBBGP_ASSERT_EQ_U64(65551u, libbgp_open_get_4b_asn(&sent.data.open));
    libbgp_packet_destroy(&sent);
    libbgp_fsm_destroy(&fsm);
    libbgp_out_handler_destroy(&out_handler);
}

LIBBGP_TEST(fsm_default_config_start_rejects_zero_local_bgp_id_without_sending)
{
    libbgp_fsm_t fsm;
    libbgp_out_handler_t out_handler;
    out_ctx_t out;

    setup_out(&out_handler, &out);
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_fsm_init(&fsm, NULL));
    libbgp_fsm_set_out_handler(&fsm, &out_handler);

    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_INVALID, libbgp_fsm_start(&fsm));
    LIBBGP_ASSERT_EQ_U64(LIBBGP_FSM_IDLE, libbgp_fsm_state(&fsm));
    LIBBGP_ASSERT_EQ_U64(0u, out.count);
    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_INVALID, libbgp_fsm_start(&fsm));
    LIBBGP_ASSERT_EQ_U64(LIBBGP_FSM_IDLE, libbgp_fsm_state(&fsm));
    LIBBGP_ASSERT_EQ_U64(0u, out.count);

    libbgp_fsm_destroy(&fsm);
    libbgp_out_handler_destroy(&out_handler);
}

LIBBGP_TEST(fsm_start_rejects_invalid_local_hold_time_without_sending)
{
    struct libbgp_fsm_config config = test_fsm_config();
    libbgp_fsm_t fsm;
    libbgp_out_handler_t out_handler;
    out_ctx_t out;

    setup_out(&out_handler, &out);
    config.hold_time = 1u;
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_fsm_init(&fsm, &config));
    libbgp_fsm_set_out_handler(&fsm, &out_handler);

    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_INVALID, libbgp_fsm_start(&fsm));
    LIBBGP_ASSERT_EQ_U64(LIBBGP_FSM_IDLE, libbgp_fsm_state(&fsm));
    LIBBGP_ASSERT_EQ_U64(0u, out.count);

    libbgp_fsm_destroy(&fsm);
    libbgp_out_handler_destroy(&out_handler);
}

LIBBGP_TEST(fsm_start_rejects_local_asn_truncation_without_sending)
{
    struct libbgp_fsm_config config = test_fsm_config();
    libbgp_fsm_t fsm;
    libbgp_out_handler_t out_handler;
    out_ctx_t out;

    setup_out(&out_handler, &out);
    config.local_asn = 65551u;
    config.enable_4byte_asn = false;
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_fsm_init(&fsm, &config));
    libbgp_fsm_set_out_handler(&fsm, &out_handler);

    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_INVALID, libbgp_fsm_start(&fsm));
    LIBBGP_ASSERT_EQ_U64(LIBBGP_FSM_IDLE, libbgp_fsm_state(&fsm));
    LIBBGP_ASSERT_EQ_U64(0u, out.count);

    libbgp_fsm_destroy(&fsm);
    libbgp_out_handler_destroy(&out_handler);
}

LIBBGP_TEST(fsm_default_config_open_sent_rejects_peer_open_without_sending)
{
    libbgp_fsm_t fsm;
    libbgp_out_handler_t out_handler;
    out_ctx_t out;
    libbgp_packet_t open = make_open_packet(65560u, 60u, ip4(203u, 0u, 113u, 9u), true);

    setup_out(&out_handler, &out);
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_fsm_init(&fsm, NULL));
    libbgp_fsm_set_out_handler(&fsm, &out_handler);
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_fsm_enter_active(&fsm));

    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_INVALID, libbgp_fsm_on_packet(&fsm, &open));
    LIBBGP_ASSERT_EQ_U64(LIBBGP_FSM_IDLE, libbgp_fsm_state(&fsm));
    LIBBGP_ASSERT_EQ_U64(0u, libbgp_fsm_peer_asn(&fsm));
    LIBBGP_ASSERT_EQ_U64(0u, libbgp_fsm_peer_bgp_id(&fsm));
    LIBBGP_ASSERT_EQ_U64(0u, out.count);

    libbgp_packet_destroy(&open);
    libbgp_fsm_destroy(&fsm);
    libbgp_out_handler_destroy(&out_handler);
}

LIBBGP_TEST(fsm_start_send_failure_leaves_idle_and_retryable)
{
    libbgp_fsm_t fsm;
    libbgp_out_handler_t out_handler;
    out_ctx_t out;

    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_out_handler_init(&out_handler));
    set_out_send_fn(&out_handler, fail_send, NULL);
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, init_test_fsm(&fsm));
    libbgp_fsm_set_out_handler(&fsm, &out_handler);

    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_WRITE, libbgp_fsm_start(&fsm));
    LIBBGP_ASSERT_EQ_U64(LIBBGP_FSM_IDLE, libbgp_fsm_state(&fsm));

    memset(&out, 0, sizeof(out));
    set_out_send_fn(&out_handler, capture_send, &out);
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_fsm_start(&fsm));
    LIBBGP_ASSERT_EQ_U64(LIBBGP_FSM_OPEN_SENT, libbgp_fsm_state(&fsm));
    LIBBGP_ASSERT_EQ_U64(1u, out.count);
    LIBBGP_ASSERT_EQ_U64(LIBBGP_PACKET_OPEN, out.sent[0].type);

    libbgp_fsm_destroy(&fsm);
    libbgp_out_handler_destroy(&out_handler);
}

LIBBGP_TEST(fsm_start_without_output_handler_returns_invalid_and_retryable)
{
    libbgp_fsm_t fsm;
    libbgp_out_handler_t out_handler;
    out_ctx_t out;

    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, init_test_fsm(&fsm));

    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_INVALID, libbgp_fsm_start(&fsm));
    LIBBGP_ASSERT_EQ_U64(LIBBGP_FSM_IDLE, libbgp_fsm_state(&fsm));

    setup_out(&out_handler, &out);
    libbgp_fsm_set_out_handler(&fsm, &out_handler);
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_fsm_start(&fsm));
    LIBBGP_ASSERT_EQ_U64(LIBBGP_FSM_OPEN_SENT, libbgp_fsm_state(&fsm));
    LIBBGP_ASSERT_EQ_U64(1u, out.count);
    LIBBGP_ASSERT_EQ_U64(LIBBGP_PACKET_OPEN, out.sent[0].type);

    libbgp_fsm_destroy(&fsm);
    libbgp_out_handler_destroy(&out_handler);
}

LIBBGP_TEST(fsm_start_zero_progress_short_send_rolls_back_to_idle)
{
    libbgp_fsm_t fsm;
    libbgp_out_handler_t out_handler;
    short_send_ctx_t short_send;

    memset(&short_send, 0, sizeof(short_send));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_out_handler_init(&out_handler));
    set_out_send_fn(&out_handler, zero_progress_send, &short_send);
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, init_test_fsm(&fsm));
    libbgp_fsm_set_out_handler(&fsm, &out_handler);

    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_WRITE, libbgp_fsm_start(&fsm));
    LIBBGP_ASSERT_EQ_U64(LIBBGP_FSM_IDLE, libbgp_fsm_state(&fsm));
    LIBBGP_ASSERT_EQ_U64(1u, short_send.calls);
    LIBBGP_ASSERT(short_send.len > 0u);

    libbgp_fsm_destroy(&fsm);
    libbgp_out_handler_destroy(&out_handler);
}

LIBBGP_TEST(fsm_start_reentrant_start_does_not_send_duplicate_open)
{
    libbgp_fsm_t fsm;
    libbgp_out_handler_t out_handler;
    reentrant_start_ctx_t reentrant;

    memset(&reentrant, 0, sizeof(reentrant));
    reentrant.fsm = &fsm;
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_out_handler_init(&out_handler));
    set_out_send_fn(&out_handler, reentrant_start_send, &reentrant);
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, init_test_fsm(&fsm));
    libbgp_fsm_set_out_handler(&fsm, &out_handler);

    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_fsm_start(&fsm));
    LIBBGP_ASSERT_EQ_U64(1u, reentrant.calls);
    LIBBGP_ASSERT_EQ_U64(1u, reentrant.out.count);
    LIBBGP_ASSERT_EQ_U64(LIBBGP_PACKET_OPEN, reentrant.out.sent[0].type);
    LIBBGP_ASSERT_EQ_U64(LIBBGP_FSM_OPEN_SENT, libbgp_fsm_state(&fsm));

    libbgp_fsm_destroy(&fsm);
    libbgp_out_handler_destroy(&out_handler);
}

LIBBGP_TEST(fsm_start_failed_send_does_not_rollback_reentrant_restart)
{
    libbgp_fsm_t fsm;
    libbgp_out_handler_t out_handler;
    reentrant_restart_fail_ctx_t reentrant;

    memset(&reentrant, 0, sizeof(reentrant));
    reentrant.fsm = &fsm;
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_out_handler_init(&out_handler));
    set_out_send_fn(&out_handler, reentrant_restart_then_fail_send, &reentrant);
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, init_test_fsm(&fsm));
    libbgp_fsm_set_out_handler(&fsm, &out_handler);

    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_WRITE, libbgp_fsm_start(&fsm));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, reentrant.stop_err);
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, reentrant.start_err);
    LIBBGP_ASSERT_EQ_U64(3u, reentrant.calls);
    LIBBGP_ASSERT_EQ_U64(3u, reentrant.out.count);
    LIBBGP_ASSERT_EQ_U64(LIBBGP_PACKET_OPEN, reentrant.out.sent[0].type);
    LIBBGP_ASSERT_EQ_U64(LIBBGP_PACKET_NOTIFICATION, reentrant.out.sent[1].type);
    LIBBGP_ASSERT_EQ_U64(LIBBGP_PACKET_OPEN, reentrant.out.sent[2].type);
    LIBBGP_ASSERT_EQ_U64(LIBBGP_FSM_OPEN_SENT, libbgp_fsm_state(&fsm));

    libbgp_fsm_destroy(&fsm);
    libbgp_out_handler_destroy(&out_handler);
}

LIBBGP_TEST(fsm_open_sent_accepts_open_records_peer_and_sends_keepalive)
{
    libbgp_fsm_t fsm;
    libbgp_out_handler_t out_handler;
    out_ctx_t out;
    libbgp_packet_t open = make_open_packet(65560u, 60u, ip4(203u, 0u, 113u, 9u), true);

    setup_out(&out_handler, &out);
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, init_test_fsm(&fsm));
    libbgp_fsm_set_out_handler(&fsm, &out_handler);
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_fsm_start(&fsm));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_fsm_on_packet(&fsm, &open));
    LIBBGP_ASSERT_EQ_U64(LIBBGP_FSM_OPEN_CONFIRM, libbgp_fsm_state(&fsm));
    LIBBGP_ASSERT_EQ_U64(65560u, libbgp_fsm_peer_asn(&fsm));
    LIBBGP_ASSERT_EQ_U64(ip4(203u, 0u, 113u, 9u), libbgp_fsm_peer_bgp_id(&fsm));
    LIBBGP_ASSERT_EQ_U64(2u, out.count);
    LIBBGP_ASSERT_EQ_U64(LIBBGP_PACKET_KEEPALIVE, out.sent[1].type);
    libbgp_packet_destroy(&open);
    libbgp_fsm_destroy(&fsm);
    libbgp_out_handler_destroy(&out_handler);
}

LIBBGP_TEST(fsm_open_sent_reentrant_keepalive_establishes)
{
    libbgp_fsm_t fsm;
    libbgp_out_handler_t out_handler;
    reentrant_packet_ctx_t reentrant;
    libbgp_packet_t open = make_open_packet(65560u, 60u, ip4(203u, 0u, 113u, 9u), true);
    libbgp_packet_t keepalive = make_keepalive_packet();

    memset(&reentrant, 0, sizeof(reentrant));
    reentrant.fsm = &fsm;
    reentrant.packet = &keepalive;
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_out_handler_init(&out_handler));
    set_out_send_fn(&out_handler, reentrant_packet_on_keepalive_send, &reentrant);
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, init_test_fsm(&fsm));
    libbgp_fsm_set_out_handler(&fsm, &out_handler);

    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_fsm_start(&fsm));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_fsm_on_packet(&fsm, &open));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, reentrant.packet_err);
    LIBBGP_ASSERT_EQ_U64(LIBBGP_FSM_ESTABLISHED, libbgp_fsm_state(&fsm));
    LIBBGP_ASSERT_EQ_U64(2u, reentrant.out.count);
    LIBBGP_ASSERT_EQ_U64(LIBBGP_PACKET_OPEN, reentrant.out.sent[0].type);
    LIBBGP_ASSERT_EQ_U64(LIBBGP_PACKET_KEEPALIVE, reentrant.out.sent[1].type);

    libbgp_packet_destroy(&keepalive);
    libbgp_packet_destroy(&open);
    libbgp_fsm_destroy(&fsm);
    libbgp_out_handler_destroy(&out_handler);
}

LIBBGP_TEST(fsm_open_sent_keepalive_send_failure_leaves_idle)
{
    libbgp_fsm_t fsm;
    libbgp_out_handler_t out_handler;
    fail_after_send_ctx_t fail_after;
    libbgp_packet_t open = make_open_packet(65560u, 60u, ip4(203u, 0u, 113u, 9u), true);

    memset(&fail_after, 0, sizeof(fail_after));
    fail_after.fail_on_call = 2u;
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_out_handler_init(&out_handler));
    set_out_send_fn(&out_handler, fail_after_send, &fail_after);
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, init_test_fsm(&fsm));
    libbgp_fsm_set_out_handler(&fsm, &out_handler);

    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_fsm_start(&fsm));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_WRITE, libbgp_fsm_on_packet(&fsm, &open));
    LIBBGP_ASSERT_EQ_U64(LIBBGP_FSM_IDLE, libbgp_fsm_state(&fsm));
    LIBBGP_ASSERT_EQ_U64(0u, libbgp_fsm_peer_asn(&fsm));
    LIBBGP_ASSERT_EQ_U64(0u, libbgp_fsm_peer_bgp_id(&fsm));
    LIBBGP_ASSERT_EQ_U64(1u, fail_after.out.count);
    LIBBGP_ASSERT_EQ_U64(LIBBGP_PACKET_OPEN, fail_after.out.sent[0].type);

    libbgp_packet_destroy(&open);
    libbgp_fsm_destroy(&fsm);
    libbgp_out_handler_destroy(&out_handler);
}

LIBBGP_TEST(fsm_open_sent_reentrant_keepalive_then_failed_keepalive_send_leaves_idle)
{
    libbgp_fsm_t fsm;
    libbgp_out_handler_t out_handler;
    libbgp_event_bus_t bus;
    libbgp_rib4_t rib4;
    reentrant_packet_fail_on_keepalive_ctx_t reentrant;
    event_ctx_t events;
    session_up_insert_local_ctx_t insert;
    libbgp_packet_t open = make_open_packet(65560u, 60u, ip4(203u, 0u, 113u, 9u), true);
    libbgp_packet_t keepalive = make_keepalive_packet();

    memset(&reentrant, 0, sizeof(reentrant));
    memset(&events, 0, sizeof(events));
    memset(&insert, 0, sizeof(insert));
    reentrant.fsm = &fsm;
    reentrant.packet = &keepalive;
    insert.rib = &rib4;
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_out_handler_init(&out_handler));
    set_out_send_fn(&out_handler, reentrant_packet_fail_on_keepalive_send, &reentrant);
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_event_bus_init(&bus));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_event_bus_subscribe(&bus, LIBBGP_EVENT_SESSION_UP, event_capture, &events, NULL));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_event_bus_subscribe(&bus, LIBBGP_EVENT_SESSION_DOWN, event_capture, &events, NULL));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_event_bus_subscribe(&bus, LIBBGP_EVENT_SESSION_UP, insert_local_on_session_up, &insert, NULL));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_rib4_init(&rib4));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, init_test_fsm(&fsm));
    libbgp_fsm_set_out_handler(&fsm, &out_handler);
    libbgp_fsm_set_event_bus(&fsm, &bus);
    libbgp_fsm_set_rib4(&fsm, &rib4);

    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_fsm_start(&fsm));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_WRITE, libbgp_fsm_on_packet(&fsm, &open));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, reentrant.packet_err);
    LIBBGP_ASSERT_EQ_U64(LIBBGP_FSM_IDLE, libbgp_fsm_state(&fsm));
    LIBBGP_ASSERT_EQ_U64(0u, libbgp_fsm_peer_asn(&fsm));
    LIBBGP_ASSERT_EQ_U64(0u, libbgp_fsm_peer_bgp_id(&fsm));
    LIBBGP_ASSERT_EQ_U64(0u, events.count);
    LIBBGP_ASSERT_EQ_U64(0u, insert.calls);
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, insert.insert_err);
    LIBBGP_ASSERT_EQ_U64(0u, libbgp_rib4_route_count(&rib4));
    LIBBGP_ASSERT_EQ_U64(2u, reentrant.out.count);
    LIBBGP_ASSERT_EQ_U64(LIBBGP_PACKET_OPEN, reentrant.out.sent[0].type);
    LIBBGP_ASSERT_EQ_U64(LIBBGP_PACKET_KEEPALIVE, reentrant.out.sent[1].type);

    libbgp_packet_destroy(&keepalive);
    libbgp_packet_destroy(&open);
    libbgp_fsm_destroy(&fsm);
    libbgp_rib4_destroy(&rib4);
    libbgp_event_bus_destroy(&bus);
    libbgp_out_handler_destroy(&out_handler);
}

LIBBGP_TEST(fsm_open_sent_failed_keepalive_does_not_rollback_reentrant_restart)
{
    libbgp_fsm_t fsm;
    libbgp_out_handler_t out_handler;
    reentrant_restart_on_keepalive_ctx_t reentrant;
    libbgp_packet_t open = make_open_packet(65560u, 60u, ip4(203u, 0u, 113u, 9u), true);

    memset(&reentrant, 0, sizeof(reentrant));
    reentrant.fsm = &fsm;
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_out_handler_init(&out_handler));
    set_out_send_fn(&out_handler, reentrant_restart_on_keepalive_send, &reentrant);
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, init_test_fsm(&fsm));
    libbgp_fsm_set_out_handler(&fsm, &out_handler);

    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_fsm_start(&fsm));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_WRITE, libbgp_fsm_on_packet(&fsm, &open));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, reentrant.stop_err);
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, reentrant.start_err);
    LIBBGP_ASSERT_EQ_U64(LIBBGP_FSM_OPEN_SENT, libbgp_fsm_state(&fsm));
    LIBBGP_ASSERT_EQ_U64(4u, reentrant.out.count);
    LIBBGP_ASSERT_EQ_U64(LIBBGP_PACKET_OPEN, reentrant.out.sent[0].type);
    LIBBGP_ASSERT_EQ_U64(LIBBGP_PACKET_KEEPALIVE, reentrant.out.sent[1].type);
    LIBBGP_ASSERT_EQ_U64(LIBBGP_PACKET_NOTIFICATION, reentrant.out.sent[2].type);
    LIBBGP_ASSERT_EQ_U64(LIBBGP_PACKET_OPEN, reentrant.out.sent[3].type);

    libbgp_packet_destroy(&open);
    libbgp_fsm_destroy(&fsm);
    libbgp_out_handler_destroy(&out_handler);
}

LIBBGP_TEST(fsm_enter_connect_then_start_sends_open)
{
    libbgp_fsm_t fsm;
    libbgp_out_handler_t out_handler;
    out_ctx_t out;

    setup_out(&out_handler, &out);
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, init_test_fsm(&fsm));
    libbgp_fsm_set_out_handler(&fsm, &out_handler);

    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_fsm_enter_connect(&fsm));
    LIBBGP_ASSERT_EQ_U64(LIBBGP_FSM_CONNECT, libbgp_fsm_state(&fsm));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_fsm_start(&fsm));
    LIBBGP_ASSERT_EQ_U64(LIBBGP_FSM_OPEN_SENT, libbgp_fsm_state(&fsm));
    LIBBGP_ASSERT_EQ_U64(1u, out.count);
    LIBBGP_ASSERT_EQ_U64(LIBBGP_PACKET_OPEN, out.sent[0].type);

    libbgp_fsm_destroy(&fsm);
    libbgp_out_handler_destroy(&out_handler);
}

LIBBGP_TEST(fsm_enter_active_then_start_sends_open)
{
    libbgp_fsm_t fsm;
    libbgp_out_handler_t out_handler;
    out_ctx_t out;

    setup_out(&out_handler, &out);
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, init_test_fsm(&fsm));
    libbgp_fsm_set_out_handler(&fsm, &out_handler);

    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_fsm_enter_active(&fsm));
    LIBBGP_ASSERT_EQ_U64(LIBBGP_FSM_ACTIVE, libbgp_fsm_state(&fsm));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_fsm_start(&fsm));
    LIBBGP_ASSERT_EQ_U64(LIBBGP_FSM_OPEN_SENT, libbgp_fsm_state(&fsm));
    LIBBGP_ASSERT_EQ_U64(1u, out.count);
    LIBBGP_ASSERT_EQ_U64(LIBBGP_PACKET_OPEN, out.sent[0].type);

    libbgp_fsm_destroy(&fsm);
    libbgp_out_handler_destroy(&out_handler);
}

LIBBGP_TEST(fsm_connect_open_sends_open_keepalive_and_can_establish)
{
    libbgp_fsm_t fsm;
    libbgp_out_handler_t out_handler;
    libbgp_event_bus_t bus;
    out_ctx_t out;
    event_ctx_t events;
    libbgp_packet_t open = make_open_packet(65560u, 60u, ip4(203u, 0u, 113u, 9u), true);
    libbgp_packet_t keepalive = make_keepalive_packet();

    setup_out(&out_handler, &out);
    memset(&events, 0, sizeof(events));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_event_bus_init(&bus));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_event_bus_subscribe(&bus, LIBBGP_EVENT_SESSION_UP, event_capture, &events, NULL));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, init_test_fsm(&fsm));
    libbgp_fsm_set_out_handler(&fsm, &out_handler);
    libbgp_fsm_set_event_bus(&fsm, &bus);
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_fsm_enter_connect(&fsm));

    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_fsm_on_packet(&fsm, &open));
    LIBBGP_ASSERT_EQ_U64(LIBBGP_FSM_OPEN_CONFIRM, libbgp_fsm_state(&fsm));
    LIBBGP_ASSERT_EQ_U64(2u, out.count);
    LIBBGP_ASSERT_EQ_U64(LIBBGP_PACKET_OPEN, out.sent[0].type);
    LIBBGP_ASSERT_EQ_U64(LIBBGP_PACKET_KEEPALIVE, out.sent[1].type);
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_fsm_on_packet(&fsm, &keepalive));
    LIBBGP_ASSERT_EQ_U64(LIBBGP_FSM_ESTABLISHED, libbgp_fsm_state(&fsm));
    LIBBGP_ASSERT_EQ_U64(1u, events.count);
    LIBBGP_ASSERT_EQ_U64(LIBBGP_EVENT_SESSION_UP, events.types[0]);

    libbgp_packet_destroy(&keepalive);
    libbgp_packet_destroy(&open);
    libbgp_fsm_destroy(&fsm);
    libbgp_event_bus_destroy(&bus);
    libbgp_out_handler_destroy(&out_handler);
}

LIBBGP_TEST(fsm_active_open_sends_open_keepalive_and_can_establish)
{
    libbgp_fsm_t fsm;
    libbgp_out_handler_t out_handler;
    libbgp_event_bus_t bus;
    out_ctx_t out;
    event_ctx_t events;
    libbgp_packet_t open = make_open_packet(65560u, 60u, ip4(203u, 0u, 113u, 9u), true);
    libbgp_packet_t keepalive = make_keepalive_packet();

    setup_out(&out_handler, &out);
    memset(&events, 0, sizeof(events));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_event_bus_init(&bus));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_event_bus_subscribe(&bus, LIBBGP_EVENT_SESSION_UP, event_capture, &events, NULL));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, init_test_fsm(&fsm));
    libbgp_fsm_set_out_handler(&fsm, &out_handler);
    libbgp_fsm_set_event_bus(&fsm, &bus);
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_fsm_enter_active(&fsm));

    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_fsm_on_packet(&fsm, &open));
    LIBBGP_ASSERT_EQ_U64(LIBBGP_FSM_OPEN_CONFIRM, libbgp_fsm_state(&fsm));
    LIBBGP_ASSERT_EQ_U64(2u, out.count);
    LIBBGP_ASSERT_EQ_U64(LIBBGP_PACKET_OPEN, out.sent[0].type);
    LIBBGP_ASSERT_EQ_U64(LIBBGP_PACKET_KEEPALIVE, out.sent[1].type);
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_fsm_on_packet(&fsm, &keepalive));
    LIBBGP_ASSERT_EQ_U64(LIBBGP_FSM_ESTABLISHED, libbgp_fsm_state(&fsm));
    LIBBGP_ASSERT_EQ_U64(1u, events.count);
    LIBBGP_ASSERT_EQ_U64(LIBBGP_EVENT_SESSION_UP, events.types[0]);

    libbgp_packet_destroy(&keepalive);
    libbgp_packet_destroy(&open);
    libbgp_fsm_destroy(&fsm);
    libbgp_event_bus_destroy(&bus);
    libbgp_out_handler_destroy(&out_handler);
}

LIBBGP_TEST(fsm_idle_open_sends_open_keepalive_and_can_establish)
{
    libbgp_fsm_t fsm;
    libbgp_out_handler_t out_handler;
    libbgp_event_bus_t bus;
    out_ctx_t out;
    event_ctx_t events;
    libbgp_packet_t open = make_open_packet(65560u, 60u, ip4(203u, 0u, 113u, 9u), true);
    libbgp_packet_t keepalive = make_keepalive_packet();

    setup_out(&out_handler, &out);
    memset(&events, 0, sizeof(events));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_event_bus_init(&bus));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_event_bus_subscribe(&bus, LIBBGP_EVENT_SESSION_UP, event_capture, &events, NULL));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, init_test_fsm(&fsm));
    libbgp_fsm_set_out_handler(&fsm, &out_handler);
    libbgp_fsm_set_event_bus(&fsm, &bus);

    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_fsm_on_packet(&fsm, &open));
    LIBBGP_ASSERT_EQ_U64(LIBBGP_FSM_OPEN_CONFIRM, libbgp_fsm_state(&fsm));
    LIBBGP_ASSERT_EQ_U64(2u, out.count);
    LIBBGP_ASSERT_EQ_U64(LIBBGP_PACKET_OPEN, out.sent[0].type);
    LIBBGP_ASSERT_EQ_U64(LIBBGP_PACKET_KEEPALIVE, out.sent[1].type);
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_fsm_on_packet(&fsm, &keepalive));
    LIBBGP_ASSERT_EQ_U64(LIBBGP_FSM_ESTABLISHED, libbgp_fsm_state(&fsm));
    LIBBGP_ASSERT_EQ_U64(1u, events.count);
    LIBBGP_ASSERT_EQ_U64(LIBBGP_EVENT_SESSION_UP, events.types[0]);

    libbgp_packet_destroy(&keepalive);
    libbgp_packet_destroy(&open);
    libbgp_fsm_destroy(&fsm);
    libbgp_event_bus_destroy(&bus);
    libbgp_out_handler_destroy(&out_handler);
}

LIBBGP_TEST(fsm_default_config_passive_open_rejects_zero_local_bgp_id_without_sending)
{
    libbgp_fsm_t fsm;
    libbgp_out_handler_t out_handler;
    out_ctx_t out;
    libbgp_packet_t open = make_open_packet(65560u, 60u, ip4(203u, 0u, 113u, 9u), true);

    setup_out(&out_handler, &out);
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_fsm_init(&fsm, NULL));
    libbgp_fsm_set_out_handler(&fsm, &out_handler);

    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_INVALID, libbgp_fsm_on_packet(&fsm, &open));
    LIBBGP_ASSERT_EQ_U64(LIBBGP_FSM_IDLE, libbgp_fsm_state(&fsm));
    LIBBGP_ASSERT_EQ_U64(0u, libbgp_fsm_peer_asn(&fsm));
    LIBBGP_ASSERT_EQ_U64(0u, libbgp_fsm_peer_bgp_id(&fsm));
    LIBBGP_ASSERT_EQ_U64(0u, out.count);

    libbgp_packet_destroy(&open);
    libbgp_fsm_destroy(&fsm);
    libbgp_out_handler_destroy(&out_handler);
}

LIBBGP_TEST(fsm_passive_open_rejects_invalid_local_hold_time_without_sending)
{
    struct libbgp_fsm_config config = test_fsm_config();
    libbgp_fsm_t fsm;
    libbgp_out_handler_t out_handler;
    out_ctx_t out;
    libbgp_packet_t open = make_open_packet(65560u, 60u, ip4(203u, 0u, 113u, 9u), true);

    setup_out(&out_handler, &out);
    config.hold_time = 1u;
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_fsm_init(&fsm, &config));
    libbgp_fsm_set_out_handler(&fsm, &out_handler);

    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_INVALID, libbgp_fsm_on_packet(&fsm, &open));
    LIBBGP_ASSERT_EQ_U64(LIBBGP_FSM_IDLE, libbgp_fsm_state(&fsm));
    LIBBGP_ASSERT_EQ_U64(0u, libbgp_fsm_peer_asn(&fsm));
    LIBBGP_ASSERT_EQ_U64(0u, libbgp_fsm_peer_bgp_id(&fsm));
    LIBBGP_ASSERT_EQ_U64(0u, out.count);

    libbgp_packet_destroy(&open);
    libbgp_fsm_destroy(&fsm);
    libbgp_out_handler_destroy(&out_handler);
}

LIBBGP_TEST(fsm_passive_open_rejects_local_asn_truncation_without_sending)
{
    struct libbgp_fsm_config config = test_fsm_config();
    libbgp_fsm_t fsm;
    libbgp_out_handler_t out_handler;
    out_ctx_t out;
    libbgp_packet_t open = make_open_packet(65560u, 60u, ip4(203u, 0u, 113u, 9u), true);

    setup_out(&out_handler, &out);
    config.local_asn = 65551u;
    config.enable_4byte_asn = false;
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_fsm_init(&fsm, &config));
    libbgp_fsm_set_out_handler(&fsm, &out_handler);

    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_INVALID, libbgp_fsm_on_packet(&fsm, &open));
    LIBBGP_ASSERT_EQ_U64(LIBBGP_FSM_IDLE, libbgp_fsm_state(&fsm));
    LIBBGP_ASSERT_EQ_U64(0u, libbgp_fsm_peer_asn(&fsm));
    LIBBGP_ASSERT_EQ_U64(0u, libbgp_fsm_peer_bgp_id(&fsm));
    LIBBGP_ASSERT_EQ_U64(0u, out.count);

    libbgp_packet_destroy(&open);
    libbgp_fsm_destroy(&fsm);
    libbgp_out_handler_destroy(&out_handler);
}

LIBBGP_TEST(fsm_idle_open_local_open_send_failure_leaves_idle)
{
    libbgp_fsm_t fsm;
    libbgp_out_handler_t out_handler;
    libbgp_packet_t open = make_open_packet(65560u, 60u, ip4(203u, 0u, 113u, 9u), true);

    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_out_handler_init(&out_handler));
    set_out_send_fn(&out_handler, fail_send, NULL);
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, init_test_fsm(&fsm));
    libbgp_fsm_set_out_handler(&fsm, &out_handler);

    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_WRITE, libbgp_fsm_on_packet(&fsm, &open));
    LIBBGP_ASSERT_EQ_U64(LIBBGP_FSM_IDLE, libbgp_fsm_state(&fsm));
    LIBBGP_ASSERT_EQ_U64(0u, libbgp_fsm_peer_asn(&fsm));
    LIBBGP_ASSERT_EQ_U64(0u, libbgp_fsm_peer_bgp_id(&fsm));

    libbgp_packet_destroy(&open);
    libbgp_fsm_destroy(&fsm);
    libbgp_out_handler_destroy(&out_handler);
}

LIBBGP_TEST(fsm_idle_open_keepalive_send_failure_leaves_idle)
{
    libbgp_fsm_t fsm;
    libbgp_out_handler_t out_handler;
    fail_after_send_ctx_t fail_after;
    libbgp_packet_t open = make_open_packet(65560u, 60u, ip4(203u, 0u, 113u, 9u), true);

    memset(&fail_after, 0, sizeof(fail_after));
    fail_after.fail_on_call = 2u;
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_out_handler_init(&out_handler));
    set_out_send_fn(&out_handler, fail_after_send, &fail_after);
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, init_test_fsm(&fsm));
    libbgp_fsm_set_out_handler(&fsm, &out_handler);

    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_WRITE, libbgp_fsm_on_packet(&fsm, &open));
    LIBBGP_ASSERT_EQ_U64(LIBBGP_FSM_IDLE, libbgp_fsm_state(&fsm));
    LIBBGP_ASSERT_EQ_U64(0u, libbgp_fsm_peer_asn(&fsm));
    LIBBGP_ASSERT_EQ_U64(0u, libbgp_fsm_peer_bgp_id(&fsm));
    LIBBGP_ASSERT_EQ_U64(1u, fail_after.out.count);
    LIBBGP_ASSERT_EQ_U64(LIBBGP_PACKET_OPEN, fail_after.out.sent[0].type);

    libbgp_packet_destroy(&open);
    libbgp_fsm_destroy(&fsm);
    libbgp_out_handler_destroy(&out_handler);
}

LIBBGP_TEST(fsm_passive_open_reentrant_open_does_not_duplicate_negotiation)
{
    libbgp_fsm_t fsm;
    libbgp_out_handler_t out_handler;
    reentrant_packet_ctx_t reentrant;
    libbgp_packet_t open = make_open_packet(65560u, 60u, ip4(203u, 0u, 113u, 9u), true);

    memset(&reentrant, 0, sizeof(reentrant));
    reentrant.fsm = &fsm;
    reentrant.packet = &open;
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_out_handler_init(&out_handler));
    set_out_send_fn(&out_handler, reentrant_packet_send, &reentrant);
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, init_test_fsm(&fsm));
    libbgp_fsm_set_out_handler(&fsm, &out_handler);

    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_fsm_on_packet(&fsm, &open));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, reentrant.packet_err);
    LIBBGP_ASSERT_EQ_U64(LIBBGP_FSM_OPEN_CONFIRM, libbgp_fsm_state(&fsm));
    LIBBGP_ASSERT_EQ_U64(2u, reentrant.out.count);
    LIBBGP_ASSERT_EQ_U64(LIBBGP_PACKET_OPEN, reentrant.out.sent[0].type);
    LIBBGP_ASSERT_EQ_U64(LIBBGP_PACKET_KEEPALIVE, reentrant.out.sent[1].type);

    libbgp_packet_destroy(&open);
    libbgp_fsm_destroy(&fsm);
    libbgp_out_handler_destroy(&out_handler);
}

LIBBGP_TEST(fsm_passive_open_reentrant_keepalive_establishes)
{
    libbgp_fsm_t fsm;
    libbgp_out_handler_t out_handler;
    reentrant_packet_ctx_t reentrant;
    libbgp_packet_t open = make_open_packet(65560u, 60u, ip4(203u, 0u, 113u, 9u), true);
    libbgp_packet_t keepalive = make_keepalive_packet();

    memset(&reentrant, 0, sizeof(reentrant));
    reentrant.fsm = &fsm;
    reentrant.packet = &keepalive;
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_out_handler_init(&out_handler));
    set_out_send_fn(&out_handler, reentrant_packet_on_keepalive_send, &reentrant);
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, init_test_fsm(&fsm));
    libbgp_fsm_set_out_handler(&fsm, &out_handler);

    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_fsm_on_packet(&fsm, &open));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, reentrant.packet_err);
    LIBBGP_ASSERT_EQ_U64(LIBBGP_FSM_ESTABLISHED, libbgp_fsm_state(&fsm));
    LIBBGP_ASSERT_EQ_U64(2u, reentrant.out.count);
    LIBBGP_ASSERT_EQ_U64(LIBBGP_PACKET_OPEN, reentrant.out.sent[0].type);
    LIBBGP_ASSERT_EQ_U64(LIBBGP_PACKET_KEEPALIVE, reentrant.out.sent[1].type);

    libbgp_packet_destroy(&keepalive);
    libbgp_packet_destroy(&open);
    libbgp_fsm_destroy(&fsm);
    libbgp_out_handler_destroy(&out_handler);
}

LIBBGP_TEST(fsm_passive_open_reentrant_keepalive_during_local_open_send_establishes)
{
    libbgp_fsm_t fsm;
    libbgp_out_handler_t out_handler;
    reentrant_packet_ctx_t reentrant;
    libbgp_packet_t open = make_open_packet(65560u, 60u, ip4(203u, 0u, 113u, 9u), true);
    libbgp_packet_t keepalive = make_keepalive_packet();

    memset(&reentrant, 0, sizeof(reentrant));
    reentrant.fsm = &fsm;
    reentrant.packet = &keepalive;
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_out_handler_init(&out_handler));
    set_out_send_fn(&out_handler, reentrant_packet_on_open_send, &reentrant);
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, init_test_fsm(&fsm));
    libbgp_fsm_set_out_handler(&fsm, &out_handler);

    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_fsm_on_packet(&fsm, &open));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, reentrant.packet_err);
    LIBBGP_ASSERT_EQ_U64(LIBBGP_FSM_ESTABLISHED, libbgp_fsm_state(&fsm));
    LIBBGP_ASSERT_EQ_U64(2u, reentrant.out.count);
    LIBBGP_ASSERT_EQ_U64(LIBBGP_PACKET_OPEN, reentrant.out.sent[0].type);
    LIBBGP_ASSERT_EQ_U64(LIBBGP_PACKET_KEEPALIVE, reentrant.out.sent[1].type);

    libbgp_packet_destroy(&keepalive);
    libbgp_packet_destroy(&open);
    libbgp_fsm_destroy(&fsm);
    libbgp_out_handler_destroy(&out_handler);
}

LIBBGP_TEST(fsm_passive_open_reentrant_keepalive_then_failed_keepalive_send_leaves_idle)
{
    libbgp_fsm_t fsm;
    libbgp_out_handler_t out_handler;
    libbgp_event_bus_t bus;
    reentrant_packet_fail_on_keepalive_ctx_t reentrant;
    event_ctx_t events;
    libbgp_packet_t open = make_open_packet(65560u, 60u, ip4(203u, 0u, 113u, 9u), true);
    libbgp_packet_t keepalive = make_keepalive_packet();

    memset(&reentrant, 0, sizeof(reentrant));
    memset(&events, 0, sizeof(events));
    reentrant.fsm = &fsm;
    reentrant.packet = &keepalive;
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_out_handler_init(&out_handler));
    set_out_send_fn(&out_handler, reentrant_packet_fail_on_keepalive_send, &reentrant);
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_event_bus_init(&bus));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_event_bus_subscribe(&bus, LIBBGP_EVENT_SESSION_UP, event_capture, &events, NULL));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_event_bus_subscribe(&bus, LIBBGP_EVENT_SESSION_DOWN, event_capture, &events, NULL));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, init_test_fsm(&fsm));
    libbgp_fsm_set_out_handler(&fsm, &out_handler);
    libbgp_fsm_set_event_bus(&fsm, &bus);

    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_WRITE, libbgp_fsm_on_packet(&fsm, &open));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, reentrant.packet_err);
    LIBBGP_ASSERT_EQ_U64(LIBBGP_FSM_IDLE, libbgp_fsm_state(&fsm));
    LIBBGP_ASSERT_EQ_U64(0u, libbgp_fsm_peer_asn(&fsm));
    LIBBGP_ASSERT_EQ_U64(0u, libbgp_fsm_peer_bgp_id(&fsm));
    LIBBGP_ASSERT_EQ_U64(0u, events.count);
    LIBBGP_ASSERT_EQ_U64(2u, reentrant.out.count);
    LIBBGP_ASSERT_EQ_U64(LIBBGP_PACKET_OPEN, reentrant.out.sent[0].type);
    LIBBGP_ASSERT_EQ_U64(LIBBGP_PACKET_KEEPALIVE, reentrant.out.sent[1].type);

    libbgp_packet_destroy(&keepalive);
    libbgp_packet_destroy(&open);
    libbgp_fsm_destroy(&fsm);
    libbgp_event_bus_destroy(&bus);
    libbgp_out_handler_destroy(&out_handler);
}

LIBBGP_TEST(fsm_passive_open_reentrant_invalid_open_prevents_stale_promotion)
{
    libbgp_fsm_t fsm;
    libbgp_out_handler_t out_handler;
    reentrant_packet_ctx_t reentrant;
    libbgp_packet_t valid = make_open_packet(65560u, 60u, ip4(203u, 0u, 113u, 9u), true);
    libbgp_packet_t invalid = make_open_packet(65560u, 60u, 0u, true);

    memset(&reentrant, 0, sizeof(reentrant));
    reentrant.fsm = &fsm;
    reentrant.packet = &invalid;
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_out_handler_init(&out_handler));
    set_out_send_fn(&out_handler, reentrant_packet_send, &reentrant);
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, init_test_fsm(&fsm));
    libbgp_fsm_set_out_handler(&fsm, &out_handler);

    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_fsm_on_packet(&fsm, &valid));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_INVALID, reentrant.packet_err);
    LIBBGP_ASSERT_EQ_U64(LIBBGP_FSM_IDLE, libbgp_fsm_state(&fsm));
    LIBBGP_ASSERT_EQ_U64(0u, libbgp_fsm_peer_asn(&fsm));
    LIBBGP_ASSERT_EQ_U64(0u, libbgp_fsm_peer_bgp_id(&fsm));
    LIBBGP_ASSERT_EQ_U64(2u, reentrant.out.count);
    LIBBGP_ASSERT_EQ_U64(LIBBGP_PACKET_OPEN, reentrant.out.sent[0].type);
    LIBBGP_ASSERT_EQ_U64(LIBBGP_PACKET_NOTIFICATION, reentrant.out.sent[1].type);

    libbgp_packet_destroy(&invalid);
    libbgp_packet_destroy(&valid);
    libbgp_fsm_destroy(&fsm);
    libbgp_out_handler_destroy(&out_handler);
}

LIBBGP_TEST(fsm_passive_open_failed_send_does_not_rollback_reentrant_restart)
{
    libbgp_fsm_t fsm;
    libbgp_out_handler_t out_handler;
    reentrant_restart_fail_ctx_t reentrant;
    libbgp_packet_t open = make_open_packet(65560u, 60u, ip4(203u, 0u, 113u, 9u), true);

    memset(&reentrant, 0, sizeof(reentrant));
    reentrant.fsm = &fsm;
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_out_handler_init(&out_handler));
    set_out_send_fn(&out_handler, reentrant_restart_then_fail_send, &reentrant);
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, init_test_fsm(&fsm));
    libbgp_fsm_set_out_handler(&fsm, &out_handler);

    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_WRITE, libbgp_fsm_on_packet(&fsm, &open));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, reentrant.stop_err);
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, reentrant.start_err);
    LIBBGP_ASSERT_EQ_U64(LIBBGP_FSM_OPEN_SENT, libbgp_fsm_state(&fsm));
    LIBBGP_ASSERT_EQ_U64(3u, reentrant.out.count);
    LIBBGP_ASSERT_EQ_U64(LIBBGP_PACKET_OPEN, reentrant.out.sent[0].type);
    LIBBGP_ASSERT_EQ_U64(LIBBGP_PACKET_NOTIFICATION, reentrant.out.sent[1].type);
    LIBBGP_ASSERT_EQ_U64(LIBBGP_PACKET_OPEN, reentrant.out.sent[2].type);

    libbgp_packet_destroy(&open);
    libbgp_fsm_destroy(&fsm);
    libbgp_out_handler_destroy(&out_handler);
}

static void assert_open_sent_rejects_invalid_open(
    libbgp_packet_t *open,
    libbgp_err_t expected_err,
    uint8_t expected_code,
    uint8_t expected_subcode)
{
    libbgp_fsm_t fsm;
    libbgp_out_handler_t out_handler;
    out_ctx_t out;

    setup_out(&out_handler, &out);
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, init_test_fsm(&fsm));
    libbgp_fsm_set_out_handler(&fsm, &out_handler);
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_fsm_start(&fsm));

    LIBBGP_ASSERT_EQ_I64(expected_err, libbgp_fsm_on_packet(&fsm, open));
    LIBBGP_ASSERT_EQ_U64(LIBBGP_FSM_IDLE, libbgp_fsm_state(&fsm));
    LIBBGP_ASSERT_EQ_U64(0u, libbgp_fsm_peer_asn(&fsm));
    LIBBGP_ASSERT_EQ_U64(0u, libbgp_fsm_peer_bgp_id(&fsm));
    LIBBGP_ASSERT_EQ_U64(2u, out.count);
    assert_sent_notification(&out, 1u, expected_code, expected_subcode);

    libbgp_fsm_destroy(&fsm);
    libbgp_out_handler_destroy(&out_handler);
}

LIBBGP_TEST(fsm_open_sent_rejects_invalid_open_version_with_open_error)
{
    libbgp_packet_t open = make_open_packet(65010u, 3u, ip4(203u, 0u, 113u, 9u), true);

    open.data.open.version = 3u;
    assert_open_sent_rejects_invalid_open(&open, LIBBGP_ERR_BAD_LEN, 2u, 1u);
    libbgp_packet_destroy(&open);
}

LIBBGP_TEST(fsm_packet_parse_open_v3_then_fsm_sends_open_error)
{
    const uint8_t open_v3[] = {
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0x00, 0x1d, 0x01,
        0x03, 0xfd, 0xe8, 0x00, 0x5a, 0xcb, 0x00, 0x71, 0x01, 0x00
    };
    libbgp_fsm_t fsm;
    libbgp_out_handler_t out_handler;
    out_ctx_t out;
    libbgp_packet_t pkt;
    size_t used = 0u;

    setup_out(&out_handler, &out);
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, init_test_fsm(&fsm));
    libbgp_fsm_set_out_handler(&fsm, &out_handler);
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_fsm_start(&fsm));
    libbgp_packet_init(&pkt);
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_packet_parse(&pkt, open_v3, sizeof(open_v3), &used));
    LIBBGP_ASSERT_EQ_U64(sizeof(open_v3), used);

    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_BAD_LEN, libbgp_fsm_on_packet(&fsm, &pkt));
    LIBBGP_ASSERT_EQ_U64(LIBBGP_FSM_IDLE, libbgp_fsm_state(&fsm));
    LIBBGP_ASSERT_EQ_U64(0u, libbgp_fsm_peer_asn(&fsm));
    LIBBGP_ASSERT_EQ_U64(0u, libbgp_fsm_peer_bgp_id(&fsm));
    LIBBGP_ASSERT_EQ_U64(2u, out.count);
    assert_sent_notification(&out, 1u, 2u, 1u);

    libbgp_packet_destroy(&pkt);
    libbgp_fsm_destroy(&fsm);
    libbgp_out_handler_destroy(&out_handler);
}

LIBBGP_TEST(fsm_open_sent_rejects_invalid_open_hold_time)
{
    libbgp_packet_t open = make_open_packet(65010u, 1u, ip4(203u, 0u, 113u, 9u), true);

    assert_open_sent_rejects_invalid_open(&open, LIBBGP_ERR_INVALID, 2u, 6u);
    open.data.open.hold_time = 2u;
    assert_open_sent_rejects_invalid_open(&open, LIBBGP_ERR_INVALID, 2u, 6u);
    libbgp_packet_destroy(&open);
}

LIBBGP_TEST(fsm_open_sent_rejects_invalid_open_bgp_id)
{
    libbgp_packet_t open = make_open_packet(65010u, 3u, 0u, true);

    assert_open_sent_rejects_invalid_open(&open, LIBBGP_ERR_INVALID, 2u, 3u);
    libbgp_packet_destroy(&open);
}

LIBBGP_TEST(fsm_open_confirm_keepalive_establishes_and_events)
{
    libbgp_fsm_t fsm;
    libbgp_out_handler_t out_handler;
    libbgp_event_bus_t bus;
    out_ctx_t out;
    event_ctx_t events;

    setup_out(&out_handler, &out);
    memset(&events, 0, sizeof(events));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_event_bus_init(&bus));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_event_bus_subscribe(&bus, LIBBGP_EVENT_SESSION_UP, event_capture, &events, NULL));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, init_test_fsm(&fsm));
    libbgp_fsm_set_out_handler(&fsm, &out_handler);
    libbgp_fsm_set_event_bus(&fsm, &bus);
    establish(&fsm, &out, &events);

    libbgp_fsm_destroy(&fsm);
    libbgp_event_bus_destroy(&bus);
    libbgp_out_handler_destroy(&out_handler);
}

LIBBGP_TEST(fsm_open_confirm_unexpected_packet_sends_fsm_error)
{
    libbgp_fsm_t fsm;
    libbgp_out_handler_t out_handler;
    out_ctx_t out;
    event_ctx_t events;
    libbgp_packet_t update;

    setup_out(&out_handler, &out);
    memset(&events, 0, sizeof(events));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, init_test_fsm(&fsm));
    libbgp_fsm_set_out_handler(&fsm, &out_handler);
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_fsm_start(&fsm));
    {
        libbgp_packet_t open = make_open_packet(65010u, 45u, ip4(198u, 51u, 100u, 10u), true);
        LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_fsm_on_packet(&fsm, &open));
        libbgp_packet_destroy(&open);
    }
    libbgp_packet_init(&update);
    update.type = LIBBGP_PACKET_UPDATE;
    libbgp_update_init(&update.data.update);

    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_BAD_TYPE, libbgp_fsm_on_packet(&fsm, &update));
    LIBBGP_ASSERT_EQ_U64(LIBBGP_FSM_IDLE, libbgp_fsm_state(&fsm));
    LIBBGP_ASSERT_EQ_U64(3u, out.count);
    assert_sent_notification(&out, 2u, 5u, 2u);

    libbgp_packet_destroy(&update);
    libbgp_fsm_destroy(&fsm);
    libbgp_out_handler_destroy(&out_handler);
}

LIBBGP_TEST(fsm_open_confirm_notification_clears_peer_state_without_session_down)
{
    struct libbgp_fsm_config config;
    libbgp_fsm_t fsm;
    libbgp_out_handler_t out_handler;
    libbgp_event_bus_t bus;
    out_ctx_t out;
    event_ctx_t events;
    libbgp_packet_t open = make_open_packet(65010u, 45u, ip4(198u, 51u, 100u, 10u), true);
    libbgp_packet_t notification = make_notification_packet(6u, 2u);

    config.local_asn = 65000u;
    config.local_bgp_id = ip4(192u, 0u, 2u, 1u);
    config.hold_time = 30u;
    config.keepalive_time = 10u;
    config.enable_4byte_asn = true;
    config.enable_mpbgp_ipv6 = true;
    setup_out(&out_handler, &out);
    memset(&events, 0, sizeof(events));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_event_bus_init(&bus));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_event_bus_subscribe(&bus, LIBBGP_EVENT_SESSION_DOWN, event_capture, &events, NULL));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_fsm_init(&fsm, &config));
    libbgp_fsm_set_out_handler(&fsm, &out_handler);
    libbgp_fsm_set_event_bus(&fsm, &bus);

    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_fsm_start(&fsm));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_fsm_on_packet(&fsm, &open));
    LIBBGP_ASSERT_EQ_U64(LIBBGP_FSM_OPEN_CONFIRM, libbgp_fsm_state(&fsm));
    LIBBGP_ASSERT_EQ_U64(65010u, libbgp_fsm_peer_asn(&fsm));
    LIBBGP_ASSERT_EQ_U64(ip4(198u, 51u, 100u, 10u), libbgp_fsm_peer_bgp_id(&fsm));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_fsm_tick(&fsm, 1000u));

    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_fsm_on_packet(&fsm, &notification));
    LIBBGP_ASSERT_EQ_U64(LIBBGP_FSM_IDLE, libbgp_fsm_state(&fsm));
    LIBBGP_ASSERT_EQ_U64(0u, libbgp_fsm_peer_asn(&fsm));
    LIBBGP_ASSERT_EQ_U64(0u, libbgp_fsm_peer_bgp_id(&fsm));
    LIBBGP_ASSERT_EQ_U64(0u, events.count);
    LIBBGP_ASSERT_EQ_U64(2u, out.count);
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_fsm_tick(&fsm, 45000u));
    LIBBGP_ASSERT_EQ_U64(LIBBGP_FSM_IDLE, libbgp_fsm_state(&fsm));
    LIBBGP_ASSERT_EQ_U64(2u, out.count);

    libbgp_packet_destroy(&notification);
    libbgp_packet_destroy(&open);
    libbgp_fsm_destroy(&fsm);
    libbgp_event_bus_destroy(&bus);
    libbgp_out_handler_destroy(&out_handler);
}

LIBBGP_TEST(fsm_established_keepalive_stays_established)
{
    libbgp_fsm_t fsm;
    libbgp_out_handler_t out_handler;
    libbgp_event_bus_t bus;
    out_ctx_t out;
    event_ctx_t events;
    libbgp_packet_t keepalive = make_keepalive_packet();

    setup_out(&out_handler, &out);
    memset(&events, 0, sizeof(events));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_event_bus_init(&bus));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_event_bus_subscribe(&bus, LIBBGP_EVENT_SESSION_UP, event_capture, &events, NULL));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, init_test_fsm(&fsm));
    libbgp_fsm_set_out_handler(&fsm, &out_handler);
    libbgp_fsm_set_event_bus(&fsm, &bus);
    establish(&fsm, &out, &events);

    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_fsm_on_packet(&fsm, &keepalive));
    LIBBGP_ASSERT_EQ_U64(LIBBGP_FSM_ESTABLISHED, libbgp_fsm_state(&fsm));
    libbgp_packet_destroy(&keepalive);
    libbgp_fsm_destroy(&fsm);
    libbgp_event_bus_destroy(&bus);
    libbgp_out_handler_destroy(&out_handler);
}

LIBBGP_TEST(fsm_established_update_adds_route_and_event)
{
    libbgp_fsm_t fsm;
    libbgp_out_handler_t out_handler;
    libbgp_event_bus_t bus;
    libbgp_rib4_t rib;
    out_ctx_t out;
    event_ctx_t events;
    libbgp_prefix4_t prefix = p4(203u, 0u, 113u, 0u, 24u);
    libbgp_packet_t update = make_update_add(prefix, ip4(192u, 0u, 2u, 254u));
    const libbgp_rib4_route_t *route = NULL;

    setup_out(&out_handler, &out);
    memset(&events, 0, sizeof(events));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_event_bus_init(&bus));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_event_bus_subscribe(&bus, LIBBGP_EVENT_SESSION_UP, event_capture, &events, NULL));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_event_bus_subscribe(&bus, LIBBGP_EVENT_ROUTE_ADDED, event_capture, &events, NULL));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_rib4_init(&rib));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, init_test_fsm(&fsm));
    libbgp_fsm_set_out_handler(&fsm, &out_handler);
    libbgp_fsm_set_event_bus(&fsm, &bus);
    libbgp_fsm_set_rib4(&fsm, &rib);
    establish(&fsm, &out, &events);

    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_fsm_on_packet(&fsm, &update));
    LIBBGP_ASSERT_EQ_U64(2u, events.count);
    LIBBGP_ASSERT_EQ_U64(LIBBGP_EVENT_ROUTE_ADDED, events.types[1]);
    LIBBGP_ASSERT(libbgp_prefix4_eq(&prefix, &events.prefixes[1]));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_rib4_lookup_scoped(&rib, ip4(198u, 51u, 100u, 10u), ip4(203u, 0u, 113u, 44u), &route));
    LIBBGP_ASSERT_EQ_U64(ip4(192u, 0u, 2u, 254u), route->next_hop);
    LIBBGP_ASSERT_EQ_U64(200u, route->local_pref);
    LIBBGP_ASSERT_EQ_U64(9u, route->med);
    LIBBGP_ASSERT_EQ_U64(1u, route->as_path_len);
    LIBBGP_ASSERT_EQ_U64(65010u, route->origin_as);

    libbgp_packet_destroy(&update);
    libbgp_fsm_destroy(&fsm);
    libbgp_rib4_destroy(&rib);
    libbgp_event_bus_destroy(&bus);
    libbgp_out_handler_destroy(&out_handler);
}

LIBBGP_TEST(fsm_established_update_after_teardown_discards_late_routes)
{
    libbgp_fsm_t fsm;
    libbgp_out_handler_t out_handler;
    libbgp_event_bus_t bus;
    libbgp_rib4_t rib;
    out_ctx_t out;
    event_ctx_t events;
    stop_on_route_ctx_t stop;
    libbgp_prefix4_t prefixes[2];
    libbgp_packet_t update;

    prefixes[0] = p4(203u, 0u, 113u, 0u, 24u);
    prefixes[1] = p4(198u, 51u, 100u, 0u, 24u);
    update = make_update_add_multi(prefixes, LIBBGP_ARRAY_LEN(prefixes), ip4(192u, 0u, 2u, 254u));
    setup_out(&out_handler, &out);
    memset(&events, 0, sizeof(events));
    memset(&stop, 0, sizeof(stop));
    stop.fsm = &fsm;
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_event_bus_init(&bus));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_event_bus_subscribe(&bus, LIBBGP_EVENT_SESSION_UP, event_capture, &events, NULL));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_event_bus_subscribe(&bus, LIBBGP_EVENT_SESSION_DOWN, event_capture, &events, NULL));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_event_bus_subscribe(&bus, LIBBGP_EVENT_ROUTE_ADDED, stop_on_first_route_added, &stop, NULL));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_rib4_init(&rib));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, init_test_fsm(&fsm));
    libbgp_fsm_set_out_handler(&fsm, &out_handler);
    libbgp_fsm_set_event_bus(&fsm, &bus);
    libbgp_fsm_set_rib4(&fsm, &rib);
    establish(&fsm, &out, &events);

    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_fsm_on_packet(&fsm, &update));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, stop.stop_err);
    LIBBGP_ASSERT_EQ_U64(1u, stop.route_events);
    LIBBGP_ASSERT_EQ_U64(LIBBGP_FSM_IDLE, libbgp_fsm_state(&fsm));
    LIBBGP_ASSERT_EQ_U64(0u, libbgp_rib4_route_count(&rib));
    LIBBGP_ASSERT_EQ_U64(2u, events.count);
    LIBBGP_ASSERT_EQ_U64(LIBBGP_EVENT_SESSION_DOWN, events.types[1]);

    libbgp_packet_destroy(&update);
    libbgp_fsm_destroy(&fsm);
    libbgp_rib4_destroy(&rib);
    libbgp_event_bus_destroy(&bus);
    libbgp_out_handler_destroy(&out_handler);
}

LIBBGP_TEST(fsm_accepted_update_refreshes_hold_timer_before_route_event)
{
    struct libbgp_fsm_config config;
    libbgp_fsm_t fsm;
    libbgp_out_handler_t out_handler;
    libbgp_event_bus_t bus;
    libbgp_rib4_t rib;
    out_ctx_t out;
    event_ctx_t events;
    tick_on_route_ctx_t tick;
    libbgp_prefix4_t prefix = p4(203u, 0u, 113u, 0u, 24u);
    libbgp_packet_t update = make_update_add(prefix, ip4(192u, 0u, 2u, 254u));
    const libbgp_rib4_route_t *route = NULL;

    config = test_fsm_config();
    config.hold_time = 3u;
    config.keepalive_time = 0u;
    setup_out(&out_handler, &out);
    memset(&events, 0, sizeof(events));
    memset(&tick, 0, sizeof(tick));
    tick.fsm = &fsm;
    tick.now_ms = 4501u;
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_event_bus_init(&bus));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_event_bus_subscribe(&bus, LIBBGP_EVENT_SESSION_UP, event_capture, &events, NULL));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_event_bus_subscribe(&bus, LIBBGP_EVENT_SESSION_DOWN, event_capture, &events, NULL));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_event_bus_subscribe(&bus, LIBBGP_EVENT_ROUTE_ADDED, tick_on_first_route_added, &tick, NULL));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_rib4_init(&rib));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_fsm_init(&fsm, &config));
    libbgp_fsm_set_out_handler(&fsm, &out_handler);
    libbgp_fsm_set_event_bus(&fsm, &bus);
    libbgp_fsm_set_rib4(&fsm, &rib);
    establish(&fsm, &out, &events);

    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_fsm_tick(&fsm, 1000u));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_fsm_tick(&fsm, 3500u));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_fsm_on_packet(&fsm, &update));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, tick.tick_err);
    LIBBGP_ASSERT_EQ_U64(1u, tick.route_events);
    LIBBGP_ASSERT_EQ_U64(LIBBGP_FSM_ESTABLISHED, libbgp_fsm_state(&fsm));
    LIBBGP_ASSERT_EQ_U64(1u, libbgp_rib4_route_count(&rib));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_rib4_lookup_scoped(&rib, ip4(198u, 51u, 100u, 10u), ip4(203u, 0u, 113u, 44u), &route));
    LIBBGP_ASSERT_EQ_U64(ip4(192u, 0u, 2u, 254u), route->next_hop);
    LIBBGP_ASSERT_EQ_U64(1u, events.count);
    LIBBGP_ASSERT_EQ_U64(4u, out.count);
    LIBBGP_ASSERT_EQ_U64(LIBBGP_PACKET_KEEPALIVE, out.sent[3].type);

    libbgp_packet_destroy(&update);
    libbgp_fsm_destroy(&fsm);
    libbgp_rib4_destroy(&rib);
    libbgp_event_bus_destroy(&bus);
    libbgp_out_handler_destroy(&out_handler);
}

LIBBGP_TEST(fsm_established_invalid_update_is_atomic_and_does_not_refresh_hold_timer)
{
    static const uint8_t addr6[16] = { 0x20u, 0x01u, 0x0du, 0xb8u };
    struct libbgp_fsm_config config;
    libbgp_fsm_t fsm;
    libbgp_out_handler_t out_handler;
    libbgp_event_bus_t bus;
    libbgp_rib4_t rib4;
    out_ctx_t out;
    event_ctx_t events;
    libbgp_prefix4_t prefix4 = p4(203u, 0u, 113u, 0u, 24u);
    libbgp_prefix6_t prefix6 = p6(addr6, 64u);
    libbgp_packet_t update = make_update_add_then_invalid_mp_reach6(prefix4, prefix6);
    const libbgp_rib4_route_t *route = NULL;

    config.local_asn = 65000u;
    config.local_bgp_id = ip4(192u, 0u, 2u, 1u);
    config.hold_time = 3u;
    config.keepalive_time = 0u;
    config.enable_4byte_asn = true;
    config.enable_mpbgp_ipv6 = true;
    setup_out(&out_handler, &out);
    memset(&events, 0, sizeof(events));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_event_bus_init(&bus));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_event_bus_subscribe(&bus, LIBBGP_EVENT_SESSION_UP, event_capture, &events, NULL));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_event_bus_subscribe(&bus, LIBBGP_EVENT_SESSION_DOWN, event_capture, &events, NULL));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_event_bus_subscribe(&bus, LIBBGP_EVENT_ROUTE_ADDED, event_capture, &events, NULL));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_rib4_init(&rib4));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_fsm_init(&fsm, &config));
    libbgp_fsm_set_out_handler(&fsm, &out_handler);
    libbgp_fsm_set_event_bus(&fsm, &bus);
    libbgp_fsm_set_rib4(&fsm, &rib4);
    establish(&fsm, &out, &events);

    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_fsm_tick(&fsm, 1000u));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_fsm_tick(&fsm, 3500u));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_INVALID, libbgp_fsm_on_packet(&fsm, &update));
    LIBBGP_ASSERT_EQ_U64(LIBBGP_FSM_IDLE, libbgp_fsm_state(&fsm));
    LIBBGP_ASSERT_EQ_U64(0u, libbgp_rib4_route_count(&rib4));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_NOT_FOUND, libbgp_rib4_lookup_scoped(&rib4, ip4(198u, 51u, 100u, 10u), ip4(203u, 0u, 113u, 44u), &route));
    LIBBGP_ASSERT_EQ_U64(2u, events.count);
    LIBBGP_ASSERT_EQ_U64(LIBBGP_EVENT_SESSION_DOWN, events.types[1]);
    LIBBGP_ASSERT_EQ_U64(4u, out.count);
    assert_sent_notification(&out, 3u, 3u, 5u);
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_fsm_tick(&fsm, 4501u));
    LIBBGP_ASSERT_EQ_U64(LIBBGP_FSM_IDLE, libbgp_fsm_state(&fsm));
    LIBBGP_ASSERT_EQ_U64(4u, out.count);
    LIBBGP_ASSERT_EQ_U64(2u, events.count);

    libbgp_packet_destroy(&update);
    libbgp_fsm_destroy(&fsm);
    libbgp_rib4_destroy(&rib4);
    libbgp_event_bus_destroy(&bus);
    libbgp_out_handler_destroy(&out_handler);
}

LIBBGP_TEST(fsm_established_update_nomem_rolls_back_inserted_routes_and_events)
{
    static const uint8_t addr6[16] = { 0x20u, 0x01u, 0x0du, 0xb8u, 0x60u };
    static const uint8_t dest6[16] = { 0x20u, 0x01u, 0x0du, 0xb8u, 0x60u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 1u };
    static const uint8_t next_hop6[16] = { 0x20u, 0x01u, 0x0du, 0xb8u, 0xffu, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 6u };
    struct libbgp_fsm_config config;
    libbgp_fsm_t fsm;
    libbgp_out_handler_t out_handler;
    libbgp_event_bus_t bus;
    libbgp_rib4_t rib4;
    libbgp_rib6_t rib6;
    out_ctx_t out;
    event_ctx_t events;
    fail_rib6_route_alloc_ctx_t fail_ctx = { 0u, 0u, 0u };
    libbgp_alloc_t fail_alloc;
    libbgp_prefix4_t prefix4 = p4(203u, 0u, 113u, 0u, 24u);
    libbgp_prefix6_t prefix6 = p6(addr6, 40u);
    libbgp_packet_t update = make_update_add_then_mp_reach6(prefix4, prefix6, next_hop6);
    const libbgp_rib4_route_t *route4 = NULL;
    const libbgp_rib6_route_t *route6 = NULL;
    libbgp_err_t err;
    size_t out_before_update;

    config.local_asn = 65000u;
    config.local_bgp_id = ip4(192u, 0u, 2u, 1u);
    config.hold_time = 3u;
    config.keepalive_time = 0u;
    config.enable_4byte_asn = true;
    config.enable_mpbgp_ipv6 = true;
    setup_out(&out_handler, &out);
    memset(&events, 0, sizeof(events));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_event_bus_init(&bus));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_event_bus_subscribe(&bus, LIBBGP_EVENT_SESSION_UP, event_capture, &events, NULL));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_event_bus_subscribe(&bus, LIBBGP_EVENT_SESSION_DOWN, event_capture, &events, NULL));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_event_bus_subscribe(&bus, LIBBGP_EVENT_ROUTE_ADDED, event_capture, &events, NULL));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_rib4_init(&rib4));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_rib6_init(&rib6));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_fsm_init(&fsm, &config));
    libbgp_fsm_set_out_handler(&fsm, &out_handler);
    libbgp_fsm_set_event_bus(&fsm, &bus);
    libbgp_fsm_set_rib4(&fsm, &rib4);
    libbgp_fsm_set_rib6(&fsm, &rib6);
    establish(&fsm, &out, &events);

    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_fsm_tick(&fsm, 1000u));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_fsm_tick(&fsm, 3500u));
    out_before_update = out.count;
    fail_alloc = fail_rib6_route_alloc_make(&fail_ctx);
    libbgp_set_alloc(&fail_alloc);
    err = libbgp_fsm_on_packet(&fsm, &update);
    libbgp_set_alloc(NULL);
    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_NOMEM, err);
    LIBBGP_ASSERT_EQ_U64(1u, fail_ctx.rib6_route_calloc_calls);
    LIBBGP_ASSERT_EQ_U64(1u, fail_ctx.failed_calloc_calls);
    LIBBGP_ASSERT_EQ_U64(LIBBGP_FSM_ESTABLISHED, libbgp_fsm_state(&fsm));
    LIBBGP_ASSERT_EQ_U64(0u, libbgp_rib4_route_count(&rib4));
    LIBBGP_ASSERT_EQ_U64(0u, libbgp_rib6_route_count(&rib6));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_NOT_FOUND, libbgp_rib4_lookup_scoped(&rib4, ip4(198u, 51u, 100u, 10u), ip4(203u, 0u, 113u, 44u), &route4));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_NOT_FOUND, libbgp_rib6_lookup_scoped(&rib6, ip4(198u, 51u, 100u, 10u), dest6, &route6));
    LIBBGP_ASSERT_EQ_U64(1u, events.count);
    LIBBGP_ASSERT_EQ_U64(out_before_update, out.count);

    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_fsm_tick(&fsm, 4501u));
    LIBBGP_ASSERT_EQ_U64(LIBBGP_FSM_IDLE, libbgp_fsm_state(&fsm));
    LIBBGP_ASSERT_EQ_U64(out_before_update + 1u, out.count);
    LIBBGP_ASSERT_EQ_U64(LIBBGP_PACKET_NOTIFICATION, out.sent[out_before_update].type);
    LIBBGP_ASSERT_EQ_U64(2u, events.count);
    LIBBGP_ASSERT_EQ_U64(LIBBGP_EVENT_SESSION_DOWN, events.types[1]);

    libbgp_packet_destroy(&update);
    libbgp_fsm_destroy(&fsm);
    libbgp_rib6_destroy(&rib6);
    libbgp_rib4_destroy(&rib4);
    libbgp_event_bus_destroy(&bus);
    libbgp_out_handler_destroy(&out_handler);
}

LIBBGP_TEST(fsm_established_update_nomem_restores_withdrawn_routes_and_events)
{
    static const uint8_t old_addr6[16] = { 0x20u, 0x01u, 0x0du, 0xb8u, 0x61u };
    static const uint8_t old_dest6[16] = { 0x20u, 0x01u, 0x0du, 0xb8u, 0x61u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 1u };
    static const uint8_t old_next_hop6[16] = { 0x20u, 0x01u, 0x0du, 0xb8u, 0xfeu, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 6u };
    static const uint8_t new_addr6[16] = { 0x20u, 0x01u, 0x0du, 0xb8u, 0x62u };
    static const uint8_t new_dest6[16] = { 0x20u, 0x01u, 0x0du, 0xb8u, 0x62u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 1u };
    static const uint8_t new_next_hop6[16] = { 0x20u, 0x01u, 0x0du, 0xb8u, 0xffu, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 6u };
    struct libbgp_fsm_config config;
    libbgp_fsm_t fsm;
    libbgp_out_handler_t out_handler;
    libbgp_event_bus_t bus;
    libbgp_rib4_t rib4;
    libbgp_rib6_t rib6;
    out_ctx_t out;
    event_ctx_t events;
    fail_rib6_route_alloc_ctx_t fail_ctx = { 0u, 0u, 0u };
    libbgp_alloc_t fail_alloc;
    libbgp_prefix4_t prefix4 = p4(203u, 0u, 113u, 0u, 24u);
    libbgp_prefix6_t old_prefix6 = p6(old_addr6, 40u);
    libbgp_prefix6_t new_prefix6 = p6(new_addr6, 40u);
    libbgp_packet_t add4 = make_update_add(prefix4, ip4(192u, 0u, 2u, 44u));
    libbgp_packet_t add6 = make_update_mp_reach6(old_prefix6, old_next_hop6);
    libbgp_packet_t update = make_update_withdraw4_unreach6_then_mp_reach6(
        prefix4,
        old_prefix6,
        new_prefix6,
        new_next_hop6);
    const libbgp_rib4_route_t *route4 = NULL;
    const libbgp_rib6_route_t *route6 = NULL;
    uint64_t old_update_id4;
    uint64_t old_update_id6;
    size_t old_attr_count4;
    size_t old_attr_count6;
    libbgp_err_t err;
    size_t events_before_update;
    size_t out_before_update;

    config.local_asn = 65000u;
    config.local_bgp_id = ip4(192u, 0u, 2u, 1u);
    config.hold_time = 3u;
    config.keepalive_time = 0u;
    config.enable_4byte_asn = true;
    config.enable_mpbgp_ipv6 = true;
    setup_out(&out_handler, &out);
    memset(&events, 0, sizeof(events));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_event_bus_init(&bus));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_event_bus_subscribe(&bus, LIBBGP_EVENT_SESSION_UP, event_capture, &events, NULL));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_event_bus_subscribe(&bus, LIBBGP_EVENT_SESSION_DOWN, event_capture, &events, NULL));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_event_bus_subscribe(&bus, LIBBGP_EVENT_ROUTE_ADDED, event_capture, &events, NULL));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_event_bus_subscribe(&bus, LIBBGP_EVENT_ROUTE_WITHDRAWN, event_capture, &events, NULL));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_rib4_init(&rib4));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_rib6_init(&rib6));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_fsm_init(&fsm, &config));
    libbgp_fsm_set_out_handler(&fsm, &out_handler);
    libbgp_fsm_set_event_bus(&fsm, &bus);
    libbgp_fsm_set_rib4(&fsm, &rib4);
    libbgp_fsm_set_rib6(&fsm, &rib6);
    establish(&fsm, &out, &events);
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_fsm_on_packet(&fsm, &add4));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_fsm_on_packet(&fsm, &add6));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_rib4_lookup_scoped(&rib4, ip4(198u, 51u, 100u, 10u), ip4(203u, 0u, 113u, 44u), &route4));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_rib6_lookup_scoped(&rib6, ip4(198u, 51u, 100u, 10u), old_dest6, &route6));
    old_update_id4 = route4->update_id;
    old_update_id6 = route6->update_id;
    old_attr_count4 = route4->attr_count;
    old_attr_count6 = route6->attr_count;

    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_fsm_tick(&fsm, 1000u));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_fsm_tick(&fsm, 3500u));
    events_before_update = events.count;
    out_before_update = out.count;
    fail_alloc = fail_rib6_route_alloc_make(&fail_ctx);
    libbgp_set_alloc(&fail_alloc);
    err = libbgp_fsm_on_packet(&fsm, &update);
    libbgp_set_alloc(NULL);
    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_NOMEM, err);
    LIBBGP_ASSERT_EQ_U64(1u, fail_ctx.failed_calloc_calls);
    LIBBGP_ASSERT_EQ_U64(LIBBGP_FSM_ESTABLISHED, libbgp_fsm_state(&fsm));
    LIBBGP_ASSERT_EQ_U64(1u, libbgp_rib4_route_count(&rib4));
    LIBBGP_ASSERT_EQ_U64(1u, libbgp_rib6_route_count(&rib6));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_rib4_lookup_scoped(&rib4, ip4(198u, 51u, 100u, 10u), ip4(203u, 0u, 113u, 44u), &route4));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_rib6_lookup_scoped(&rib6, ip4(198u, 51u, 100u, 10u), old_dest6, &route6));
    LIBBGP_ASSERT_EQ_U64(old_update_id4, route4->update_id);
    LIBBGP_ASSERT_EQ_U64(old_update_id6, route6->update_id);
    LIBBGP_ASSERT_EQ_U64(old_attr_count4, route4->attr_count);
    LIBBGP_ASSERT_EQ_U64(old_attr_count6, route6->attr_count);
    LIBBGP_ASSERT_EQ_U64(ip4(192u, 0u, 2u, 44u), route4->next_hop);
    LIBBGP_ASSERT_EQ_I64(0, memcmp(old_next_hop6, route6->next_hop, sizeof(route6->next_hop)));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_NOT_FOUND, libbgp_rib6_lookup_scoped(&rib6, ip4(198u, 51u, 100u, 10u), new_dest6, &route6));
    LIBBGP_ASSERT_EQ_U64(events_before_update, events.count);
    LIBBGP_ASSERT_EQ_U64(out_before_update, out.count);

    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_fsm_tick(&fsm, 4501u));
    LIBBGP_ASSERT_EQ_U64(LIBBGP_FSM_IDLE, libbgp_fsm_state(&fsm));
    LIBBGP_ASSERT_EQ_U64(out_before_update + 1u, out.count);
    LIBBGP_ASSERT_EQ_U64(LIBBGP_PACKET_NOTIFICATION, out.sent[out_before_update].type);
    LIBBGP_ASSERT_EQ_U64(events_before_update + 1u, events.count);
    LIBBGP_ASSERT_EQ_U64(LIBBGP_EVENT_SESSION_DOWN, events.types[events_before_update]);

    libbgp_packet_destroy(&update);
    libbgp_packet_destroy(&add6);
    libbgp_packet_destroy(&add4);
    libbgp_fsm_destroy(&fsm);
    libbgp_rib6_destroy(&rib6);
    libbgp_rib4_destroy(&rib4);
    libbgp_event_bus_destroy(&bus);
    libbgp_out_handler_destroy(&out_handler);
}

LIBBGP_TEST(fsm_established_update_nomem_restores_replaced_ipv4_route_and_events)
{
    static const uint8_t addr6[16] = { 0x20u, 0x01u, 0x0du, 0xb8u, 0x63u };
    static const uint8_t dest6[16] = { 0x20u, 0x01u, 0x0du, 0xb8u, 0x63u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 1u };
    static const uint8_t next_hop6[16] = { 0x20u, 0x01u, 0x0du, 0xb8u, 0xffu, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 6u };
    struct libbgp_fsm_config config;
    libbgp_fsm_t fsm;
    libbgp_out_handler_t out_handler;
    libbgp_event_bus_t bus;
    libbgp_rib4_t rib4;
    libbgp_rib6_t rib6;
    out_ctx_t out;
    event_ctx_t events;
    fail_rib6_route_alloc_ctx_t fail_ctx = { 0u, 0u, 0u };
    libbgp_alloc_t fail_alloc;
    libbgp_prefix4_t prefix4 = p4(203u, 0u, 113u, 0u, 24u);
    libbgp_prefix6_t prefix6 = p6(addr6, 40u);
    libbgp_packet_t add4 = make_update_add(prefix4, ip4(192u, 0u, 2u, 44u));
    libbgp_packet_t replace4_then_fail = make_update_add_then_mp_reach6(prefix4, prefix6, next_hop6);
    const libbgp_rib4_route_t *route4 = NULL;
    const libbgp_rib6_route_t *route6 = NULL;
    uint64_t old_update_id4;
    size_t old_attr_count4;
    libbgp_err_t err;
    size_t events_before_update;
    size_t out_before_update;

    config.local_asn = 65000u;
    config.local_bgp_id = ip4(192u, 0u, 2u, 1u);
    config.hold_time = 3u;
    config.keepalive_time = 0u;
    config.enable_4byte_asn = true;
    config.enable_mpbgp_ipv6 = true;
    setup_out(&out_handler, &out);
    memset(&events, 0, sizeof(events));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_event_bus_init(&bus));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_event_bus_subscribe(&bus, LIBBGP_EVENT_SESSION_UP, event_capture, &events, NULL));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_event_bus_subscribe(&bus, LIBBGP_EVENT_SESSION_DOWN, event_capture, &events, NULL));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_event_bus_subscribe(&bus, LIBBGP_EVENT_ROUTE_ADDED, event_capture, &events, NULL));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_event_bus_subscribe(&bus, LIBBGP_EVENT_ROUTE_WITHDRAWN, event_capture, &events, NULL));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_rib4_init(&rib4));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_rib6_init(&rib6));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_fsm_init(&fsm, &config));
    libbgp_fsm_set_out_handler(&fsm, &out_handler);
    libbgp_fsm_set_event_bus(&fsm, &bus);
    libbgp_fsm_set_rib4(&fsm, &rib4);
    libbgp_fsm_set_rib6(&fsm, &rib6);
    establish(&fsm, &out, &events);
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_fsm_on_packet(&fsm, &add4));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_rib4_lookup_scoped(&rib4, ip4(198u, 51u, 100u, 10u), ip4(203u, 0u, 113u, 44u), &route4));
    old_update_id4 = route4->update_id;
    old_attr_count4 = route4->attr_count;

    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_fsm_tick(&fsm, 1000u));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_fsm_tick(&fsm, 3500u));
    events_before_update = events.count;
    out_before_update = out.count;
    fail_alloc = fail_rib6_route_alloc_make(&fail_ctx);
    libbgp_set_alloc(&fail_alloc);
    err = libbgp_fsm_on_packet(&fsm, &replace4_then_fail);
    libbgp_set_alloc(NULL);
    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_NOMEM, err);
    LIBBGP_ASSERT_EQ_U64(1u, fail_ctx.failed_calloc_calls);
    LIBBGP_ASSERT_EQ_U64(LIBBGP_FSM_ESTABLISHED, libbgp_fsm_state(&fsm));
    LIBBGP_ASSERT_EQ_U64(1u, libbgp_rib4_route_count(&rib4));
    LIBBGP_ASSERT_EQ_U64(0u, libbgp_rib6_route_count(&rib6));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_rib4_lookup_scoped(&rib4, ip4(198u, 51u, 100u, 10u), ip4(203u, 0u, 113u, 44u), &route4));
    LIBBGP_ASSERT_EQ_U64(old_update_id4, route4->update_id);
    LIBBGP_ASSERT_EQ_U64(old_attr_count4, route4->attr_count);
    LIBBGP_ASSERT_EQ_U64(ip4(192u, 0u, 2u, 44u), route4->next_hop);
    LIBBGP_ASSERT_EQ_U64(200u, route4->local_pref);
    LIBBGP_ASSERT_EQ_U64(9u, route4->med);
    LIBBGP_ASSERT_EQ_U64(1u, route4->as_path_len);
    LIBBGP_ASSERT_EQ_U64(65010u, route4->origin_as);
    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_NOT_FOUND, libbgp_rib6_lookup_scoped(&rib6, ip4(198u, 51u, 100u, 10u), dest6, &route6));
    LIBBGP_ASSERT_EQ_U64(events_before_update, events.count);
    LIBBGP_ASSERT_EQ_U64(out_before_update, out.count);

    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_fsm_tick(&fsm, 4501u));
    LIBBGP_ASSERT_EQ_U64(LIBBGP_FSM_IDLE, libbgp_fsm_state(&fsm));
    LIBBGP_ASSERT_EQ_U64(out_before_update + 1u, out.count);
    LIBBGP_ASSERT_EQ_U64(LIBBGP_PACKET_NOTIFICATION, out.sent[out_before_update].type);
    LIBBGP_ASSERT_EQ_U64(events_before_update + 1u, events.count);
    LIBBGP_ASSERT_EQ_U64(LIBBGP_EVENT_SESSION_DOWN, events.types[events_before_update]);

    libbgp_packet_destroy(&replace4_then_fail);
    libbgp_packet_destroy(&add4);
    libbgp_fsm_destroy(&fsm);
    libbgp_rib6_destroy(&rib6);
    libbgp_rib4_destroy(&rib4);
    libbgp_event_bus_destroy(&bus);
    libbgp_out_handler_destroy(&out_handler);
}

LIBBGP_TEST(fsm_established_update_nomem_restores_original_after_duplicate_ipv4_replacements)
{
    static const uint8_t fail_addr6[16] = { 0x20u, 0x01u, 0x0du, 0xb8u, 0x66u };
    static const uint8_t fail_dest6[16] = { 0x20u, 0x01u, 0x0du, 0xb8u, 0x66u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 1u };
    static const uint8_t fail_next_hop6[16] = { 0x20u, 0x01u, 0x0du, 0xb8u, 0xffu, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 6u };
    struct libbgp_fsm_config config;
    libbgp_fsm_t fsm;
    libbgp_out_handler_t out_handler;
    libbgp_event_bus_t bus;
    libbgp_rib4_t rib4;
    libbgp_rib6_t rib6;
    out_ctx_t out;
    event_ctx_t events;
    fail_rib6_route_alloc_ctx_t fail_ctx = { 0u, 0u, 0u };
    libbgp_alloc_t fail_alloc;
    libbgp_prefix4_t prefix4 = p4(203u, 0u, 113u, 0u, 24u);
    libbgp_prefix6_t fail_prefix6 = p6(fail_addr6, 40u);
    libbgp_packet_t add4 = make_update_add(prefix4, ip4(192u, 0u, 2u, 44u));
    libbgp_packet_t duplicate4_then_fail;
    const libbgp_rib4_route_t *route4 = NULL;
    const libbgp_rib6_route_t *route6 = NULL;
    uint64_t old_update_id4;
    size_t old_attr_count4;
    libbgp_err_t err;
    size_t events_before_update;
    size_t out_before_update;

    duplicate4_then_fail = make_update_add_then_mp_reach6(prefix4, fail_prefix6, fail_next_hop6);
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_update_add_nlri(&duplicate4_then_fail.data.update, &prefix4));
    config.local_asn = 65000u;
    config.local_bgp_id = ip4(192u, 0u, 2u, 1u);
    config.hold_time = 3u;
    config.keepalive_time = 0u;
    config.enable_4byte_asn = true;
    config.enable_mpbgp_ipv6 = true;
    setup_out(&out_handler, &out);
    memset(&events, 0, sizeof(events));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_event_bus_init(&bus));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_event_bus_subscribe(&bus, LIBBGP_EVENT_SESSION_UP, event_capture, &events, NULL));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_event_bus_subscribe(&bus, LIBBGP_EVENT_SESSION_DOWN, event_capture, &events, NULL));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_event_bus_subscribe(&bus, LIBBGP_EVENT_ROUTE_ADDED, event_capture, &events, NULL));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_event_bus_subscribe(&bus, LIBBGP_EVENT_ROUTE_WITHDRAWN, event_capture, &events, NULL));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_rib4_init(&rib4));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_rib6_init(&rib6));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_fsm_init(&fsm, &config));
    libbgp_fsm_set_out_handler(&fsm, &out_handler);
    libbgp_fsm_set_event_bus(&fsm, &bus);
    libbgp_fsm_set_rib4(&fsm, &rib4);
    libbgp_fsm_set_rib6(&fsm, &rib6);
    establish(&fsm, &out, &events);
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_fsm_on_packet(&fsm, &add4));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_rib4_lookup_scoped(&rib4, ip4(198u, 51u, 100u, 10u), ip4(203u, 0u, 113u, 44u), &route4));
    old_update_id4 = route4->update_id;
    old_attr_count4 = route4->attr_count;

    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_fsm_tick(&fsm, 1000u));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_fsm_tick(&fsm, 3500u));
    events_before_update = events.count;
    out_before_update = out.count;
    fail_alloc = fail_rib6_route_alloc_make(&fail_ctx);
    libbgp_set_alloc(&fail_alloc);
    err = libbgp_fsm_on_packet(&fsm, &duplicate4_then_fail);
    libbgp_set_alloc(NULL);
    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_NOMEM, err);
    LIBBGP_ASSERT(fail_ctx.failed_calloc_calls > 0u);
    LIBBGP_ASSERT_EQ_U64(LIBBGP_FSM_ESTABLISHED, libbgp_fsm_state(&fsm));
    LIBBGP_ASSERT_EQ_U64(1u, libbgp_rib4_route_count(&rib4));
    LIBBGP_ASSERT_EQ_U64(0u, libbgp_rib6_route_count(&rib6));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_rib4_lookup_scoped(&rib4, ip4(198u, 51u, 100u, 10u), ip4(203u, 0u, 113u, 44u), &route4));
    LIBBGP_ASSERT_EQ_U64(old_update_id4, route4->update_id);
    LIBBGP_ASSERT_EQ_U64(old_attr_count4, route4->attr_count);
    LIBBGP_ASSERT_EQ_U64(ip4(192u, 0u, 2u, 44u), route4->next_hop);
    LIBBGP_ASSERT_EQ_U64(200u, route4->local_pref);
    LIBBGP_ASSERT_EQ_U64(9u, route4->med);
    LIBBGP_ASSERT_EQ_U64(1u, route4->as_path_len);
    LIBBGP_ASSERT_EQ_U64(65010u, route4->origin_as);
    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_NOT_FOUND, libbgp_rib6_lookup_scoped(&rib6, ip4(198u, 51u, 100u, 10u), fail_dest6, &route6));
    LIBBGP_ASSERT_EQ_U64(events_before_update, events.count);
    LIBBGP_ASSERT_EQ_U64(out_before_update, out.count);

    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_fsm_tick(&fsm, 4501u));
    LIBBGP_ASSERT_EQ_U64(LIBBGP_FSM_IDLE, libbgp_fsm_state(&fsm));
    LIBBGP_ASSERT_EQ_U64(out_before_update + 1u, out.count);
    LIBBGP_ASSERT_EQ_U64(LIBBGP_PACKET_NOTIFICATION, out.sent[out_before_update].type);
    LIBBGP_ASSERT_EQ_U64(events_before_update + 1u, events.count);
    LIBBGP_ASSERT_EQ_U64(LIBBGP_EVENT_SESSION_DOWN, events.types[events_before_update]);

    libbgp_packet_destroy(&duplicate4_then_fail);
    libbgp_packet_destroy(&add4);
    libbgp_fsm_destroy(&fsm);
    libbgp_rib6_destroy(&rib6);
    libbgp_rib4_destroy(&rib4);
    libbgp_event_bus_destroy(&bus);
    libbgp_out_handler_destroy(&out_handler);
}

LIBBGP_TEST(fsm_established_update_nomem_removes_absent_duplicate_ipv4_replacements)
{
    static const uint8_t fail_addr6[16] = { 0x20u, 0x01u, 0x0du, 0xb8u, 0x69u };
    static const uint8_t fail_dest6[16] = { 0x20u, 0x01u, 0x0du, 0xb8u, 0x69u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 1u };
    static const uint8_t fail_next_hop6[16] = { 0x20u, 0x01u, 0x0du, 0xb8u, 0xffu, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 6u };
    struct libbgp_fsm_config config;
    libbgp_fsm_t fsm;
    libbgp_out_handler_t out_handler;
    libbgp_event_bus_t bus;
    libbgp_rib4_t rib4;
    libbgp_rib6_t rib6;
    out_ctx_t out;
    event_ctx_t events;
    fail_rib6_route_alloc_ctx_t fail_ctx = { 0u, 0u, 0u };
    libbgp_alloc_t fail_alloc;
    libbgp_prefix4_t prefix4 = p4(203u, 0u, 113u, 0u, 24u);
    libbgp_prefix6_t fail_prefix6 = p6(fail_addr6, 40u);
    libbgp_packet_t duplicate4_then_fail;
    const libbgp_rib4_route_t *route4 = NULL;
    const libbgp_rib6_route_t *route6 = NULL;
    libbgp_err_t err;
    size_t events_before_update;
    size_t out_before_update;

    duplicate4_then_fail = make_update_add_then_mp_reach6(prefix4, fail_prefix6, fail_next_hop6);
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_update_add_nlri(&duplicate4_then_fail.data.update, &prefix4));
    config.local_asn = 65000u;
    config.local_bgp_id = ip4(192u, 0u, 2u, 1u);
    config.hold_time = 3u;
    config.keepalive_time = 0u;
    config.enable_4byte_asn = true;
    config.enable_mpbgp_ipv6 = true;
    setup_out(&out_handler, &out);
    memset(&events, 0, sizeof(events));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_event_bus_init(&bus));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_event_bus_subscribe(&bus, LIBBGP_EVENT_SESSION_UP, event_capture, &events, NULL));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_event_bus_subscribe(&bus, LIBBGP_EVENT_SESSION_DOWN, event_capture, &events, NULL));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_event_bus_subscribe(&bus, LIBBGP_EVENT_ROUTE_ADDED, event_capture, &events, NULL));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_event_bus_subscribe(&bus, LIBBGP_EVENT_ROUTE_WITHDRAWN, event_capture, &events, NULL));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_rib4_init(&rib4));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_rib6_init(&rib6));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_fsm_init(&fsm, &config));
    libbgp_fsm_set_out_handler(&fsm, &out_handler);
    libbgp_fsm_set_event_bus(&fsm, &bus);
    libbgp_fsm_set_rib4(&fsm, &rib4);
    libbgp_fsm_set_rib6(&fsm, &rib6);
    establish(&fsm, &out, &events);

    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_fsm_tick(&fsm, 1000u));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_fsm_tick(&fsm, 3500u));
    events_before_update = events.count;
    out_before_update = out.count;
    fail_alloc = fail_rib6_route_alloc_make(&fail_ctx);
    libbgp_set_alloc(&fail_alloc);
    err = libbgp_fsm_on_packet(&fsm, &duplicate4_then_fail);
    libbgp_set_alloc(NULL);
    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_NOMEM, err);
    LIBBGP_ASSERT(fail_ctx.failed_calloc_calls > 0u);
    LIBBGP_ASSERT_EQ_U64(LIBBGP_FSM_ESTABLISHED, libbgp_fsm_state(&fsm));
    LIBBGP_ASSERT_EQ_U64(0u, libbgp_rib4_route_count(&rib4));
    LIBBGP_ASSERT_EQ_U64(0u, libbgp_rib6_route_count(&rib6));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_NOT_FOUND, libbgp_rib4_lookup_scoped(&rib4, ip4(198u, 51u, 100u, 10u), ip4(203u, 0u, 113u, 44u), &route4));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_NOT_FOUND, libbgp_rib6_lookup_scoped(&rib6, ip4(198u, 51u, 100u, 10u), fail_dest6, &route6));
    LIBBGP_ASSERT_EQ_U64(events_before_update, events.count);
    LIBBGP_ASSERT_EQ_U64(out_before_update, out.count);

    libbgp_packet_destroy(&duplicate4_then_fail);
    libbgp_fsm_destroy(&fsm);
    libbgp_rib6_destroy(&rib6);
    libbgp_rib4_destroy(&rib4);
    libbgp_event_bus_destroy(&bus);
    libbgp_out_handler_destroy(&out_handler);
}

LIBBGP_TEST(fsm_established_update_nomem_restores_replaced_ipv6_route_and_events)
{
    static const uint8_t old_addr6[16] = { 0x20u, 0x01u, 0x0du, 0xb8u, 0x64u };
    static const uint8_t old_dest6[16] = { 0x20u, 0x01u, 0x0du, 0xb8u, 0x64u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 1u };
    static const uint8_t old_next_hop6[16] = { 0x20u, 0x01u, 0x0du, 0xb8u, 0xfeu, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 6u };
    static const uint8_t new_next_hop6[16] = { 0x20u, 0x01u, 0x0du, 0xb8u, 0xffu, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 6u };
    static const uint8_t fail_addr6[16] = { 0x20u, 0x01u, 0x0du, 0xb8u, 0x65u };
    static const uint8_t fail_dest6[16] = { 0x20u, 0x01u, 0x0du, 0xb8u, 0x65u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 1u };
    struct libbgp_fsm_config config;
    libbgp_fsm_t fsm;
    libbgp_out_handler_t out_handler;
    libbgp_event_bus_t bus;
    libbgp_rib6_t rib6;
    out_ctx_t out;
    event_ctx_t events;
    fail_rib6_route_alloc_ctx_t fail_ctx = { 0u, 0u, 2u };
    libbgp_alloc_t fail_alloc;
    libbgp_prefix6_t old_prefix6 = p6(old_addr6, 40u);
    libbgp_prefix6_t fail_prefix6 = p6(fail_addr6, 40u);
    libbgp_prefix6_t replace_prefixes6[2];
    libbgp_packet_t add6 = make_update_mp_reach6(old_prefix6, old_next_hop6);
    libbgp_packet_t replace6_then_fail;
    const libbgp_rib6_route_t *route6 = NULL;
    uint64_t old_update_id6;
    size_t old_attr_count6;
    libbgp_err_t err;
    size_t events_before_update;
    size_t out_before_update;

    replace_prefixes6[0] = old_prefix6;
    replace_prefixes6[1] = fail_prefix6;
    replace6_then_fail = make_update_mp_reach6_multi(replace_prefixes6, LIBBGP_ARRAY_LEN(replace_prefixes6), new_next_hop6);
    config.local_asn = 65000u;
    config.local_bgp_id = ip4(192u, 0u, 2u, 1u);
    config.hold_time = 3u;
    config.keepalive_time = 0u;
    config.enable_4byte_asn = true;
    config.enable_mpbgp_ipv6 = true;
    setup_out(&out_handler, &out);
    memset(&events, 0, sizeof(events));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_event_bus_init(&bus));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_event_bus_subscribe(&bus, LIBBGP_EVENT_SESSION_UP, event_capture, &events, NULL));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_event_bus_subscribe(&bus, LIBBGP_EVENT_SESSION_DOWN, event_capture, &events, NULL));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_event_bus_subscribe(&bus, LIBBGP_EVENT_ROUTE_ADDED, event_capture, &events, NULL));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_event_bus_subscribe(&bus, LIBBGP_EVENT_ROUTE_WITHDRAWN, event_capture, &events, NULL));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_rib6_init(&rib6));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_fsm_init(&fsm, &config));
    libbgp_fsm_set_out_handler(&fsm, &out_handler);
    libbgp_fsm_set_event_bus(&fsm, &bus);
    libbgp_fsm_set_rib6(&fsm, &rib6);
    establish(&fsm, &out, &events);
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_fsm_on_packet(&fsm, &add6));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_rib6_lookup_scoped(&rib6, ip4(198u, 51u, 100u, 10u), old_dest6, &route6));
    old_update_id6 = route6->update_id;
    old_attr_count6 = route6->attr_count;

    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_fsm_tick(&fsm, 1000u));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_fsm_tick(&fsm, 3500u));
    events_before_update = events.count;
    out_before_update = out.count;
    fail_alloc = fail_rib6_route_alloc_make(&fail_ctx);
    libbgp_set_alloc(&fail_alloc);
    err = libbgp_fsm_on_packet(&fsm, &replace6_then_fail);
    libbgp_set_alloc(NULL);
    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_NOMEM, err);
    LIBBGP_ASSERT_EQ_U64(2u, fail_ctx.rib6_route_calloc_calls);
    LIBBGP_ASSERT_EQ_U64(1u, fail_ctx.failed_calloc_calls);
    LIBBGP_ASSERT_EQ_U64(LIBBGP_FSM_ESTABLISHED, libbgp_fsm_state(&fsm));
    LIBBGP_ASSERT_EQ_U64(1u, libbgp_rib6_route_count(&rib6));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_rib6_lookup_scoped(&rib6, ip4(198u, 51u, 100u, 10u), old_dest6, &route6));
    LIBBGP_ASSERT_EQ_U64(old_update_id6, route6->update_id);
    LIBBGP_ASSERT_EQ_U64(old_attr_count6, route6->attr_count);
    LIBBGP_ASSERT_EQ_I64(0, memcmp(old_next_hop6, route6->next_hop, sizeof(route6->next_hop)));
    LIBBGP_ASSERT_EQ_U64(200u, route6->local_pref);
    LIBBGP_ASSERT_EQ_U64(9u, route6->med);
    LIBBGP_ASSERT_EQ_U64(1u, route6->as_path_len);
    LIBBGP_ASSERT_EQ_U64(65010u, route6->origin_as);
    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_NOT_FOUND, libbgp_rib6_lookup_scoped(&rib6, ip4(198u, 51u, 100u, 10u), fail_dest6, &route6));
    LIBBGP_ASSERT_EQ_U64(events_before_update, events.count);
    LIBBGP_ASSERT_EQ_U64(out_before_update, out.count);

    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_fsm_tick(&fsm, 4501u));
    LIBBGP_ASSERT_EQ_U64(LIBBGP_FSM_IDLE, libbgp_fsm_state(&fsm));
    LIBBGP_ASSERT_EQ_U64(out_before_update + 1u, out.count);
    LIBBGP_ASSERT_EQ_U64(LIBBGP_PACKET_NOTIFICATION, out.sent[out_before_update].type);
    LIBBGP_ASSERT_EQ_U64(events_before_update + 1u, events.count);
    LIBBGP_ASSERT_EQ_U64(LIBBGP_EVENT_SESSION_DOWN, events.types[events_before_update]);

    libbgp_packet_destroy(&replace6_then_fail);
    libbgp_packet_destroy(&add6);
    libbgp_fsm_destroy(&fsm);
    libbgp_rib6_destroy(&rib6);
    libbgp_event_bus_destroy(&bus);
    libbgp_out_handler_destroy(&out_handler);
}

LIBBGP_TEST(fsm_established_update_nomem_restores_original_after_duplicate_ipv6_replacements)
{
    static const uint8_t old_addr6[16] = { 0x20u, 0x01u, 0x0du, 0xb8u, 0x67u };
    static const uint8_t old_dest6[16] = { 0x20u, 0x01u, 0x0du, 0xb8u, 0x67u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 1u };
    static const uint8_t old_next_hop6[16] = { 0x20u, 0x01u, 0x0du, 0xb8u, 0xfeu, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 6u };
    static const uint8_t new_next_hop6[16] = { 0x20u, 0x01u, 0x0du, 0xb8u, 0xffu, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 6u };
    static const uint8_t fail_addr6[16] = { 0x20u, 0x01u, 0x0du, 0xb8u, 0x68u };
    static const uint8_t fail_dest6[16] = { 0x20u, 0x01u, 0x0du, 0xb8u, 0x68u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 1u };
    struct libbgp_fsm_config config;
    libbgp_fsm_t fsm;
    libbgp_out_handler_t out_handler;
    libbgp_event_bus_t bus;
    libbgp_rib6_t rib6;
    out_ctx_t out;
    event_ctx_t events;
    fail_rib6_route_alloc_ctx_t fail_ctx = { 0u, 0u, 3u };
    libbgp_alloc_t fail_alloc;
    libbgp_prefix6_t old_prefix6 = p6(old_addr6, 40u);
    libbgp_prefix6_t fail_prefix6 = p6(fail_addr6, 40u);
    libbgp_prefix6_t replace_prefixes6[3];
    libbgp_packet_t add6 = make_update_mp_reach6(old_prefix6, old_next_hop6);
    libbgp_packet_t duplicate6_then_fail;
    const libbgp_rib6_route_t *route6 = NULL;
    uint64_t old_update_id6;
    size_t old_attr_count6;
    libbgp_err_t err;
    size_t events_before_update;
    size_t out_before_update;

    replace_prefixes6[0] = old_prefix6;
    replace_prefixes6[1] = old_prefix6;
    replace_prefixes6[2] = fail_prefix6;
    duplicate6_then_fail = make_update_mp_reach6_multi(
        replace_prefixes6,
        LIBBGP_ARRAY_LEN(replace_prefixes6),
        new_next_hop6);
    config.local_asn = 65000u;
    config.local_bgp_id = ip4(192u, 0u, 2u, 1u);
    config.hold_time = 3u;
    config.keepalive_time = 0u;
    config.enable_4byte_asn = true;
    config.enable_mpbgp_ipv6 = true;
    setup_out(&out_handler, &out);
    memset(&events, 0, sizeof(events));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_event_bus_init(&bus));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_event_bus_subscribe(&bus, LIBBGP_EVENT_SESSION_UP, event_capture, &events, NULL));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_event_bus_subscribe(&bus, LIBBGP_EVENT_SESSION_DOWN, event_capture, &events, NULL));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_event_bus_subscribe(&bus, LIBBGP_EVENT_ROUTE_ADDED, event_capture, &events, NULL));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_event_bus_subscribe(&bus, LIBBGP_EVENT_ROUTE_WITHDRAWN, event_capture, &events, NULL));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_rib6_init(&rib6));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_fsm_init(&fsm, &config));
    libbgp_fsm_set_out_handler(&fsm, &out_handler);
    libbgp_fsm_set_event_bus(&fsm, &bus);
    libbgp_fsm_set_rib6(&fsm, &rib6);
    establish(&fsm, &out, &events);
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_fsm_on_packet(&fsm, &add6));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_rib6_lookup_scoped(&rib6, ip4(198u, 51u, 100u, 10u), old_dest6, &route6));
    old_update_id6 = route6->update_id;
    old_attr_count6 = route6->attr_count;

    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_fsm_tick(&fsm, 1000u));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_fsm_tick(&fsm, 3500u));
    events_before_update = events.count;
    out_before_update = out.count;
    fail_alloc = fail_rib6_route_alloc_make(&fail_ctx);
    libbgp_set_alloc(&fail_alloc);
    err = libbgp_fsm_on_packet(&fsm, &duplicate6_then_fail);
    libbgp_set_alloc(NULL);
    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_NOMEM, err);
    LIBBGP_ASSERT(fail_ctx.failed_calloc_calls > 0u);
    LIBBGP_ASSERT_EQ_U64(LIBBGP_FSM_ESTABLISHED, libbgp_fsm_state(&fsm));
    LIBBGP_ASSERT_EQ_U64(1u, libbgp_rib6_route_count(&rib6));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_rib6_lookup_scoped(&rib6, ip4(198u, 51u, 100u, 10u), old_dest6, &route6));
    LIBBGP_ASSERT_EQ_U64(old_update_id6, route6->update_id);
    LIBBGP_ASSERT_EQ_U64(old_attr_count6, route6->attr_count);
    LIBBGP_ASSERT_EQ_I64(0, memcmp(old_next_hop6, route6->next_hop, sizeof(route6->next_hop)));
    LIBBGP_ASSERT_EQ_U64(200u, route6->local_pref);
    LIBBGP_ASSERT_EQ_U64(9u, route6->med);
    LIBBGP_ASSERT_EQ_U64(1u, route6->as_path_len);
    LIBBGP_ASSERT_EQ_U64(65010u, route6->origin_as);
    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_NOT_FOUND, libbgp_rib6_lookup_scoped(&rib6, ip4(198u, 51u, 100u, 10u), fail_dest6, &route6));
    LIBBGP_ASSERT_EQ_U64(events_before_update, events.count);
    LIBBGP_ASSERT_EQ_U64(out_before_update, out.count);

    libbgp_packet_destroy(&duplicate6_then_fail);
    libbgp_packet_destroy(&add6);
    libbgp_fsm_destroy(&fsm);
    libbgp_rib6_destroy(&rib6);
    libbgp_event_bus_destroy(&bus);
    libbgp_out_handler_destroy(&out_handler);
}

LIBBGP_TEST(fsm_established_update_nomem_removes_absent_duplicate_ipv6_replacements)
{
    static const uint8_t prefix_addr6[16] = { 0x20u, 0x01u, 0x0du, 0xb8u, 0x6au };
    static const uint8_t prefix_dest6[16] = { 0x20u, 0x01u, 0x0du, 0xb8u, 0x6au, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 1u };
    static const uint8_t fail_addr6[16] = { 0x20u, 0x01u, 0x0du, 0xb8u, 0x6bu };
    static const uint8_t fail_dest6[16] = { 0x20u, 0x01u, 0x0du, 0xb8u, 0x6bu, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 1u };
    static const uint8_t next_hop6[16] = { 0x20u, 0x01u, 0x0du, 0xb8u, 0xffu, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 6u };
    struct libbgp_fsm_config config;
    libbgp_fsm_t fsm;
    libbgp_out_handler_t out_handler;
    libbgp_event_bus_t bus;
    libbgp_rib6_t rib6;
    out_ctx_t out;
    event_ctx_t events;
    fail_rib6_route_alloc_ctx_t fail_ctx = { 0u, 0u, 3u };
    libbgp_alloc_t fail_alloc;
    libbgp_prefix6_t prefix6 = p6(prefix_addr6, 40u);
    libbgp_prefix6_t fail_prefix6 = p6(fail_addr6, 40u);
    libbgp_prefix6_t prefixes6[3];
    libbgp_packet_t duplicate6_then_fail;
    const libbgp_rib6_route_t *route6 = NULL;
    libbgp_err_t err;
    size_t events_before_update;
    size_t out_before_update;

    prefixes6[0] = prefix6;
    prefixes6[1] = prefix6;
    prefixes6[2] = fail_prefix6;
    duplicate6_then_fail = make_update_mp_reach6_multi(prefixes6, LIBBGP_ARRAY_LEN(prefixes6), next_hop6);
    config.local_asn = 65000u;
    config.local_bgp_id = ip4(192u, 0u, 2u, 1u);
    config.hold_time = 3u;
    config.keepalive_time = 0u;
    config.enable_4byte_asn = true;
    config.enable_mpbgp_ipv6 = true;
    setup_out(&out_handler, &out);
    memset(&events, 0, sizeof(events));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_event_bus_init(&bus));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_event_bus_subscribe(&bus, LIBBGP_EVENT_SESSION_UP, event_capture, &events, NULL));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_event_bus_subscribe(&bus, LIBBGP_EVENT_SESSION_DOWN, event_capture, &events, NULL));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_event_bus_subscribe(&bus, LIBBGP_EVENT_ROUTE_ADDED, event_capture, &events, NULL));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_event_bus_subscribe(&bus, LIBBGP_EVENT_ROUTE_WITHDRAWN, event_capture, &events, NULL));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_rib6_init(&rib6));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_fsm_init(&fsm, &config));
    libbgp_fsm_set_out_handler(&fsm, &out_handler);
    libbgp_fsm_set_event_bus(&fsm, &bus);
    libbgp_fsm_set_rib6(&fsm, &rib6);
    establish(&fsm, &out, &events);

    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_fsm_tick(&fsm, 1000u));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_fsm_tick(&fsm, 3500u));
    events_before_update = events.count;
    out_before_update = out.count;
    fail_alloc = fail_rib6_route_alloc_make(&fail_ctx);
    libbgp_set_alloc(&fail_alloc);
    err = libbgp_fsm_on_packet(&fsm, &duplicate6_then_fail);
    libbgp_set_alloc(NULL);
    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_NOMEM, err);
    LIBBGP_ASSERT_EQ_U64(3u, fail_ctx.rib6_route_calloc_calls);
    LIBBGP_ASSERT_EQ_U64(1u, fail_ctx.failed_calloc_calls);
    LIBBGP_ASSERT_EQ_U64(LIBBGP_FSM_ESTABLISHED, libbgp_fsm_state(&fsm));
    LIBBGP_ASSERT_EQ_U64(0u, libbgp_rib6_route_count(&rib6));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_NOT_FOUND, libbgp_rib6_lookup_scoped(&rib6, ip4(198u, 51u, 100u, 10u), prefix_dest6, &route6));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_NOT_FOUND, libbgp_rib6_lookup_scoped(&rib6, ip4(198u, 51u, 100u, 10u), fail_dest6, &route6));
    LIBBGP_ASSERT_EQ_U64(events_before_update, events.count);
    LIBBGP_ASSERT_EQ_U64(out_before_update, out.count);

    libbgp_packet_destroy(&duplicate6_then_fail);
    libbgp_fsm_destroy(&fsm);
    libbgp_rib6_destroy(&rib6);
    libbgp_event_bus_destroy(&bus);
    libbgp_out_handler_destroy(&out_handler);
}

LIBBGP_TEST(fsm_established_rejects_ipv4_advertisements_missing_mandatory_attrs)
{
    libbgp_prefix4_t prefix = p4(203u, 0u, 113u, 0u, 24u);
    libbgp_packet_t missing_origin = make_update_add_with_attrs(prefix, false, true, true);
    libbgp_packet_t missing_as_path = make_update_add_with_attrs(prefix, true, false, true);
    libbgp_packet_t missing_next_hop = make_update_add_with_attrs(prefix, true, true, false);

    assert_invalid_update_no_route_effects(&missing_origin, 3u);
    assert_invalid_update_no_route_effects(&missing_as_path, 3u);
    assert_invalid_update_no_route_effects(&missing_next_hop, 3u);

    libbgp_packet_destroy(&missing_next_hop);
    libbgp_packet_destroy(&missing_as_path);
    libbgp_packet_destroy(&missing_origin);
}

LIBBGP_TEST(fsm_established_rejects_ipv6_advertisements_missing_common_mandatory_attrs)
{
    const uint8_t prefix_addr[16] = { 0x20u, 0x01u, 0x0du, 0xb8u, 0x30u };
    const uint8_t next_hop[16] = { 0x20u, 0x01u, 0x0du, 0xb8u, 0xffu, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 3u };
    libbgp_prefix6_t prefix = p6(prefix_addr, 40u);
    libbgp_packet_t missing_origin = make_update_mp_reach6_with_attrs(prefix, next_hop, false, true);
    libbgp_packet_t missing_as_path = make_update_mp_reach6_with_attrs(prefix, next_hop, true, false);

    assert_invalid_update_no_route_effects(&missing_origin, 3u);
    assert_invalid_update_no_route_effects(&missing_as_path, 3u);

    libbgp_packet_destroy(&missing_as_path);
    libbgp_packet_destroy(&missing_origin);
}

LIBBGP_TEST(fsm_established_rejects_duplicate_mandatory_attrs)
{
    libbgp_prefix4_t prefix = p4(203u, 0u, 113u, 0u, 24u);
    libbgp_packet_t duplicate_origin = make_update_add_duplicate_attr(prefix, LIBBGP_PATTR_ORIGIN);
    libbgp_packet_t duplicate_next_hop = make_update_add_duplicate_attr(prefix, LIBBGP_PATTR_NEXT_HOP);

    assert_invalid_update_no_route_effects(&duplicate_origin, 1u);
    assert_invalid_update_no_route_effects(&duplicate_next_hop, 1u);

    libbgp_packet_destroy(&duplicate_next_hop);
    libbgp_packet_destroy(&duplicate_origin);
}

LIBBGP_TEST(fsm_established_update_withdraws_route_and_event)
{
    libbgp_fsm_t fsm;
    libbgp_out_handler_t out_handler;
    libbgp_event_bus_t bus;
    libbgp_rib4_t rib;
    out_ctx_t out;
    event_ctx_t events;
    libbgp_prefix4_t prefix = p4(203u, 0u, 113u, 0u, 24u);
    libbgp_packet_t add = make_update_add(prefix, ip4(192u, 0u, 2u, 254u));
    libbgp_packet_t withdraw = make_update_withdraw(prefix);
    const libbgp_rib4_route_t *route = NULL;

    setup_out(&out_handler, &out);
    memset(&events, 0, sizeof(events));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_event_bus_init(&bus));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_event_bus_subscribe(&bus, LIBBGP_EVENT_SESSION_UP, event_capture, &events, NULL));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_event_bus_subscribe(&bus, LIBBGP_EVENT_ROUTE_ADDED, event_capture, &events, NULL));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_event_bus_subscribe(&bus, LIBBGP_EVENT_ROUTE_WITHDRAWN, event_capture, &events, NULL));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_rib4_init(&rib));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, init_test_fsm(&fsm));
    libbgp_fsm_set_out_handler(&fsm, &out_handler);
    libbgp_fsm_set_event_bus(&fsm, &bus);
    libbgp_fsm_set_rib4(&fsm, &rib);
    establish(&fsm, &out, &events);

    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_fsm_on_packet(&fsm, &add));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_fsm_on_packet(&fsm, &withdraw));
    LIBBGP_ASSERT_EQ_U64(3u, events.count);
    LIBBGP_ASSERT_EQ_U64(LIBBGP_EVENT_ROUTE_WITHDRAWN, events.types[2]);
    LIBBGP_ASSERT(libbgp_prefix4_eq(&prefix, &events.prefixes[2]));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_NOT_FOUND, libbgp_rib4_lookup_scoped(&rib, ip4(198u, 51u, 100u, 10u), ip4(203u, 0u, 113u, 44u), &route));

    libbgp_packet_destroy(&withdraw);
    libbgp_packet_destroy(&add);
    libbgp_fsm_destroy(&fsm);
    libbgp_rib4_destroy(&rib);
    libbgp_event_bus_destroy(&bus);
    libbgp_out_handler_destroy(&out_handler);
}

LIBBGP_TEST(fsm_established_update_mp_reach6_adds_rib6_route)
{
    libbgp_fsm_t fsm;
    libbgp_out_handler_t out_handler;
    libbgp_event_bus_t bus;
    libbgp_rib6_t rib;
    out_ctx_t out;
    event_ctx_t events;
    const uint8_t prefix_addr[16] = { 0x20u, 0x01u, 0x0du, 0xb8u, 0x10u };
    const uint8_t dest[16] = { 0x20u, 0x01u, 0x0du, 0xb8u, 0x10u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 1u };
    const uint8_t next_hop[16] = { 0x20u, 0x01u, 0x0du, 0xb8u, 0xffu, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 1u };
    libbgp_prefix6_t prefix = p6(prefix_addr, 40u);
    libbgp_packet_t update = make_update_mp_reach6(prefix, next_hop);
    const libbgp_rib6_route_t *route = NULL;

    setup_out(&out_handler, &out);
    memset(&events, 0, sizeof(events));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_event_bus_init(&bus));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_event_bus_subscribe(&bus, LIBBGP_EVENT_SESSION_UP, event_capture, &events, NULL));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_event_bus_subscribe(&bus, LIBBGP_EVENT_ROUTE_ADDED, event_capture, &events, NULL));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_rib6_init(&rib));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, init_test_fsm(&fsm));
    libbgp_fsm_set_out_handler(&fsm, &out_handler);
    libbgp_fsm_set_event_bus(&fsm, &bus);
    libbgp_fsm_set_rib6(&fsm, &rib);
    establish(&fsm, &out, &events);

    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_fsm_on_packet(&fsm, &update));
    LIBBGP_ASSERT_EQ_U64(2u, events.count);
    LIBBGP_ASSERT_EQ_U64(LIBBGP_EVENT_ROUTE_ADDED, events.types[1]);
    LIBBGP_ASSERT(!events.has_prefix4[1]);
    LIBBGP_ASSERT(events.has_prefix6[1]);
    LIBBGP_ASSERT(libbgp_prefix6_eq(&prefix, &events.prefixes6[1]));
    LIBBGP_ASSERT_EQ_U64(1u, libbgp_rib6_route_count(&rib));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_rib6_lookup_scoped(&rib, ip4(198u, 51u, 100u, 10u), dest, &route));
    LIBBGP_ASSERT(route != NULL);
    LIBBGP_ASSERT(libbgp_prefix6_eq(&prefix, &route->prefix));
    LIBBGP_ASSERT_EQ_U64(ip4(198u, 51u, 100u, 10u), route->source_router_id);
    LIBBGP_ASSERT(memcmp(next_hop, route->next_hop, sizeof(route->next_hop)) == 0);
    LIBBGP_ASSERT_EQ_U64(200u, route->local_pref);
    LIBBGP_ASSERT_EQ_U64(9u, route->med);
    LIBBGP_ASSERT_EQ_U64(1u, route->as_path_len);
    LIBBGP_ASSERT_EQ_U64(65010u, route->origin_as);
    LIBBGP_ASSERT_EQ_U64(4u, route->attr_count);

    libbgp_packet_destroy(&update);
    libbgp_fsm_destroy(&fsm);
    libbgp_rib6_destroy(&rib);
    libbgp_event_bus_destroy(&bus);
    libbgp_out_handler_destroy(&out_handler);
}

LIBBGP_TEST(fsm_established_update_mp_reach6_publishes_event_without_rib6)
{
    libbgp_fsm_t fsm;
    libbgp_out_handler_t out_handler;
    libbgp_event_bus_t bus;
    out_ctx_t out;
    event_ctx_t events;
    const uint8_t prefix_addr[16] = { 0x20u, 0x01u, 0x0du, 0xb8u, 0x20u };
    const uint8_t next_hop[16] = { 0x20u, 0x01u, 0x0du, 0xb8u, 0xffu, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 2u };
    libbgp_prefix6_t prefix = p6(prefix_addr, 40u);
    libbgp_packet_t update = make_update_mp_reach6(prefix, next_hop);

    setup_out(&out_handler, &out);
    memset(&events, 0, sizeof(events));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_event_bus_init(&bus));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_event_bus_subscribe(&bus, LIBBGP_EVENT_SESSION_UP, event_capture, &events, NULL));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_event_bus_subscribe(&bus, LIBBGP_EVENT_ROUTE_ADDED, event_capture, &events, NULL));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, init_test_fsm(&fsm));
    libbgp_fsm_set_out_handler(&fsm, &out_handler);
    libbgp_fsm_set_event_bus(&fsm, &bus);
    establish(&fsm, &out, &events);

    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_fsm_on_packet(&fsm, &update));
    LIBBGP_ASSERT_EQ_U64(2u, events.count);
    LIBBGP_ASSERT_EQ_U64(LIBBGP_EVENT_ROUTE_ADDED, events.types[1]);
    LIBBGP_ASSERT(!events.has_prefix4[1]);
    LIBBGP_ASSERT(events.has_prefix6[1]);
    LIBBGP_ASSERT(libbgp_prefix6_eq(&prefix, &events.prefixes6[1]));

    libbgp_packet_destroy(&update);
    libbgp_fsm_destroy(&fsm);
    libbgp_event_bus_destroy(&bus);
    libbgp_out_handler_destroy(&out_handler);
}

LIBBGP_TEST(fsm_established_invalid_mp_reach6_without_rib6_publishes_no_event)
{
    libbgp_fsm_t fsm;
    libbgp_out_handler_t out_handler;
    libbgp_event_bus_t bus;
    out_ctx_t out;
    event_ctx_t events;
    const uint8_t prefix_addr[16] = { 0x20u, 0x01u, 0x0du, 0xb8u, 0x22u };
    const uint8_t next_hop[16] = { 0x20u, 0x01u, 0x0du, 0xb8u, 0xffu, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 2u };
    libbgp_prefix6_t prefix = p6(prefix_addr, 40u);
    libbgp_packet_t update = make_update_mp_reach6(prefix, next_hop);
    libbgp_pattr_t *mp = libbgp_update_find_attr(&update.data.update, LIBBGP_PATTR_MP_REACH_IPV6);

    setup_out(&out_handler, &out);
    memset(&events, 0, sizeof(events));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_event_bus_init(&bus));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_event_bus_subscribe(&bus, LIBBGP_EVENT_SESSION_UP, event_capture, &events, NULL));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_event_bus_subscribe(&bus, LIBBGP_EVENT_SESSION_DOWN, event_capture, &events, NULL));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_event_bus_subscribe(&bus, LIBBGP_EVENT_ROUTE_ADDED, event_capture, &events, NULL));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, init_test_fsm(&fsm));
    libbgp_fsm_set_out_handler(&fsm, &out_handler);
    libbgp_fsm_set_event_bus(&fsm, &bus);
    establish(&fsm, &out, &events);

    LIBBGP_ASSERT(mp != NULL);
    mp->data.mp_reach_ipv6.nexthop_len = 15u;
    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_INVALID, libbgp_fsm_on_packet(&fsm, &update));
    LIBBGP_ASSERT_EQ_U64(LIBBGP_FSM_IDLE, libbgp_fsm_state(&fsm));
    LIBBGP_ASSERT_EQ_U64(3u, out.count);
    assert_sent_notification(&out, 2u, 3u, 5u);
    LIBBGP_ASSERT_EQ_U64(2u, events.count);
    LIBBGP_ASSERT_EQ_U64(LIBBGP_EVENT_SESSION_DOWN, events.types[1]);

    libbgp_packet_destroy(&update);
    libbgp_fsm_destroy(&fsm);
    libbgp_event_bus_destroy(&bus);
    libbgp_out_handler_destroy(&out_handler);
}

LIBBGP_TEST(fsm_established_invalid_update_sends_notification_before_reentrant_restart_open)
{
    libbgp_fsm_t fsm;
    libbgp_out_handler_t out_handler;
    libbgp_event_bus_t bus;
    out_ctx_t out;
    event_ctx_t events;
    restart_on_session_down_ctx_t restart;
    libbgp_prefix4_t prefix = p4(203u, 0u, 113u, 0u, 24u);
    libbgp_packet_t invalid = make_update_add_with_attrs(prefix, false, true, true);

    setup_out(&out_handler, &out);
    memset(&events, 0, sizeof(events));
    memset(&restart, 0, sizeof(restart));
    restart.fsm = &fsm;
    restart.start_err = LIBBGP_ERR_INVALID;
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_event_bus_init(&bus));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_event_bus_subscribe(&bus, LIBBGP_EVENT_SESSION_UP, event_capture, &events, NULL));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_event_bus_subscribe(&bus, LIBBGP_EVENT_SESSION_DOWN, event_capture, &events, NULL));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_event_bus_subscribe(&bus, LIBBGP_EVENT_SESSION_DOWN, restart_on_session_down, &restart, NULL));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, init_test_fsm(&fsm));
    libbgp_fsm_set_out_handler(&fsm, &out_handler);
    libbgp_fsm_set_event_bus(&fsm, &bus);
    establish(&fsm, &out, &events);

    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_INVALID, libbgp_fsm_on_packet(&fsm, &invalid));
    LIBBGP_ASSERT_EQ_U64(1u, restart.calls);
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, restart.start_err);
    LIBBGP_ASSERT_EQ_U64(LIBBGP_FSM_OPEN_SENT, libbgp_fsm_state(&fsm));
    LIBBGP_ASSERT_EQ_U64(0u, libbgp_fsm_peer_asn(&fsm));
    LIBBGP_ASSERT_EQ_U64(0u, libbgp_fsm_peer_bgp_id(&fsm));
    LIBBGP_ASSERT_EQ_U64(2u, events.count);
    LIBBGP_ASSERT_EQ_U64(LIBBGP_EVENT_SESSION_DOWN, events.types[1]);
    LIBBGP_ASSERT_EQ_U64(4u, out.count);
    assert_sent_notification(&out, 2u, 3u, 3u);
    LIBBGP_ASSERT_EQ_U64(LIBBGP_PACKET_OPEN, out.sent[3].type);

    libbgp_packet_destroy(&invalid);
    libbgp_fsm_destroy(&fsm);
    libbgp_event_bus_destroy(&bus);
    libbgp_out_handler_destroy(&out_handler);
}

LIBBGP_TEST(fsm_established_rejects_mp_reach6_without_peer_capability)
{
    struct libbgp_fsm_config config;
    libbgp_fsm_t fsm;
    libbgp_out_handler_t out_handler;
    libbgp_event_bus_t bus;
    libbgp_rib6_t rib;
    out_ctx_t out;
    event_ctx_t events;
    const uint8_t prefix_addr[16] = { 0x20u, 0x01u, 0x0du, 0xb8u, 0x23u };
    const uint8_t dest[16] = { 0x20u, 0x01u, 0x0du, 0xb8u, 0x23u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 1u };
    const uint8_t next_hop[16] = { 0x20u, 0x01u, 0x0du, 0xb8u, 0xffu, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 2u };
    libbgp_prefix6_t prefix = p6(prefix_addr, 40u);
    libbgp_packet_t open = make_open_packet_with_mpbgp6(65010u, 45u, ip4(198u, 51u, 100u, 10u), true, false);
    libbgp_packet_t keepalive = make_keepalive_packet();
    libbgp_packet_t update = make_update_mp_reach6(prefix, next_hop);
    const libbgp_rib6_route_t *route = NULL;

    config = test_fsm_config();
    setup_out(&out_handler, &out);
    memset(&events, 0, sizeof(events));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_event_bus_init(&bus));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_event_bus_subscribe(&bus, LIBBGP_EVENT_SESSION_UP, event_capture, &events, NULL));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_event_bus_subscribe(&bus, LIBBGP_EVENT_SESSION_DOWN, event_capture, &events, NULL));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_event_bus_subscribe(&bus, LIBBGP_EVENT_ROUTE_ADDED, event_capture, &events, NULL));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_rib6_init(&rib));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_fsm_init(&fsm, &config));
    libbgp_fsm_set_out_handler(&fsm, &out_handler);
    libbgp_fsm_set_event_bus(&fsm, &bus);
    libbgp_fsm_set_rib6(&fsm, &rib);

    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_fsm_start(&fsm));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_fsm_on_packet(&fsm, &open));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_fsm_on_packet(&fsm, &keepalive));
    LIBBGP_ASSERT_EQ_U64(LIBBGP_FSM_ESTABLISHED, libbgp_fsm_state(&fsm));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_INVALID, libbgp_fsm_on_packet(&fsm, &update));
    LIBBGP_ASSERT_EQ_U64(LIBBGP_FSM_IDLE, libbgp_fsm_state(&fsm));
    LIBBGP_ASSERT_EQ_U64(0u, libbgp_rib6_route_count(&rib));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_NOT_FOUND, libbgp_rib6_lookup_scoped(&rib, ip4(198u, 51u, 100u, 10u), dest, &route));
    LIBBGP_ASSERT_EQ_U64(2u, events.count);
    LIBBGP_ASSERT_EQ_U64(LIBBGP_EVENT_SESSION_UP, events.types[0]);
    LIBBGP_ASSERT_EQ_U64(LIBBGP_EVENT_SESSION_DOWN, events.types[1]);
    LIBBGP_ASSERT_EQ_U64(3u, out.count);
    assert_sent_notification(&out, 2u, 3u, 1u);

    libbgp_packet_destroy(&update);
    libbgp_packet_destroy(&keepalive);
    libbgp_packet_destroy(&open);
    libbgp_fsm_destroy(&fsm);
    libbgp_rib6_destroy(&rib);
    libbgp_event_bus_destroy(&bus);
    libbgp_out_handler_destroy(&out_handler);
}

LIBBGP_TEST(fsm_established_rejects_mp_reach6_when_local_capability_disabled)
{
    struct libbgp_fsm_config config;
    libbgp_fsm_t fsm;
    libbgp_out_handler_t out_handler;
    libbgp_event_bus_t bus;
    libbgp_rib6_t rib;
    out_ctx_t out;
    event_ctx_t events;
    const uint8_t prefix_addr[16] = { 0x20u, 0x01u, 0x0du, 0xb8u, 0x24u };
    const uint8_t dest[16] = { 0x20u, 0x01u, 0x0du, 0xb8u, 0x24u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 1u };
    const uint8_t next_hop[16] = { 0x20u, 0x01u, 0x0du, 0xb8u, 0xffu, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 2u };
    libbgp_prefix6_t prefix = p6(prefix_addr, 40u);
    libbgp_packet_t open = make_open_packet_with_mpbgp6(65010u, 45u, ip4(198u, 51u, 100u, 10u), true, true);
    libbgp_packet_t keepalive = make_keepalive_packet();
    libbgp_packet_t update = make_update_mp_reach6(prefix, next_hop);
    libbgp_packet_t local_open;
    const libbgp_rib6_route_t *route = NULL;
    size_t used = 0u;

    config = test_fsm_config();
    config.enable_mpbgp_ipv6 = false;
    setup_out(&out_handler, &out);
    memset(&events, 0, sizeof(events));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_event_bus_init(&bus));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_event_bus_subscribe(&bus, LIBBGP_EVENT_SESSION_UP, event_capture, &events, NULL));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_event_bus_subscribe(&bus, LIBBGP_EVENT_SESSION_DOWN, event_capture, &events, NULL));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_event_bus_subscribe(&bus, LIBBGP_EVENT_ROUTE_ADDED, event_capture, &events, NULL));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_rib6_init(&rib));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_fsm_init(&fsm, &config));
    libbgp_fsm_set_out_handler(&fsm, &out_handler);
    libbgp_fsm_set_event_bus(&fsm, &bus);
    libbgp_fsm_set_rib6(&fsm, &rib);

    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_fsm_start(&fsm));
    libbgp_packet_init(&local_open);
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_packet_parse(&local_open, out.sent[0].bytes, out.sent[0].len, &used));
    LIBBGP_ASSERT(!libbgp_open_has_mpbgp(&local_open.data.open, LIBBGP_AFI_IPV6, LIBBGP_SAFI_UNICAST));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_fsm_on_packet(&fsm, &open));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_fsm_on_packet(&fsm, &keepalive));
    LIBBGP_ASSERT_EQ_U64(LIBBGP_FSM_ESTABLISHED, libbgp_fsm_state(&fsm));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_INVALID, libbgp_fsm_on_packet(&fsm, &update));
    LIBBGP_ASSERT_EQ_U64(LIBBGP_FSM_IDLE, libbgp_fsm_state(&fsm));
    LIBBGP_ASSERT_EQ_U64(0u, libbgp_rib6_route_count(&rib));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_NOT_FOUND, libbgp_rib6_lookup_scoped(&rib, ip4(198u, 51u, 100u, 10u), dest, &route));
    LIBBGP_ASSERT_EQ_U64(2u, events.count);
    LIBBGP_ASSERT_EQ_U64(LIBBGP_EVENT_SESSION_UP, events.types[0]);
    LIBBGP_ASSERT_EQ_U64(LIBBGP_EVENT_SESSION_DOWN, events.types[1]);
    LIBBGP_ASSERT_EQ_U64(3u, out.count);
    assert_sent_notification(&out, 2u, 3u, 1u);

    libbgp_packet_destroy(&local_open);
    libbgp_packet_destroy(&update);
    libbgp_packet_destroy(&keepalive);
    libbgp_packet_destroy(&open);
    libbgp_fsm_destroy(&fsm);
    libbgp_rib6_destroy(&rib);
    libbgp_event_bus_destroy(&bus);
    libbgp_out_handler_destroy(&out_handler);
}

LIBBGP_TEST(fsm_established_update_mp_unreach6_withdraws_rib6_route)
{
    libbgp_fsm_t fsm;
    libbgp_out_handler_t out_handler;
    libbgp_event_bus_t bus;
    libbgp_rib6_t rib;
    out_ctx_t out;
    event_ctx_t events;
    const uint8_t prefix_addr[16] = { 0x20u, 0x01u, 0x0du, 0xb8u, 0x10u };
    const uint8_t dest[16] = { 0x20u, 0x01u, 0x0du, 0xb8u, 0x10u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 1u };
    const uint8_t next_hop[16] = { 0x20u, 0x01u, 0x0du, 0xb8u, 0xffu, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 1u };
    libbgp_prefix6_t prefix = p6(prefix_addr, 40u);
    libbgp_packet_t add = make_update_mp_reach6(prefix, next_hop);
    libbgp_packet_t withdraw = make_update_mp_unreach6(prefix);
    const libbgp_rib6_route_t *route = NULL;

    setup_out(&out_handler, &out);
    memset(&events, 0, sizeof(events));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_event_bus_init(&bus));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_event_bus_subscribe(&bus, LIBBGP_EVENT_SESSION_UP, event_capture, &events, NULL));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_event_bus_subscribe(&bus, LIBBGP_EVENT_ROUTE_ADDED, event_capture, &events, NULL));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_event_bus_subscribe(&bus, LIBBGP_EVENT_ROUTE_WITHDRAWN, event_capture, &events, NULL));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_rib6_init(&rib));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, init_test_fsm(&fsm));
    libbgp_fsm_set_out_handler(&fsm, &out_handler);
    libbgp_fsm_set_event_bus(&fsm, &bus);
    libbgp_fsm_set_rib6(&fsm, &rib);
    establish(&fsm, &out, &events);

    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_fsm_on_packet(&fsm, &add));
    LIBBGP_ASSERT_EQ_U64(1u, libbgp_rib6_route_count(&rib));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_fsm_on_packet(&fsm, &withdraw));
    LIBBGP_ASSERT_EQ_U64(3u, events.count);
    LIBBGP_ASSERT_EQ_U64(LIBBGP_EVENT_ROUTE_ADDED, events.types[1]);
    LIBBGP_ASSERT_EQ_U64(LIBBGP_EVENT_ROUTE_WITHDRAWN, events.types[2]);
    LIBBGP_ASSERT(!events.has_prefix4[1]);
    LIBBGP_ASSERT(events.has_prefix6[1]);
    LIBBGP_ASSERT(libbgp_prefix6_eq(&prefix, &events.prefixes6[1]));
    LIBBGP_ASSERT(!events.has_prefix4[2]);
    LIBBGP_ASSERT(events.has_prefix6[2]);
    LIBBGP_ASSERT(libbgp_prefix6_eq(&prefix, &events.prefixes6[2]));
    LIBBGP_ASSERT_EQ_U64(0u, libbgp_rib6_route_count(&rib));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_NOT_FOUND, libbgp_rib6_lookup_scoped(&rib, ip4(198u, 51u, 100u, 10u), dest, &route));

    libbgp_packet_destroy(&withdraw);
    libbgp_packet_destroy(&add);
    libbgp_fsm_destroy(&fsm);
    libbgp_rib6_destroy(&rib);
    libbgp_event_bus_destroy(&bus);
    libbgp_out_handler_destroy(&out_handler);
}

LIBBGP_TEST(fsm_established_update_mp_unreach6_publishes_event_without_rib6)
{
    libbgp_fsm_t fsm;
    libbgp_out_handler_t out_handler;
    libbgp_event_bus_t bus;
    out_ctx_t out;
    event_ctx_t events;
    const uint8_t prefix_addr[16] = { 0x20u, 0x01u, 0x0du, 0xb8u, 0x30u };
    libbgp_prefix6_t prefix = p6(prefix_addr, 40u);
    libbgp_packet_t update = make_update_mp_unreach6(prefix);

    setup_out(&out_handler, &out);
    memset(&events, 0, sizeof(events));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_event_bus_init(&bus));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_event_bus_subscribe(&bus, LIBBGP_EVENT_SESSION_UP, event_capture, &events, NULL));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_event_bus_subscribe(&bus, LIBBGP_EVENT_ROUTE_WITHDRAWN, event_capture, &events, NULL));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, init_test_fsm(&fsm));
    libbgp_fsm_set_out_handler(&fsm, &out_handler);
    libbgp_fsm_set_event_bus(&fsm, &bus);
    establish(&fsm, &out, &events);

    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_fsm_on_packet(&fsm, &update));
    LIBBGP_ASSERT_EQ_U64(2u, events.count);
    LIBBGP_ASSERT_EQ_U64(LIBBGP_EVENT_ROUTE_WITHDRAWN, events.types[1]);
    LIBBGP_ASSERT(!events.has_prefix4[1]);
    LIBBGP_ASSERT(events.has_prefix6[1]);
    LIBBGP_ASSERT(libbgp_prefix6_eq(&prefix, &events.prefixes6[1]));

    libbgp_packet_destroy(&update);
    libbgp_fsm_destroy(&fsm);
    libbgp_event_bus_destroy(&bus);
    libbgp_out_handler_destroy(&out_handler);
}

LIBBGP_TEST(fsm_established_update_reentrant_restart_preserves_replacement_route)
{
    libbgp_fsm_t fsm;
    libbgp_out_handler_t out_handler;
    libbgp_event_bus_t bus;
    libbgp_rib4_t rib;
    out_ctx_t out;
    event_ctx_t events;
    reentrant_replace_route_ctx_t replace;
    libbgp_prefix4_t prefix = p4(203u, 0u, 113u, 0u, 24u);
    libbgp_packet_t stale = make_update_add(prefix, ip4(192u, 0u, 2u, 1u));
    libbgp_packet_t replacement = make_update_add(prefix, ip4(192u, 0u, 2u, 222u));
    const libbgp_rib4_route_t *route = NULL;

    setup_out(&out_handler, &out);
    memset(&events, 0, sizeof(events));
    memset(&replace, 0, sizeof(replace));
    replace.fsm = &fsm;
    replace.replacement = &replacement;
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_event_bus_init(&bus));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_event_bus_subscribe(&bus, LIBBGP_EVENT_SESSION_UP, event_capture, &events, NULL));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_event_bus_subscribe(&bus, LIBBGP_EVENT_ROUTE_ADDED, restart_and_replace_on_first_route_added, &replace, NULL));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_rib4_init(&rib));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, init_test_fsm(&fsm));
    libbgp_fsm_set_out_handler(&fsm, &out_handler);
    libbgp_fsm_set_event_bus(&fsm, &bus);
    libbgp_fsm_set_rib4(&fsm, &rib);
    establish(&fsm, &out, &events);

    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_fsm_on_packet(&fsm, &stale));
    LIBBGP_ASSERT_EQ_U64(1u, replace.calls);
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, replace.stop_err);
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, replace.start_err);
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, replace.open_err);
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, replace.keepalive_err);
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, replace.update_err);
    LIBBGP_ASSERT_EQ_U64(LIBBGP_FSM_ESTABLISHED, libbgp_fsm_state(&fsm));
    LIBBGP_ASSERT_EQ_U64(1u, libbgp_rib4_route_count(&rib));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_rib4_lookup_scoped(&rib, ip4(198u, 51u, 100u, 10u), ip4(203u, 0u, 113u, 44u), &route));
    LIBBGP_ASSERT_EQ_U64(ip4(192u, 0u, 2u, 222u), route->next_hop);

    libbgp_packet_destroy(&replacement);
    libbgp_packet_destroy(&stale);
    libbgp_fsm_destroy(&fsm);
    libbgp_rib4_destroy(&rib);
    libbgp_event_bus_destroy(&bus);
    libbgp_out_handler_destroy(&out_handler);
}

LIBBGP_TEST(fsm_established_update_reentrant_restart_skips_later_stale_nlri)
{
    libbgp_fsm_t fsm;
    libbgp_out_handler_t out_handler;
    libbgp_event_bus_t bus;
    libbgp_rib4_t rib;
    out_ctx_t out;
    event_ctx_t events;
    reentrant_replace_route_ctx_t replace;
    libbgp_prefix4_t stale_prefixes[2];
    libbgp_packet_t stale;
    libbgp_packet_t replacement;
    const libbgp_rib4_route_t *route = NULL;
    size_t stale_target_events = 0u;
    size_t route_added_events = 0u;
    size_t i;

    stale_prefixes[0] = p4(203u, 0u, 113u, 0u, 24u);
    stale_prefixes[1] = p4(198u, 51u, 100u, 0u, 24u);
    stale = make_update_add_multi(stale_prefixes, LIBBGP_ARRAY_LEN(stale_prefixes), ip4(192u, 0u, 2u, 1u));
    replacement = make_update_add(stale_prefixes[1], ip4(192u, 0u, 2u, 222u));

    setup_out(&out_handler, &out);
    memset(&events, 0, sizeof(events));
    memset(&replace, 0, sizeof(replace));
    replace.fsm = &fsm;
    replace.replacement = &replacement;
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_event_bus_init(&bus));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_event_bus_subscribe(&bus, LIBBGP_EVENT_SESSION_UP, event_capture, &events, NULL));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_event_bus_subscribe(&bus, LIBBGP_EVENT_SESSION_DOWN, event_capture, &events, NULL));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_event_bus_subscribe(&bus, LIBBGP_EVENT_ROUTE_ADDED, event_capture, &events, NULL));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_event_bus_subscribe(&bus, LIBBGP_EVENT_ROUTE_ADDED, restart_and_replace_on_first_route_added, &replace, NULL));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_rib4_init(&rib));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, init_test_fsm(&fsm));
    libbgp_fsm_set_out_handler(&fsm, &out_handler);
    libbgp_fsm_set_event_bus(&fsm, &bus);
    libbgp_fsm_set_rib4(&fsm, &rib);
    establish(&fsm, &out, &events);

    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_fsm_on_packet(&fsm, &stale));
    LIBBGP_ASSERT_EQ_U64(1u, replace.calls);
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, replace.stop_err);
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, replace.start_err);
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, replace.open_err);
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, replace.keepalive_err);
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, replace.update_err);
    LIBBGP_ASSERT_EQ_U64(LIBBGP_FSM_ESTABLISHED, libbgp_fsm_state(&fsm));
    LIBBGP_ASSERT_EQ_U64(1u, libbgp_rib4_route_count(&rib));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_NOT_FOUND, libbgp_rib4_lookup_scoped(&rib, ip4(198u, 51u, 100u, 10u), ip4(203u, 0u, 113u, 44u), &route));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_rib4_lookup_scoped(&rib, ip4(198u, 51u, 100u, 10u), ip4(198u, 51u, 100u, 44u), &route));
    LIBBGP_ASSERT_EQ_U64(ip4(192u, 0u, 2u, 222u), route->next_hop);

    for (i = 0u; i < events.count; i++) {
        if (events.types[i] == LIBBGP_EVENT_ROUTE_ADDED) {
            route_added_events++;
            if (events.updates[i] == &stale.data.update &&
                libbgp_prefix4_eq(&events.prefixes[i], &stale_prefixes[1])) {
                stale_target_events++;
            }
        }
    }
    LIBBGP_ASSERT_EQ_U64(2u, route_added_events);
    LIBBGP_ASSERT_EQ_U64(0u, stale_target_events);

    libbgp_packet_destroy(&replacement);
    libbgp_packet_destroy(&stale);
    libbgp_fsm_destroy(&fsm);
    libbgp_rib4_destroy(&rib);
    libbgp_event_bus_destroy(&bus);
    libbgp_out_handler_destroy(&out_handler);
}

LIBBGP_TEST(fsm_established_update_reentrant_stop_does_not_restore_replaced_ipv4_route)
{
    libbgp_fsm_t fsm;
    libbgp_out_handler_t out_handler;
    libbgp_event_bus_t bus;
    libbgp_rib4_t rib;
    out_ctx_t out;
    event_ctx_t events;
    stop_on_route_ctx_t stop;
    libbgp_prefix4_t prefix = p4(203u, 0u, 113u, 0u, 24u);
    libbgp_packet_t old_route = make_update_add(prefix, ip4(192u, 0u, 2u, 44u));
    libbgp_packet_t replacement = make_update_add(prefix, ip4(192u, 0u, 2u, 222u));
    const libbgp_rib4_route_t *route = NULL;

    setup_out(&out_handler, &out);
    memset(&events, 0, sizeof(events));
    memset(&stop, 0, sizeof(stop));
    stop.fsm = &fsm;
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_event_bus_init(&bus));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_event_bus_subscribe(&bus, LIBBGP_EVENT_SESSION_UP, event_capture, &events, NULL));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_event_bus_subscribe(&bus, LIBBGP_EVENT_SESSION_DOWN, event_capture, &events, NULL));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_rib4_init(&rib));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, init_test_fsm(&fsm));
    libbgp_fsm_set_out_handler(&fsm, &out_handler);
    libbgp_fsm_set_event_bus(&fsm, &bus);
    libbgp_fsm_set_rib4(&fsm, &rib);
    establish(&fsm, &out, &events);
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_fsm_on_packet(&fsm, &old_route));
    LIBBGP_ASSERT_EQ_U64(1u, libbgp_rib4_route_count(&rib));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_event_bus_subscribe(&bus, LIBBGP_EVENT_ROUTE_ADDED, stop_on_first_route_added, &stop, NULL));

    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_fsm_on_packet(&fsm, &replacement));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, stop.stop_err);
    LIBBGP_ASSERT_EQ_U64(1u, stop.route_events);
    LIBBGP_ASSERT_EQ_U64(LIBBGP_FSM_IDLE, libbgp_fsm_state(&fsm));
    LIBBGP_ASSERT_EQ_U64(0u, libbgp_rib4_route_count(&rib));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_NOT_FOUND, libbgp_rib4_lookup_scoped(&rib, ip4(198u, 51u, 100u, 10u), ip4(203u, 0u, 113u, 44u), &route));

    libbgp_packet_destroy(&replacement);
    libbgp_packet_destroy(&old_route);
    libbgp_fsm_destroy(&fsm);
    libbgp_rib4_destroy(&rib);
    libbgp_event_bus_destroy(&bus);
    libbgp_out_handler_destroy(&out_handler);
}

LIBBGP_TEST(fsm_established_update_reentrant_restart_does_not_restore_withdrawn_ipv4_route)
{
    libbgp_fsm_t fsm;
    libbgp_out_handler_t out_handler;
    libbgp_event_bus_t bus;
    libbgp_rib4_t rib;
    out_ctx_t out;
    event_ctx_t events;
    restart_on_route_ctx_t restart;
    libbgp_prefix4_t prefix = p4(203u, 0u, 113u, 0u, 24u);
    libbgp_packet_t old_route = make_update_add(prefix, ip4(192u, 0u, 2u, 44u));
    libbgp_packet_t withdraw = make_update_withdraw(prefix);
    const libbgp_rib4_route_t *route = NULL;

    setup_out(&out_handler, &out);
    memset(&events, 0, sizeof(events));
    memset(&restart, 0, sizeof(restart));
    restart.fsm = &fsm;
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_event_bus_init(&bus));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_event_bus_subscribe(&bus, LIBBGP_EVENT_SESSION_UP, event_capture, &events, NULL));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_event_bus_subscribe(&bus, LIBBGP_EVENT_SESSION_DOWN, event_capture, &events, NULL));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_rib4_init(&rib));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, init_test_fsm(&fsm));
    libbgp_fsm_set_out_handler(&fsm, &out_handler);
    libbgp_fsm_set_event_bus(&fsm, &bus);
    libbgp_fsm_set_rib4(&fsm, &rib);
    establish(&fsm, &out, &events);
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_fsm_on_packet(&fsm, &old_route));
    LIBBGP_ASSERT_EQ_U64(1u, libbgp_rib4_route_count(&rib));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_event_bus_subscribe(&bus, LIBBGP_EVENT_ROUTE_WITHDRAWN, restart_on_first_route_withdrawn, &restart, NULL));

    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_fsm_on_packet(&fsm, &withdraw));
    LIBBGP_ASSERT_EQ_U64(1u, restart.route_events);
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, restart.stop_err);
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, restart.start_err);
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, restart.open_err);
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, restart.keepalive_err);
    LIBBGP_ASSERT_EQ_U64(LIBBGP_FSM_ESTABLISHED, libbgp_fsm_state(&fsm));
    LIBBGP_ASSERT_EQ_U64(0u, libbgp_rib4_route_count(&rib));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_NOT_FOUND, libbgp_rib4_lookup_scoped(&rib, ip4(198u, 51u, 100u, 10u), ip4(203u, 0u, 113u, 44u), &route));

    libbgp_packet_destroy(&withdraw);
    libbgp_packet_destroy(&old_route);
    libbgp_fsm_destroy(&fsm);
    libbgp_rib4_destroy(&rib);
    libbgp_event_bus_destroy(&bus);
    libbgp_out_handler_destroy(&out_handler);
}

LIBBGP_TEST(fsm_established_update_reentrant_restart_does_not_restore_withdrawn_ipv6_route)
{
    static const uint8_t prefix_addr[16] = { 0x20u, 0x01u, 0x0du, 0xb8u, 0x64u };
    static const uint8_t dest[16] = { 0x20u, 0x01u, 0x0du, 0xb8u, 0x64u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 1u };
    static const uint8_t next_hop[16] = { 0x20u, 0x01u, 0x0du, 0xb8u, 0xffu, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 6u };
    libbgp_fsm_t fsm;
    libbgp_out_handler_t out_handler;
    libbgp_event_bus_t bus;
    libbgp_rib6_t rib;
    out_ctx_t out;
    event_ctx_t events;
    restart_on_route_ctx_t restart;
    libbgp_prefix6_t prefix = p6(prefix_addr, 40u);
    libbgp_packet_t old_route = make_update_mp_reach6(prefix, next_hop);
    libbgp_packet_t withdraw = make_update_mp_unreach6(prefix);
    const libbgp_rib6_route_t *route = NULL;

    setup_out(&out_handler, &out);
    memset(&events, 0, sizeof(events));
    memset(&restart, 0, sizeof(restart));
    restart.fsm = &fsm;
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_event_bus_init(&bus));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_event_bus_subscribe(&bus, LIBBGP_EVENT_SESSION_UP, event_capture, &events, NULL));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_event_bus_subscribe(&bus, LIBBGP_EVENT_SESSION_DOWN, event_capture, &events, NULL));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_rib6_init(&rib));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, init_test_fsm(&fsm));
    libbgp_fsm_set_out_handler(&fsm, &out_handler);
    libbgp_fsm_set_event_bus(&fsm, &bus);
    libbgp_fsm_set_rib6(&fsm, &rib);
    establish(&fsm, &out, &events);
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_fsm_on_packet(&fsm, &old_route));
    LIBBGP_ASSERT_EQ_U64(1u, libbgp_rib6_route_count(&rib));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_event_bus_subscribe(&bus, LIBBGP_EVENT_ROUTE_WITHDRAWN, restart_on_first_route_withdrawn, &restart, NULL));

    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_fsm_on_packet(&fsm, &withdraw));
    LIBBGP_ASSERT_EQ_U64(1u, restart.route_events);
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, restart.stop_err);
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, restart.start_err);
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, restart.open_err);
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, restart.keepalive_err);
    LIBBGP_ASSERT_EQ_U64(LIBBGP_FSM_ESTABLISHED, libbgp_fsm_state(&fsm));
    LIBBGP_ASSERT_EQ_U64(0u, libbgp_rib6_route_count(&rib));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_NOT_FOUND, libbgp_rib6_lookup_scoped(&rib, ip4(198u, 51u, 100u, 10u), dest, &route));

    libbgp_packet_destroy(&withdraw);
    libbgp_packet_destroy(&old_route);
    libbgp_fsm_destroy(&fsm);
    libbgp_rib6_destroy(&rib);
    libbgp_event_bus_destroy(&bus);
    libbgp_out_handler_destroy(&out_handler);
}

LIBBGP_TEST(fsm_notification_moves_idle_and_session_down)
{
    libbgp_fsm_t fsm;
    libbgp_out_handler_t out_handler;
    libbgp_event_bus_t bus;
    out_ctx_t out;
    event_ctx_t events;
    libbgp_packet_t notification = make_notification_packet(6u, 2u);

    setup_out(&out_handler, &out);
    memset(&events, 0, sizeof(events));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_event_bus_init(&bus));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_event_bus_subscribe(&bus, LIBBGP_EVENT_SESSION_UP, event_capture, &events, NULL));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_event_bus_subscribe(&bus, LIBBGP_EVENT_SESSION_DOWN, event_capture, &events, NULL));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, init_test_fsm(&fsm));
    libbgp_fsm_set_out_handler(&fsm, &out_handler);
    libbgp_fsm_set_event_bus(&fsm, &bus);
    establish(&fsm, &out, &events);

    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_fsm_on_packet(&fsm, &notification));
    LIBBGP_ASSERT_EQ_U64(LIBBGP_FSM_IDLE, libbgp_fsm_state(&fsm));
    LIBBGP_ASSERT_EQ_U64(2u, events.count);
    LIBBGP_ASSERT_EQ_U64(LIBBGP_EVENT_SESSION_DOWN, events.types[1]);
    libbgp_packet_destroy(&notification);
    libbgp_fsm_destroy(&fsm);
    libbgp_event_bus_destroy(&bus);
    libbgp_out_handler_destroy(&out_handler);
}

LIBBGP_TEST(fsm_notification_discards_learned_rib4_and_rib6_routes)
{
    libbgp_fsm_t fsm;
    libbgp_out_handler_t out_handler;
    libbgp_event_bus_t bus;
    libbgp_rib4_t rib4;
    libbgp_rib6_t rib6;
    out_ctx_t out;
    event_ctx_t events;
    libbgp_prefix4_t prefix4 = p4(203u, 0u, 113u, 0u, 24u);
    const uint8_t prefix6_addr[16] = { 0x20u, 0x01u, 0x0du, 0xb8u, 0x10u };
    const uint8_t dest6[16] = { 0x20u, 0x01u, 0x0du, 0xb8u, 0x10u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 1u };
    const uint8_t next_hop6[16] = { 0x20u, 0x01u, 0x0du, 0xb8u, 0xffu, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 1u };
    libbgp_prefix6_t prefix6 = p6(prefix6_addr, 40u);
    libbgp_packet_t add4 = make_update_add(prefix4, ip4(192u, 0u, 2u, 254u));
    libbgp_packet_t add6 = make_update_mp_reach6(prefix6, next_hop6);
    libbgp_packet_t notification = make_notification_packet(6u, 2u);
    const libbgp_rib4_route_t *route4 = NULL;
    const libbgp_rib6_route_t *route6 = NULL;

    setup_out(&out_handler, &out);
    memset(&events, 0, sizeof(events));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_event_bus_init(&bus));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_event_bus_subscribe(&bus, LIBBGP_EVENT_SESSION_UP, event_capture, &events, NULL));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_event_bus_subscribe(&bus, LIBBGP_EVENT_SESSION_DOWN, event_capture, &events, NULL));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_rib4_init(&rib4));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_rib6_init(&rib6));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, init_test_fsm(&fsm));
    libbgp_fsm_set_out_handler(&fsm, &out_handler);
    libbgp_fsm_set_event_bus(&fsm, &bus);
    libbgp_fsm_set_rib4(&fsm, &rib4);
    libbgp_fsm_set_rib6(&fsm, &rib6);
    establish(&fsm, &out, &events);

    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_fsm_on_packet(&fsm, &add4));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_fsm_on_packet(&fsm, &add6));
    LIBBGP_ASSERT_EQ_U64(1u, libbgp_rib4_route_count(&rib4));
    LIBBGP_ASSERT_EQ_U64(1u, libbgp_rib6_route_count(&rib6));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_fsm_on_packet(&fsm, &notification));
    LIBBGP_ASSERT_EQ_U64(0u, libbgp_rib4_route_count(&rib4));
    LIBBGP_ASSERT_EQ_U64(0u, libbgp_rib6_route_count(&rib6));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_NOT_FOUND, libbgp_rib4_lookup_scoped(&rib4, ip4(198u, 51u, 100u, 10u), ip4(203u, 0u, 113u, 44u), &route4));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_NOT_FOUND, libbgp_rib6_lookup_scoped(&rib6, ip4(198u, 51u, 100u, 10u), dest6, &route6));

    libbgp_packet_destroy(&notification);
    libbgp_packet_destroy(&add6);
    libbgp_packet_destroy(&add4);
    libbgp_fsm_destroy(&fsm);
    libbgp_rib6_destroy(&rib6);
    libbgp_rib4_destroy(&rib4);
    libbgp_event_bus_destroy(&bus);
    libbgp_out_handler_destroy(&out_handler);
}

LIBBGP_TEST(fsm_invalid_update_discards_learned_rib4_and_rib6_routes)
{
    libbgp_fsm_t fsm;
    libbgp_out_handler_t out_handler;
    libbgp_event_bus_t bus;
    libbgp_rib4_t rib4;
    libbgp_rib6_t rib6;
    out_ctx_t out;
    event_ctx_t events;
    libbgp_prefix4_t prefix4 = p4(203u, 0u, 113u, 0u, 24u);
    const uint8_t prefix6_addr[16] = { 0x20u, 0x01u, 0x0du, 0xb8u, 0x10u };
    const uint8_t dest6[16] = { 0x20u, 0x01u, 0x0du, 0xb8u, 0x10u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 1u };
    const uint8_t next_hop6[16] = { 0x20u, 0x01u, 0x0du, 0xb8u, 0xffu, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 1u };
    libbgp_prefix6_t prefix6 = p6(prefix6_addr, 40u);
    libbgp_packet_t add4 = make_update_add(prefix4, ip4(192u, 0u, 2u, 254u));
    libbgp_packet_t add6 = make_update_mp_reach6(prefix6, next_hop6);
    libbgp_packet_t invalid = make_update_add_with_attrs(prefix4, false, true, true);
    const libbgp_rib4_route_t *route4 = NULL;
    const libbgp_rib6_route_t *route6 = NULL;

    setup_out(&out_handler, &out);
    memset(&events, 0, sizeof(events));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_event_bus_init(&bus));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_event_bus_subscribe(&bus, LIBBGP_EVENT_SESSION_UP, event_capture, &events, NULL));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_event_bus_subscribe(&bus, LIBBGP_EVENT_SESSION_DOWN, event_capture, &events, NULL));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_rib4_init(&rib4));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_rib6_init(&rib6));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, init_test_fsm(&fsm));
    libbgp_fsm_set_out_handler(&fsm, &out_handler);
    libbgp_fsm_set_event_bus(&fsm, &bus);
    libbgp_fsm_set_rib4(&fsm, &rib4);
    libbgp_fsm_set_rib6(&fsm, &rib6);
    establish(&fsm, &out, &events);

    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_fsm_on_packet(&fsm, &add4));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_fsm_on_packet(&fsm, &add6));
    LIBBGP_ASSERT_EQ_U64(1u, libbgp_rib4_route_count(&rib4));
    LIBBGP_ASSERT_EQ_U64(1u, libbgp_rib6_route_count(&rib6));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_INVALID, libbgp_fsm_on_packet(&fsm, &invalid));
    LIBBGP_ASSERT_EQ_U64(LIBBGP_FSM_IDLE, libbgp_fsm_state(&fsm));
    LIBBGP_ASSERT_EQ_U64(0u, libbgp_rib4_route_count(&rib4));
    LIBBGP_ASSERT_EQ_U64(0u, libbgp_rib6_route_count(&rib6));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_NOT_FOUND, libbgp_rib4_lookup_scoped(&rib4, ip4(198u, 51u, 100u, 10u), ip4(203u, 0u, 113u, 44u), &route4));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_NOT_FOUND, libbgp_rib6_lookup_scoped(&rib6, ip4(198u, 51u, 100u, 10u), dest6, &route6));
    LIBBGP_ASSERT_EQ_U64(3u, out.count);
    assert_sent_notification(&out, 2u, 3u, 3u);
    LIBBGP_ASSERT_EQ_U64(2u, events.count);
    LIBBGP_ASSERT_EQ_U64(LIBBGP_EVENT_SESSION_DOWN, events.types[1]);

    libbgp_packet_destroy(&invalid);
    libbgp_packet_destroy(&add6);
    libbgp_packet_destroy(&add4);
    libbgp_fsm_destroy(&fsm);
    libbgp_rib6_destroy(&rib6);
    libbgp_rib4_destroy(&rib4);
    libbgp_event_bus_destroy(&bus);
    libbgp_out_handler_destroy(&out_handler);
}

LIBBGP_TEST(fsm_invalid_update_notification_send_failure_still_tears_down)
{
    libbgp_fsm_t fsm;
    libbgp_out_handler_t out_handler;
    libbgp_event_bus_t bus;
    fail_after_send_ctx_t fail_after;
    event_ctx_t events;
    libbgp_prefix4_t prefix = p4(203u, 0u, 113u, 0u, 24u);
    libbgp_packet_t invalid = make_update_add_with_attrs(prefix, false, true, true);

    memset(&fail_after, 0, sizeof(fail_after));
    fail_after.fail_on_call = 3u;
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_out_handler_init(&out_handler));
    set_out_send_fn(&out_handler, fail_after_send, &fail_after);
    memset(&events, 0, sizeof(events));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_event_bus_init(&bus));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_event_bus_subscribe(&bus, LIBBGP_EVENT_SESSION_UP, event_capture, &events, NULL));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_event_bus_subscribe(&bus, LIBBGP_EVENT_SESSION_DOWN, event_capture, &events, NULL));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, init_test_fsm(&fsm));
    libbgp_fsm_set_out_handler(&fsm, &out_handler);
    libbgp_fsm_set_event_bus(&fsm, &bus);
    establish(&fsm, &fail_after.out, &events);

    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_WRITE, libbgp_fsm_on_packet(&fsm, &invalid));
    LIBBGP_ASSERT_EQ_U64(LIBBGP_FSM_IDLE, libbgp_fsm_state(&fsm));
    LIBBGP_ASSERT_EQ_U64(2u, fail_after.out.count);
    LIBBGP_ASSERT_EQ_U64(2u, events.count);
    LIBBGP_ASSERT_EQ_U64(LIBBGP_EVENT_SESSION_DOWN, events.types[1]);

    libbgp_packet_destroy(&invalid);
    libbgp_fsm_destroy(&fsm);
    libbgp_event_bus_destroy(&bus);
    libbgp_out_handler_destroy(&out_handler);
}

LIBBGP_TEST(fsm_stop_established_sends_cease_before_reentrant_restart_open)
{
    libbgp_fsm_t fsm;
    libbgp_out_handler_t out_handler;
    libbgp_event_bus_t bus;
    out_ctx_t out;
    event_ctx_t events;
    restart_on_session_down_ctx_t restart;

    setup_out(&out_handler, &out);
    memset(&events, 0, sizeof(events));
    memset(&restart, 0, sizeof(restart));
    restart.fsm = &fsm;
    restart.start_err = LIBBGP_ERR_INVALID;
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_event_bus_init(&bus));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_event_bus_subscribe(&bus, LIBBGP_EVENT_SESSION_UP, event_capture, &events, NULL));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_event_bus_subscribe(&bus, LIBBGP_EVENT_SESSION_DOWN, event_capture, &events, NULL));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_event_bus_subscribe(&bus, LIBBGP_EVENT_SESSION_DOWN, restart_on_session_down, &restart, NULL));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, init_test_fsm(&fsm));
    libbgp_fsm_set_out_handler(&fsm, &out_handler);
    libbgp_fsm_set_event_bus(&fsm, &bus);
    establish(&fsm, &out, &events);

    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_fsm_stop(&fsm));
    LIBBGP_ASSERT_EQ_U64(1u, restart.calls);
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, restart.start_err);
    LIBBGP_ASSERT_EQ_U64(LIBBGP_FSM_OPEN_SENT, libbgp_fsm_state(&fsm));
    LIBBGP_ASSERT_EQ_U64(2u, events.count);
    LIBBGP_ASSERT_EQ_U64(LIBBGP_EVENT_SESSION_DOWN, events.types[1]);
    LIBBGP_ASSERT_EQ_U64(4u, out.count);
    assert_sent_notification(&out, 2u, 6u, 0u);
    LIBBGP_ASSERT_EQ_U64(LIBBGP_PACKET_OPEN, out.sent[3].type);

    libbgp_fsm_destroy(&fsm);
    libbgp_event_bus_destroy(&bus);
    libbgp_out_handler_destroy(&out_handler);
}

LIBBGP_TEST(fsm_stop_established_publishes_session_down_and_discards_routes)
{
    libbgp_fsm_t fsm;
    libbgp_out_handler_t out_handler;
    libbgp_event_bus_t bus;
    libbgp_rib4_t rib4;
    libbgp_rib6_t rib6;
    out_ctx_t out;
    event_ctx_t events;
    libbgp_prefix4_t prefix4 = p4(203u, 0u, 113u, 0u, 24u);
    const uint8_t prefix6_addr[16] = { 0x20u, 0x01u, 0x0du, 0xb8u, 0x20u };
    const uint8_t dest6[16] = { 0x20u, 0x01u, 0x0du, 0xb8u, 0x20u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 1u };
    const uint8_t next_hop6[16] = { 0x20u, 0x01u, 0x0du, 0xb8u, 0xffu, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 1u };
    libbgp_prefix6_t prefix6 = p6(prefix6_addr, 40u);
    libbgp_packet_t add4 = make_update_add(prefix4, ip4(192u, 0u, 2u, 254u));
    libbgp_packet_t add6 = make_update_mp_reach6(prefix6, next_hop6);
    const libbgp_rib4_route_t *route4 = NULL;
    const libbgp_rib6_route_t *route6 = NULL;

    setup_out(&out_handler, &out);
    memset(&events, 0, sizeof(events));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_event_bus_init(&bus));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_event_bus_subscribe(&bus, LIBBGP_EVENT_SESSION_UP, event_capture, &events, NULL));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_event_bus_subscribe(&bus, LIBBGP_EVENT_SESSION_DOWN, event_capture, &events, NULL));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_rib4_init(&rib4));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_rib6_init(&rib6));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, init_test_fsm(&fsm));
    libbgp_fsm_set_out_handler(&fsm, &out_handler);
    libbgp_fsm_set_event_bus(&fsm, &bus);
    libbgp_fsm_set_rib4(&fsm, &rib4);
    libbgp_fsm_set_rib6(&fsm, &rib6);
    establish(&fsm, &out, &events);

    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_fsm_on_packet(&fsm, &add4));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_fsm_on_packet(&fsm, &add6));
    LIBBGP_ASSERT_EQ_U64(1u, libbgp_rib4_route_count(&rib4));
    LIBBGP_ASSERT_EQ_U64(1u, libbgp_rib6_route_count(&rib6));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_fsm_stop(&fsm));
    LIBBGP_ASSERT_EQ_U64(LIBBGP_FSM_IDLE, libbgp_fsm_state(&fsm));
    LIBBGP_ASSERT_EQ_U64(0u, libbgp_rib4_route_count(&rib4));
    LIBBGP_ASSERT_EQ_U64(0u, libbgp_rib6_route_count(&rib6));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_NOT_FOUND, libbgp_rib4_lookup_scoped(&rib4, ip4(198u, 51u, 100u, 10u), ip4(203u, 0u, 113u, 44u), &route4));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_NOT_FOUND, libbgp_rib6_lookup_scoped(&rib6, ip4(198u, 51u, 100u, 10u), dest6, &route6));
    LIBBGP_ASSERT_EQ_U64(3u, out.count);
    LIBBGP_ASSERT_EQ_U64(LIBBGP_PACKET_NOTIFICATION, out.sent[2].type);
    LIBBGP_ASSERT_EQ_U64(2u, events.count);
    LIBBGP_ASSERT_EQ_U64(LIBBGP_EVENT_SESSION_DOWN, events.types[1]);

    libbgp_packet_destroy(&add6);
    libbgp_packet_destroy(&add4);
    libbgp_fsm_destroy(&fsm);
    libbgp_rib6_destroy(&rib6);
    libbgp_rib4_destroy(&rib4);
    libbgp_event_bus_destroy(&bus);
    libbgp_out_handler_destroy(&out_handler);
}

LIBBGP_TEST(fsm_destroy_established_discards_learned_rib4_and_rib6_routes_without_events)
{
    libbgp_fsm_t fsm;
    libbgp_out_handler_t out_handler;
    libbgp_event_bus_t bus;
    libbgp_rib4_t rib4;
    libbgp_rib6_t rib6;
    out_ctx_t out;
    event_ctx_t events;
    libbgp_prefix4_t prefix4 = p4(203u, 0u, 113u, 0u, 24u);
    const uint8_t prefix6_addr[16] = { 0x20u, 0x01u, 0x0du, 0xb8u, 0x30u };
    const uint8_t dest6[16] = { 0x20u, 0x01u, 0x0du, 0xb8u, 0x30u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 1u };
    const uint8_t next_hop6[16] = { 0x20u, 0x01u, 0x0du, 0xb8u, 0xffu, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 1u };
    libbgp_prefix6_t prefix6 = p6(prefix6_addr, 40u);
    libbgp_packet_t add4 = make_update_add(prefix4, ip4(192u, 0u, 2u, 254u));
    libbgp_packet_t add6 = make_update_mp_reach6(prefix6, next_hop6);
    const libbgp_rib4_route_t *route4 = NULL;
    const libbgp_rib6_route_t *route6 = NULL;

    setup_out(&out_handler, &out);
    memset(&events, 0, sizeof(events));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_event_bus_init(&bus));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_event_bus_subscribe(&bus, LIBBGP_EVENT_SESSION_UP, event_capture, &events, NULL));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_event_bus_subscribe(&bus, LIBBGP_EVENT_SESSION_DOWN, event_capture, &events, NULL));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_rib4_init(&rib4));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_rib6_init(&rib6));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, init_test_fsm(&fsm));
    libbgp_fsm_set_out_handler(&fsm, &out_handler);
    libbgp_fsm_set_event_bus(&fsm, &bus);
    libbgp_fsm_set_rib4(&fsm, &rib4);
    libbgp_fsm_set_rib6(&fsm, &rib6);
    establish(&fsm, &out, &events);

    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_fsm_on_packet(&fsm, &add4));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_fsm_on_packet(&fsm, &add6));
    LIBBGP_ASSERT_EQ_U64(1u, libbgp_rib4_route_count(&rib4));
    LIBBGP_ASSERT_EQ_U64(1u, libbgp_rib6_route_count(&rib6));

    libbgp_fsm_destroy(&fsm);
    LIBBGP_ASSERT_EQ_U64(0u, libbgp_rib4_route_count(&rib4));
    LIBBGP_ASSERT_EQ_U64(0u, libbgp_rib6_route_count(&rib6));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_NOT_FOUND, libbgp_rib4_lookup_scoped(&rib4, ip4(198u, 51u, 100u, 10u), ip4(203u, 0u, 113u, 44u), &route4));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_NOT_FOUND, libbgp_rib6_lookup_scoped(&rib6, ip4(198u, 51u, 100u, 10u), dest6, &route6));
    LIBBGP_ASSERT_EQ_U64(1u, events.count);
    LIBBGP_ASSERT_EQ_U64(2u, out.count);

    libbgp_packet_destroy(&add6);
    libbgp_packet_destroy(&add4);
    libbgp_rib6_destroy(&rib6);
    libbgp_rib4_destroy(&rib4);
    libbgp_event_bus_destroy(&bus);
    libbgp_out_handler_destroy(&out_handler);
}

LIBBGP_TEST(fsm_wrong_packet_in_open_sent_returns_bad_type_and_idle)
{
    libbgp_fsm_t fsm;
    libbgp_out_handler_t out_handler;
    out_ctx_t out;
    libbgp_packet_t keepalive = make_keepalive_packet();

    setup_out(&out_handler, &out);
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, init_test_fsm(&fsm));
    libbgp_fsm_set_out_handler(&fsm, &out_handler);
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_fsm_start(&fsm));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_BAD_TYPE, libbgp_fsm_on_packet(&fsm, &keepalive));
    LIBBGP_ASSERT_EQ_U64(LIBBGP_FSM_IDLE, libbgp_fsm_state(&fsm));
    LIBBGP_ASSERT_EQ_U64(2u, out.count);
    assert_sent_notification(&out, 1u, 5u, 1u);
    libbgp_packet_destroy(&keepalive);
    libbgp_fsm_destroy(&fsm);
    libbgp_out_handler_destroy(&out_handler);
}

LIBBGP_TEST(fsm_established_unexpected_packet_sends_fsm_error_and_discards_routes)
{
    libbgp_fsm_t fsm;
    libbgp_out_handler_t out_handler;
    libbgp_event_bus_t bus;
    libbgp_rib4_t rib;
    out_ctx_t out;
    event_ctx_t events;
    libbgp_prefix4_t prefix = p4(203u, 0u, 113u, 0u, 24u);
    libbgp_packet_t add = make_update_add(prefix, ip4(192u, 0u, 2u, 254u));
    libbgp_packet_t open = make_open_packet(65010u, 45u, ip4(198u, 51u, 100u, 10u), true);

    setup_out(&out_handler, &out);
    memset(&events, 0, sizeof(events));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_event_bus_init(&bus));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_event_bus_subscribe(&bus, LIBBGP_EVENT_SESSION_UP, event_capture, &events, NULL));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_event_bus_subscribe(&bus, LIBBGP_EVENT_SESSION_DOWN, event_capture, &events, NULL));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_rib4_init(&rib));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, init_test_fsm(&fsm));
    libbgp_fsm_set_out_handler(&fsm, &out_handler);
    libbgp_fsm_set_event_bus(&fsm, &bus);
    libbgp_fsm_set_rib4(&fsm, &rib);
    establish(&fsm, &out, &events);

    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_fsm_on_packet(&fsm, &add));
    LIBBGP_ASSERT_EQ_U64(1u, libbgp_rib4_route_count(&rib));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_BAD_TYPE, libbgp_fsm_on_packet(&fsm, &open));
    LIBBGP_ASSERT_EQ_U64(LIBBGP_FSM_IDLE, libbgp_fsm_state(&fsm));
    LIBBGP_ASSERT_EQ_U64(0u, libbgp_rib4_route_count(&rib));
    LIBBGP_ASSERT_EQ_U64(3u, out.count);
    assert_sent_notification(&out, 2u, 5u, 3u);
    LIBBGP_ASSERT_EQ_U64(2u, events.count);
    LIBBGP_ASSERT_EQ_U64(LIBBGP_EVENT_SESSION_DOWN, events.types[1]);

    libbgp_packet_destroy(&open);
    libbgp_packet_destroy(&add);
    libbgp_fsm_destroy(&fsm);
    libbgp_rib4_destroy(&rib);
    libbgp_event_bus_destroy(&bus);
    libbgp_out_handler_destroy(&out_handler);
}

LIBBGP_TEST(fsm_tick_keepalive_and_hold_timeout)
{
    struct libbgp_fsm_config config;
    libbgp_fsm_t fsm;
    libbgp_out_handler_t out_handler;
    libbgp_event_bus_t bus;
    out_ctx_t out;
    event_ctx_t events;
    libbgp_packet_t open = make_open_packet_with_mpbgp6(65010u, 3u, ip4(198u, 51u, 100u, 10u), true, true);
    libbgp_packet_t keepalive = make_keepalive_packet();

    config.local_asn = 65000u;
    config.local_bgp_id = ip4(192u, 0u, 2u, 1u);
    config.hold_time = 3u;
    config.keepalive_time = 1u;
    config.enable_4byte_asn = true;
    config.enable_mpbgp_ipv6 = true;
    setup_out(&out_handler, &out);
    memset(&events, 0, sizeof(events));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_event_bus_init(&bus));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_event_bus_subscribe(&bus, LIBBGP_EVENT_SESSION_UP, event_capture, &events, NULL));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_event_bus_subscribe(&bus, LIBBGP_EVENT_SESSION_DOWN, event_capture, &events, NULL));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_fsm_init(&fsm, &config));
    libbgp_fsm_set_out_handler(&fsm, &out_handler);
    libbgp_fsm_set_event_bus(&fsm, &bus);
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_fsm_start(&fsm));
    LIBBGP_ASSERT_EQ_U64(1u, out.count);
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_fsm_on_packet(&fsm, &open));
    LIBBGP_ASSERT_EQ_U64(2u, out.count);
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_fsm_on_packet(&fsm, &keepalive));
    LIBBGP_ASSERT_EQ_U64(LIBBGP_FSM_ESTABLISHED, libbgp_fsm_state(&fsm));
    LIBBGP_ASSERT_EQ_U64(1u, events.count);
    LIBBGP_ASSERT_EQ_U64(LIBBGP_EVENT_SESSION_UP, events.types[0]);

    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_fsm_tick(&fsm, 1000u));
    LIBBGP_ASSERT_EQ_U64(2u, out.count);
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_fsm_tick(&fsm, 2000u));
    LIBBGP_ASSERT_EQ_U64(3u, out.count);
    LIBBGP_ASSERT_EQ_U64(LIBBGP_PACKET_KEEPALIVE, out.sent[2].type);
    LIBBGP_ASSERT_EQ_U64(LIBBGP_FSM_ESTABLISHED, libbgp_fsm_state(&fsm));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_fsm_tick(&fsm, 3000u));
    LIBBGP_ASSERT_EQ_U64(LIBBGP_FSM_ESTABLISHED, libbgp_fsm_state(&fsm));
    LIBBGP_ASSERT_EQ_U64(4u, out.count);
    LIBBGP_ASSERT_EQ_U64(LIBBGP_PACKET_KEEPALIVE, out.sent[3].type);
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_fsm_tick(&fsm, 4000u));
    LIBBGP_ASSERT_EQ_U64(LIBBGP_FSM_IDLE, libbgp_fsm_state(&fsm));
    LIBBGP_ASSERT_EQ_U64(5u, out.count);
    LIBBGP_ASSERT_EQ_U64(LIBBGP_PACKET_NOTIFICATION, out.sent[4].type);
    LIBBGP_ASSERT_EQ_U64(2u, events.count);
    LIBBGP_ASSERT_EQ_U64(LIBBGP_EVENT_SESSION_DOWN, events.types[1]);

    libbgp_packet_destroy(&keepalive);
    libbgp_packet_destroy(&open);
    libbgp_fsm_destroy(&fsm);
    libbgp_event_bus_destroy(&bus);
    libbgp_out_handler_destroy(&out_handler);
}

LIBBGP_TEST(fsm_established_periodic_keepalive_send_failure_tears_down)
{
    struct libbgp_fsm_config config;
    libbgp_fsm_t fsm;
    libbgp_out_handler_t out_handler;
    libbgp_event_bus_t bus;
    libbgp_rib4_t rib;
    fail_after_send_ctx_t fail_after;
    event_ctx_t events;
    libbgp_prefix4_t prefix = p4(203u, 0u, 113u, 0u, 24u);
    libbgp_packet_t add = make_update_add(prefix, ip4(192u, 0u, 2u, 254u));
    const libbgp_rib4_route_t *route = NULL;
    size_t i;
    size_t session_down_count = 0u;

    config = test_fsm_config();
    config.hold_time = 90u;
    config.keepalive_time = 1u;
    memset(&fail_after, 0, sizeof(fail_after));
    fail_after.fail_on_call = 3u;
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_out_handler_init(&out_handler));
    set_out_send_fn(&out_handler, fail_after_send, &fail_after);
    memset(&events, 0, sizeof(events));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_event_bus_init(&bus));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_event_bus_subscribe(&bus, LIBBGP_EVENT_SESSION_UP, event_capture, &events, NULL));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_event_bus_subscribe(&bus, LIBBGP_EVENT_SESSION_DOWN, event_capture, &events, NULL));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_rib4_init(&rib));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_fsm_init(&fsm, &config));
    libbgp_fsm_set_out_handler(&fsm, &out_handler);
    libbgp_fsm_set_event_bus(&fsm, &bus);
    libbgp_fsm_set_rib4(&fsm, &rib);
    establish(&fsm, &fail_after.out, &events);
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_fsm_on_packet(&fsm, &add));
    LIBBGP_ASSERT_EQ_U64(1u, libbgp_rib4_route_count(&rib));

    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_fsm_tick(&fsm, 1000u));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_WRITE, libbgp_fsm_tick(&fsm, 2000u));
    LIBBGP_ASSERT_EQ_U64(LIBBGP_FSM_IDLE, libbgp_fsm_state(&fsm));
    LIBBGP_ASSERT_EQ_U64(0u, libbgp_rib4_route_count(&rib));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_NOT_FOUND, libbgp_rib4_lookup_scoped(&rib, ip4(198u, 51u, 100u, 10u), ip4(203u, 0u, 113u, 44u), &route));
    for (i = 0u; i < events.count; i++) {
        if (events.types[i] == LIBBGP_EVENT_SESSION_DOWN) {
            session_down_count++;
        }
    }
    LIBBGP_ASSERT_EQ_U64(1u, session_down_count);

    libbgp_packet_destroy(&add);
    libbgp_fsm_destroy(&fsm);
    libbgp_rib4_destroy(&rib);
    libbgp_event_bus_destroy(&bus);
    libbgp_out_handler_destroy(&out_handler);
}

LIBBGP_TEST(fsm_open_confirm_hold_timeout_does_not_publish_session_down)
{
    struct libbgp_fsm_config config;
    libbgp_fsm_t fsm;
    libbgp_out_handler_t out_handler;
    libbgp_event_bus_t bus;
    out_ctx_t out;
    event_ctx_t events;
    libbgp_packet_t open = make_open_packet(65010u, 45u, ip4(198u, 51u, 100u, 10u), true);

    config.local_asn = 65000u;
    config.local_bgp_id = ip4(192u, 0u, 2u, 1u);
    config.hold_time = 3u;
    config.keepalive_time = 0u;
    config.enable_4byte_asn = true;
    config.enable_mpbgp_ipv6 = true;
    setup_out(&out_handler, &out);
    memset(&events, 0, sizeof(events));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_event_bus_init(&bus));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_event_bus_subscribe(&bus, LIBBGP_EVENT_SESSION_UP, event_capture, &events, NULL));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_event_bus_subscribe(&bus, LIBBGP_EVENT_SESSION_DOWN, event_capture, &events, NULL));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_fsm_init(&fsm, &config));
    libbgp_fsm_set_out_handler(&fsm, &out_handler);
    libbgp_fsm_set_event_bus(&fsm, &bus);

    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_fsm_start(&fsm));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_fsm_on_packet(&fsm, &open));
    LIBBGP_ASSERT_EQ_U64(LIBBGP_FSM_OPEN_CONFIRM, libbgp_fsm_state(&fsm));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_fsm_tick(&fsm, 1000u));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_fsm_tick(&fsm, 2000u));
    LIBBGP_ASSERT_EQ_U64(LIBBGP_FSM_OPEN_CONFIRM, libbgp_fsm_state(&fsm));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_fsm_tick(&fsm, 3000u));
    LIBBGP_ASSERT_EQ_U64(LIBBGP_FSM_OPEN_CONFIRM, libbgp_fsm_state(&fsm));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_fsm_tick(&fsm, 4000u));
    LIBBGP_ASSERT_EQ_U64(LIBBGP_FSM_IDLE, libbgp_fsm_state(&fsm));
    LIBBGP_ASSERT_EQ_U64(5u, out.count);
    LIBBGP_ASSERT_EQ_U64(LIBBGP_PACKET_KEEPALIVE, out.sent[2].type);
    LIBBGP_ASSERT_EQ_U64(LIBBGP_PACKET_KEEPALIVE, out.sent[3].type);
    LIBBGP_ASSERT_EQ_U64(LIBBGP_PACKET_NOTIFICATION, out.sent[4].type);
    LIBBGP_ASSERT_EQ_U64(0u, events.count);

    libbgp_packet_destroy(&open);
    libbgp_fsm_destroy(&fsm);
    libbgp_event_bus_destroy(&bus);
    libbgp_out_handler_destroy(&out_handler);
}

LIBBGP_TEST(fsm_keepalive_uses_negotiated_hold_third_when_shorter)
{
    struct libbgp_fsm_config config;
    libbgp_fsm_t fsm;
    libbgp_out_handler_t out_handler;
    libbgp_event_bus_t bus;
    out_ctx_t out;
    event_ctx_t events;

    config.local_asn = 65000u;
    config.local_bgp_id = ip4(192u, 0u, 2u, 1u);
    config.hold_time = 90u;
    config.keepalive_time = 30u;
    config.enable_4byte_asn = true;
    config.enable_mpbgp_ipv6 = true;
    setup_out(&out_handler, &out);
    memset(&events, 0, sizeof(events));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_event_bus_init(&bus));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_event_bus_subscribe(&bus, LIBBGP_EVENT_SESSION_UP, event_capture, &events, NULL));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_fsm_init(&fsm, &config));
    libbgp_fsm_set_out_handler(&fsm, &out_handler);
    libbgp_fsm_set_event_bus(&fsm, &bus);
    establish_with_peer_hold(&fsm, &out, &events, 9u);

    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_fsm_tick(&fsm, 1000u));
    LIBBGP_ASSERT_EQ_U64(2u, out.count);
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_fsm_tick(&fsm, 3999u));
    LIBBGP_ASSERT_EQ_U64(2u, out.count);
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_fsm_tick(&fsm, 4000u));
    LIBBGP_ASSERT_EQ_U64(3u, out.count);
    LIBBGP_ASSERT_EQ_U64(LIBBGP_PACKET_KEEPALIVE, out.sent[2].type);

    libbgp_fsm_destroy(&fsm);
    libbgp_event_bus_destroy(&bus);
    libbgp_out_handler_destroy(&out_handler);
}

LIBBGP_TEST(fsm_keepalive_zero_uses_negotiated_hold_third)
{
    struct libbgp_fsm_config config;
    libbgp_fsm_t fsm;
    libbgp_out_handler_t out_handler;
    libbgp_event_bus_t bus;
    out_ctx_t out;
    event_ctx_t events;

    config.local_asn = 65000u;
    config.local_bgp_id = ip4(192u, 0u, 2u, 1u);
    config.hold_time = 90u;
    config.keepalive_time = 0u;
    config.enable_4byte_asn = true;
    config.enable_mpbgp_ipv6 = true;
    setup_out(&out_handler, &out);
    memset(&events, 0, sizeof(events));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_event_bus_init(&bus));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_event_bus_subscribe(&bus, LIBBGP_EVENT_SESSION_UP, event_capture, &events, NULL));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_fsm_init(&fsm, &config));
    libbgp_fsm_set_out_handler(&fsm, &out_handler);
    libbgp_fsm_set_event_bus(&fsm, &bus);
    establish_with_peer_hold(&fsm, &out, &events, 9u);

    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_fsm_tick(&fsm, 1000u));
    LIBBGP_ASSERT_EQ_U64(2u, out.count);
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_fsm_tick(&fsm, 3999u));
    LIBBGP_ASSERT_EQ_U64(2u, out.count);
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_fsm_tick(&fsm, 4000u));
    LIBBGP_ASSERT_EQ_U64(3u, out.count);
    LIBBGP_ASSERT_EQ_U64(LIBBGP_PACKET_KEEPALIVE, out.sent[2].type);

    libbgp_fsm_destroy(&fsm);
    libbgp_event_bus_destroy(&bus);
    libbgp_out_handler_destroy(&out_handler);
}

LIBBGP_TEST(fsm_negotiated_hold_zero_disables_periodic_keepalive)
{
    struct libbgp_fsm_config config;
    libbgp_fsm_t fsm;
    libbgp_out_handler_t out_handler;
    libbgp_event_bus_t bus;
    out_ctx_t out;
    event_ctx_t events;

    config.local_asn = 65000u;
    config.local_bgp_id = ip4(192u, 0u, 2u, 1u);
    config.hold_time = 90u;
    config.keepalive_time = 1u;
    config.enable_4byte_asn = true;
    config.enable_mpbgp_ipv6 = true;
    setup_out(&out_handler, &out);
    memset(&events, 0, sizeof(events));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_event_bus_init(&bus));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_event_bus_subscribe(&bus, LIBBGP_EVENT_SESSION_UP, event_capture, &events, NULL));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_fsm_init(&fsm, &config));
    libbgp_fsm_set_out_handler(&fsm, &out_handler);
    libbgp_fsm_set_event_bus(&fsm, &bus);
    establish_with_peer_hold(&fsm, &out, &events, 0u);

    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_fsm_tick(&fsm, 1000u));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_fsm_tick(&fsm, 5000u));
    LIBBGP_ASSERT_EQ_U64(LIBBGP_FSM_ESTABLISHED, libbgp_fsm_state(&fsm));
    LIBBGP_ASSERT_EQ_U64(2u, out.count);

    libbgp_fsm_destroy(&fsm);
    libbgp_event_bus_destroy(&bus);
    libbgp_out_handler_destroy(&out_handler);
}

LIBBGP_TEST(fsm_accepted_keepalive_refreshes_hold_timer)
{
    struct libbgp_fsm_config config;
    libbgp_fsm_t fsm;
    libbgp_out_handler_t out_handler;
    libbgp_event_bus_t bus;
    out_ctx_t out;
    event_ctx_t events;
    libbgp_packet_t keepalive = make_keepalive_packet();

    config.local_asn = 65000u;
    config.local_bgp_id = ip4(192u, 0u, 2u, 1u);
    config.hold_time = 3u;
    config.keepalive_time = 0u;
    config.enable_4byte_asn = true;
    config.enable_mpbgp_ipv6 = true;
    setup_out(&out_handler, &out);
    memset(&events, 0, sizeof(events));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_event_bus_init(&bus));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_event_bus_subscribe(&bus, LIBBGP_EVENT_SESSION_UP, event_capture, &events, NULL));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_event_bus_subscribe(&bus, LIBBGP_EVENT_SESSION_DOWN, event_capture, &events, NULL));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_fsm_init(&fsm, &config));
    libbgp_fsm_set_out_handler(&fsm, &out_handler);
    libbgp_fsm_set_event_bus(&fsm, &bus);
    establish(&fsm, &out, &events);

    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_fsm_tick(&fsm, 1000u));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_fsm_tick(&fsm, 3500u));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_fsm_on_packet(&fsm, &keepalive));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_fsm_tick(&fsm, 4501u));
    LIBBGP_ASSERT_EQ_U64(LIBBGP_FSM_ESTABLISHED, libbgp_fsm_state(&fsm));
    LIBBGP_ASSERT_EQ_U64(4u, out.count);
    LIBBGP_ASSERT_EQ_U64(1u, events.count);

    libbgp_packet_destroy(&keepalive);
    libbgp_fsm_destroy(&fsm);
    libbgp_event_bus_destroy(&bus);
    libbgp_out_handler_destroy(&out_handler);
}

LIBBGP_TEST(fsm_unexpected_packet_does_not_refresh_hold_timer)
{
    struct libbgp_fsm_config config;
    libbgp_fsm_t fsm;
    libbgp_out_handler_t out_handler;
    libbgp_event_bus_t bus;
    out_ctx_t out;
    event_ctx_t events;
    libbgp_packet_t unknown;

    config.local_asn = 65000u;
    config.local_bgp_id = ip4(192u, 0u, 2u, 1u);
    config.hold_time = 3u;
    config.keepalive_time = 0u;
    config.enable_4byte_asn = true;
    config.enable_mpbgp_ipv6 = true;
    setup_out(&out_handler, &out);
    memset(&events, 0, sizeof(events));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_event_bus_init(&bus));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_event_bus_subscribe(&bus, LIBBGP_EVENT_SESSION_UP, event_capture, &events, NULL));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_event_bus_subscribe(&bus, LIBBGP_EVENT_SESSION_DOWN, event_capture, &events, NULL));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_fsm_init(&fsm, &config));
    libbgp_fsm_set_out_handler(&fsm, &out_handler);
    libbgp_fsm_set_event_bus(&fsm, &bus);
    establish(&fsm, &out, &events);

    libbgp_packet_init(&unknown);
    unknown.type = LIBBGP_PACKET_UNKNOWN;
    unknown.raw_type = 99u;
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_fsm_tick(&fsm, 1000u));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_fsm_tick(&fsm, 3500u));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_BAD_TYPE, libbgp_fsm_on_packet(&fsm, &unknown));
    LIBBGP_ASSERT_EQ_U64(LIBBGP_FSM_IDLE, libbgp_fsm_state(&fsm));
    LIBBGP_ASSERT_EQ_U64(4u, out.count);
    assert_sent_notification(&out, 3u, 5u, 3u);
    LIBBGP_ASSERT_EQ_U64(2u, events.count);
    LIBBGP_ASSERT_EQ_U64(LIBBGP_EVENT_SESSION_DOWN, events.types[1]);

    libbgp_packet_destroy(&unknown);
    libbgp_fsm_destroy(&fsm);
    libbgp_event_bus_destroy(&bus);
    libbgp_out_handler_destroy(&out_handler);
}

LIBBGP_TEST(fsm_invalid_update_does_not_refresh_hold_timer)
{
    struct libbgp_fsm_config config;
    libbgp_fsm_t fsm;
    libbgp_out_handler_t out_handler;
    libbgp_event_bus_t bus;
    libbgp_rib6_t rib6;
    out_ctx_t out;
    event_ctx_t events;
    uint8_t addr[16] = {
        0x20u, 0x01u, 0x0du, 0xb8u,
        0x00u, 0x00u, 0x00u, 0x00u,
        0x00u, 0x00u, 0x00u, 0x00u,
        0x00u, 0x00u, 0x00u, 0x00u
    };
    uint8_t next_hop[16] = {
        0x20u, 0x01u, 0x0du, 0xb8u,
        0x00u, 0x00u, 0x00u, 0x00u,
        0x00u, 0x00u, 0x00u, 0x00u,
        0x00u, 0x00u, 0x00u, 0x01u
    };
    libbgp_packet_t update = make_update_mp_reach6(p6(addr, 64u), next_hop);
    libbgp_pattr_t *mp = libbgp_update_find_attr(&update.data.update, LIBBGP_PATTR_MP_REACH_IPV6);

    config.local_asn = 65000u;
    config.local_bgp_id = ip4(192u, 0u, 2u, 1u);
    config.hold_time = 3u;
    config.keepalive_time = 0u;
    config.enable_4byte_asn = true;
    config.enable_mpbgp_ipv6 = true;
    setup_out(&out_handler, &out);
    memset(&events, 0, sizeof(events));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_event_bus_init(&bus));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_event_bus_subscribe(&bus, LIBBGP_EVENT_SESSION_UP, event_capture, &events, NULL));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_event_bus_subscribe(&bus, LIBBGP_EVENT_SESSION_DOWN, event_capture, &events, NULL));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_rib6_init(&rib6));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_fsm_init(&fsm, &config));
    libbgp_fsm_set_out_handler(&fsm, &out_handler);
    libbgp_fsm_set_event_bus(&fsm, &bus);
    libbgp_fsm_set_rib6(&fsm, &rib6);
    establish(&fsm, &out, &events);

    LIBBGP_ASSERT(mp != NULL);
    mp->data.mp_reach_ipv6.nexthop_len = 15u;
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_fsm_tick(&fsm, 1000u));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_fsm_tick(&fsm, 3500u));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_INVALID, libbgp_fsm_on_packet(&fsm, &update));
    LIBBGP_ASSERT_EQ_U64(LIBBGP_FSM_IDLE, libbgp_fsm_state(&fsm));
    LIBBGP_ASSERT_EQ_U64(4u, out.count);
    assert_sent_notification(&out, 3u, 3u, 5u);
    LIBBGP_ASSERT_EQ_U64(2u, events.count);
    LIBBGP_ASSERT_EQ_U64(LIBBGP_EVENT_SESSION_DOWN, events.types[1]);
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_fsm_tick(&fsm, 4501u));
    LIBBGP_ASSERT_EQ_U64(LIBBGP_FSM_IDLE, libbgp_fsm_state(&fsm));
    LIBBGP_ASSERT_EQ_U64(4u, out.count);
    LIBBGP_ASSERT_EQ_U64(2u, events.count);
    LIBBGP_ASSERT_EQ_U64(0u, libbgp_rib6_route_count(&rib6));

    libbgp_packet_destroy(&update);
    libbgp_fsm_destroy(&fsm);
    libbgp_rib6_destroy(&rib6);
    libbgp_event_bus_destroy(&bus);
    libbgp_out_handler_destroy(&out_handler);
}

int main(void)
{
    const libbgp_test_case_t tests[] = {
        { "fsm_init_defaults_and_custom_config", fsm_init_defaults_and_custom_config },
        { "fsm_start_sends_open_and_moves_open_sent", fsm_start_sends_open_and_moves_open_sent },
        { "fsm_default_config_start_rejects_zero_local_bgp_id_without_sending", fsm_default_config_start_rejects_zero_local_bgp_id_without_sending },
        { "fsm_start_rejects_invalid_local_hold_time_without_sending", fsm_start_rejects_invalid_local_hold_time_without_sending },
        { "fsm_start_rejects_local_asn_truncation_without_sending", fsm_start_rejects_local_asn_truncation_without_sending },
        { "fsm_default_config_open_sent_rejects_peer_open_without_sending", fsm_default_config_open_sent_rejects_peer_open_without_sending },
        { "fsm_start_send_failure_leaves_idle_and_retryable", fsm_start_send_failure_leaves_idle_and_retryable },
        { "fsm_start_without_output_handler_returns_invalid_and_retryable", fsm_start_without_output_handler_returns_invalid_and_retryable },
        { "fsm_start_zero_progress_short_send_rolls_back_to_idle", fsm_start_zero_progress_short_send_rolls_back_to_idle },
        { "fsm_start_reentrant_start_does_not_send_duplicate_open", fsm_start_reentrant_start_does_not_send_duplicate_open },
        { "fsm_start_failed_send_does_not_rollback_reentrant_restart", fsm_start_failed_send_does_not_rollback_reentrant_restart },
        { "fsm_open_sent_accepts_open_records_peer_and_sends_keepalive", fsm_open_sent_accepts_open_records_peer_and_sends_keepalive },
        { "fsm_open_sent_reentrant_keepalive_establishes", fsm_open_sent_reentrant_keepalive_establishes },
        { "fsm_open_sent_keepalive_send_failure_leaves_idle", fsm_open_sent_keepalive_send_failure_leaves_idle },
        { "fsm_open_sent_reentrant_keepalive_then_failed_keepalive_send_leaves_idle", fsm_open_sent_reentrant_keepalive_then_failed_keepalive_send_leaves_idle },
        { "fsm_open_sent_failed_keepalive_does_not_rollback_reentrant_restart", fsm_open_sent_failed_keepalive_does_not_rollback_reentrant_restart },
        { "fsm_enter_connect_then_start_sends_open", fsm_enter_connect_then_start_sends_open },
        { "fsm_enter_active_then_start_sends_open", fsm_enter_active_then_start_sends_open },
        { "fsm_connect_open_sends_open_keepalive_and_can_establish", fsm_connect_open_sends_open_keepalive_and_can_establish },
        { "fsm_active_open_sends_open_keepalive_and_can_establish", fsm_active_open_sends_open_keepalive_and_can_establish },
        { "fsm_idle_open_sends_open_keepalive_and_can_establish", fsm_idle_open_sends_open_keepalive_and_can_establish },
        { "fsm_default_config_passive_open_rejects_zero_local_bgp_id_without_sending", fsm_default_config_passive_open_rejects_zero_local_bgp_id_without_sending },
        { "fsm_passive_open_rejects_invalid_local_hold_time_without_sending", fsm_passive_open_rejects_invalid_local_hold_time_without_sending },
        { "fsm_passive_open_rejects_local_asn_truncation_without_sending", fsm_passive_open_rejects_local_asn_truncation_without_sending },
        { "fsm_idle_open_local_open_send_failure_leaves_idle", fsm_idle_open_local_open_send_failure_leaves_idle },
        { "fsm_idle_open_keepalive_send_failure_leaves_idle", fsm_idle_open_keepalive_send_failure_leaves_idle },
        { "fsm_passive_open_reentrant_open_does_not_duplicate_negotiation", fsm_passive_open_reentrant_open_does_not_duplicate_negotiation },
        { "fsm_passive_open_reentrant_keepalive_establishes", fsm_passive_open_reentrant_keepalive_establishes },
        { "fsm_passive_open_reentrant_keepalive_during_local_open_send_establishes", fsm_passive_open_reentrant_keepalive_during_local_open_send_establishes },
        { "fsm_passive_open_reentrant_keepalive_then_failed_keepalive_send_leaves_idle", fsm_passive_open_reentrant_keepalive_then_failed_keepalive_send_leaves_idle },
        { "fsm_passive_open_reentrant_invalid_open_prevents_stale_promotion", fsm_passive_open_reentrant_invalid_open_prevents_stale_promotion },
        { "fsm_passive_open_failed_send_does_not_rollback_reentrant_restart", fsm_passive_open_failed_send_does_not_rollback_reentrant_restart },
        { "fsm_open_sent_rejects_invalid_open_version_with_open_error", fsm_open_sent_rejects_invalid_open_version_with_open_error },
        { "fsm_packet_parse_open_v3_then_fsm_sends_open_error", fsm_packet_parse_open_v3_then_fsm_sends_open_error },
        { "fsm_open_sent_rejects_invalid_open_hold_time", fsm_open_sent_rejects_invalid_open_hold_time },
        { "fsm_open_sent_rejects_invalid_open_bgp_id", fsm_open_sent_rejects_invalid_open_bgp_id },
        { "fsm_open_confirm_keepalive_establishes_and_events", fsm_open_confirm_keepalive_establishes_and_events },
        { "fsm_open_confirm_unexpected_packet_sends_fsm_error", fsm_open_confirm_unexpected_packet_sends_fsm_error },
        { "fsm_open_confirm_notification_clears_peer_state_without_session_down", fsm_open_confirm_notification_clears_peer_state_without_session_down },
        { "fsm_established_keepalive_stays_established", fsm_established_keepalive_stays_established },
        { "fsm_established_update_adds_route_and_event", fsm_established_update_adds_route_and_event },
        { "fsm_established_update_after_teardown_discards_late_routes", fsm_established_update_after_teardown_discards_late_routes },
        { "fsm_accepted_update_refreshes_hold_timer_before_route_event", fsm_accepted_update_refreshes_hold_timer_before_route_event },
        { "fsm_established_invalid_update_is_atomic_and_does_not_refresh_hold_timer", fsm_established_invalid_update_is_atomic_and_does_not_refresh_hold_timer },
        { "fsm_established_update_nomem_rolls_back_inserted_routes_and_events", fsm_established_update_nomem_rolls_back_inserted_routes_and_events },
        { "fsm_established_update_nomem_restores_withdrawn_routes_and_events", fsm_established_update_nomem_restores_withdrawn_routes_and_events },
        { "fsm_established_update_nomem_restores_replaced_ipv4_route_and_events", fsm_established_update_nomem_restores_replaced_ipv4_route_and_events },
        { "fsm_established_update_nomem_restores_original_after_duplicate_ipv4_replacements", fsm_established_update_nomem_restores_original_after_duplicate_ipv4_replacements },
        { "fsm_established_update_nomem_removes_absent_duplicate_ipv4_replacements", fsm_established_update_nomem_removes_absent_duplicate_ipv4_replacements },
        { "fsm_established_update_nomem_restores_replaced_ipv6_route_and_events", fsm_established_update_nomem_restores_replaced_ipv6_route_and_events },
        { "fsm_established_update_nomem_restores_original_after_duplicate_ipv6_replacements", fsm_established_update_nomem_restores_original_after_duplicate_ipv6_replacements },
        { "fsm_established_update_nomem_removes_absent_duplicate_ipv6_replacements", fsm_established_update_nomem_removes_absent_duplicate_ipv6_replacements },
        { "fsm_established_rejects_ipv4_advertisements_missing_mandatory_attrs", fsm_established_rejects_ipv4_advertisements_missing_mandatory_attrs },
        { "fsm_established_rejects_ipv6_advertisements_missing_common_mandatory_attrs", fsm_established_rejects_ipv6_advertisements_missing_common_mandatory_attrs },
        { "fsm_established_rejects_duplicate_mandatory_attrs", fsm_established_rejects_duplicate_mandatory_attrs },
        { "fsm_established_update_withdraws_route_and_event", fsm_established_update_withdraws_route_and_event },
        { "fsm_established_update_mp_reach6_adds_rib6_route", fsm_established_update_mp_reach6_adds_rib6_route },
        { "fsm_established_update_mp_reach6_publishes_event_without_rib6", fsm_established_update_mp_reach6_publishes_event_without_rib6 },
        { "fsm_established_invalid_mp_reach6_without_rib6_publishes_no_event", fsm_established_invalid_mp_reach6_without_rib6_publishes_no_event },
        { "fsm_established_invalid_update_sends_notification_before_reentrant_restart_open", fsm_established_invalid_update_sends_notification_before_reentrant_restart_open },
        { "fsm_established_rejects_mp_reach6_without_peer_capability", fsm_established_rejects_mp_reach6_without_peer_capability },
        { "fsm_established_rejects_mp_reach6_when_local_capability_disabled", fsm_established_rejects_mp_reach6_when_local_capability_disabled },
        { "fsm_established_update_mp_unreach6_withdraws_rib6_route", fsm_established_update_mp_unreach6_withdraws_rib6_route },
        { "fsm_established_update_mp_unreach6_publishes_event_without_rib6", fsm_established_update_mp_unreach6_publishes_event_without_rib6 },
        { "fsm_established_update_reentrant_restart_preserves_replacement_route", fsm_established_update_reentrant_restart_preserves_replacement_route },
        { "fsm_established_update_reentrant_restart_skips_later_stale_nlri", fsm_established_update_reentrant_restart_skips_later_stale_nlri },
        { "fsm_established_update_reentrant_stop_does_not_restore_replaced_ipv4_route", fsm_established_update_reentrant_stop_does_not_restore_replaced_ipv4_route },
        { "fsm_established_update_reentrant_restart_does_not_restore_withdrawn_ipv4_route", fsm_established_update_reentrant_restart_does_not_restore_withdrawn_ipv4_route },
        { "fsm_established_update_reentrant_restart_does_not_restore_withdrawn_ipv6_route", fsm_established_update_reentrant_restart_does_not_restore_withdrawn_ipv6_route },
        { "fsm_notification_moves_idle_and_session_down", fsm_notification_moves_idle_and_session_down },
        { "fsm_notification_discards_learned_rib4_and_rib6_routes", fsm_notification_discards_learned_rib4_and_rib6_routes },
        { "fsm_invalid_update_discards_learned_rib4_and_rib6_routes", fsm_invalid_update_discards_learned_rib4_and_rib6_routes },
        { "fsm_invalid_update_notification_send_failure_still_tears_down", fsm_invalid_update_notification_send_failure_still_tears_down },
        { "fsm_stop_established_sends_cease_before_reentrant_restart_open", fsm_stop_established_sends_cease_before_reentrant_restart_open },
        { "fsm_stop_established_publishes_session_down_and_discards_routes", fsm_stop_established_publishes_session_down_and_discards_routes },
        { "fsm_destroy_established_discards_learned_rib4_and_rib6_routes_without_events", fsm_destroy_established_discards_learned_rib4_and_rib6_routes_without_events },
        { "fsm_wrong_packet_in_open_sent_returns_bad_type_and_idle", fsm_wrong_packet_in_open_sent_returns_bad_type_and_idle },
        { "fsm_established_unexpected_packet_sends_fsm_error_and_discards_routes", fsm_established_unexpected_packet_sends_fsm_error_and_discards_routes },
        { "fsm_tick_keepalive_and_hold_timeout", fsm_tick_keepalive_and_hold_timeout },
        { "fsm_established_periodic_keepalive_send_failure_tears_down", fsm_established_periodic_keepalive_send_failure_tears_down },
        { "fsm_open_confirm_hold_timeout_does_not_publish_session_down", fsm_open_confirm_hold_timeout_does_not_publish_session_down },
        { "fsm_keepalive_uses_negotiated_hold_third_when_shorter", fsm_keepalive_uses_negotiated_hold_third_when_shorter },
        { "fsm_keepalive_zero_uses_negotiated_hold_third", fsm_keepalive_zero_uses_negotiated_hold_third },
        { "fsm_negotiated_hold_zero_disables_periodic_keepalive", fsm_negotiated_hold_zero_disables_periodic_keepalive },
        { "fsm_accepted_keepalive_refreshes_hold_timer", fsm_accepted_keepalive_refreshes_hold_timer },
        { "fsm_unexpected_packet_does_not_refresh_hold_timer", fsm_unexpected_packet_does_not_refresh_hold_timer },
        { "fsm_invalid_update_does_not_refresh_hold_timer", fsm_invalid_update_does_not_refresh_hold_timer }
    };

    return libbgp_run_tests("fsm", tests, LIBBGP_ARRAY_LEN(tests));
}
