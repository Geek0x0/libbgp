#include "test_main.h"

#include "libbgp/capability.h"
#include "libbgp/event.h"
#include "libbgp/fsm.h"
#include "libbgp/pattr.h"
#include "libbgp/rib4.h"

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
    uint32_t sources[16];
    size_t count;
} event_ctx_t;

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

static void event_capture(const libbgp_event_t *event, void *ctx)
{
    event_ctx_t *events = (event_ctx_t *)ctx;

    LIBBGP_ASSERT(events->count < LIBBGP_ARRAY_LEN(events->types));
    events->types[events->count] = event->type;
    events->sources[events->count] = event->source_router_id;
    if (event->prefix4 != NULL) {
        events->prefixes[events->count] = *event->prefix4;
    } else {
        memset(&events->prefixes[events->count], 0, sizeof(events->prefixes[events->count]));
    }
    events->count++;
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

static libbgp_packet_t make_update_withdraw(libbgp_prefix4_t prefix)
{
    libbgp_packet_t pkt;

    libbgp_packet_init(&pkt);
    pkt.type = LIBBGP_PACKET_UPDATE;
    libbgp_update_init(&pkt.data.update);
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_update_add_withdrawn(&pkt.data.update, &prefix));
    return pkt;
}

static void establish(libbgp_fsm_t *fsm, out_ctx_t *out, event_ctx_t *events)
{
    libbgp_packet_t open = make_open_packet(65010u, 45u, ip4(198u, 51u, 100u, 10u), true);
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

LIBBGP_TEST(fsm_start_send_failure_leaves_idle_and_retryable)
{
    libbgp_fsm_t fsm;
    libbgp_out_handler_t out_handler;
    out_ctx_t out;

    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_out_handler_init(&out_handler));
    set_out_send_fn(&out_handler, fail_send, NULL);
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_fsm_init(&fsm, NULL));
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

LIBBGP_TEST(fsm_open_sent_accepts_open_records_peer_and_sends_keepalive)
{
    libbgp_fsm_t fsm;
    libbgp_out_handler_t out_handler;
    out_ctx_t out;
    libbgp_packet_t open = make_open_packet(65560u, 60u, ip4(203u, 0u, 113u, 9u), true);

    setup_out(&out_handler, &out);
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_fsm_init(&fsm, NULL));
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
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_fsm_init(&fsm, NULL));
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
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_fsm_init(&fsm, NULL));
    libbgp_fsm_set_out_handler(&fsm, &out_handler);
    libbgp_fsm_set_event_bus(&fsm, &bus);
    establish(&fsm, &out, &events);

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
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_fsm_init(&fsm, NULL));
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
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_fsm_init(&fsm, NULL));
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
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_fsm_init(&fsm, NULL));
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
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_fsm_init(&fsm, NULL));
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

LIBBGP_TEST(fsm_wrong_packet_in_open_sent_returns_bad_type_and_idle)
{
    libbgp_fsm_t fsm;
    libbgp_out_handler_t out_handler;
    out_ctx_t out;
    libbgp_packet_t keepalive = make_keepalive_packet();

    setup_out(&out_handler, &out);
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_fsm_init(&fsm, NULL));
    libbgp_fsm_set_out_handler(&fsm, &out_handler);
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_fsm_start(&fsm));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_BAD_TYPE, libbgp_fsm_on_packet(&fsm, &keepalive));
    LIBBGP_ASSERT_EQ_U64(LIBBGP_FSM_IDLE, libbgp_fsm_state(&fsm));
    LIBBGP_ASSERT_EQ_U64(2u, out.count);
    LIBBGP_ASSERT_EQ_U64(LIBBGP_PACKET_NOTIFICATION, out.sent[1].type);
    libbgp_packet_destroy(&keepalive);
    libbgp_fsm_destroy(&fsm);
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

    config.local_asn = 65000u;
    config.local_bgp_id = ip4(192u, 0u, 2u, 1u);
    config.hold_time = 1u;
    config.keepalive_time = 1u;
    config.enable_4byte_asn = true;
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
    LIBBGP_ASSERT_EQ_U64(2u, out.count);
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_fsm_tick(&fsm, 2000u));
    LIBBGP_ASSERT_EQ_U64(3u, out.count);
    LIBBGP_ASSERT_EQ_U64(LIBBGP_PACKET_KEEPALIVE, out.sent[2].type);
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_fsm_tick(&fsm, 3001u));
    LIBBGP_ASSERT_EQ_U64(LIBBGP_FSM_IDLE, libbgp_fsm_state(&fsm));
    LIBBGP_ASSERT_EQ_U64(4u, out.count);
    LIBBGP_ASSERT_EQ_U64(LIBBGP_PACKET_NOTIFICATION, out.sent[3].type);
    LIBBGP_ASSERT_EQ_U64(2u, events.count);
    LIBBGP_ASSERT_EQ_U64(LIBBGP_EVENT_SESSION_DOWN, events.types[1]);

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
    LIBBGP_ASSERT_EQ_U64(LIBBGP_FSM_ESTABLISHED, libbgp_fsm_state(&fsm));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_fsm_tick(&fsm, 4501u));
    LIBBGP_ASSERT_EQ_U64(LIBBGP_FSM_IDLE, libbgp_fsm_state(&fsm));
    LIBBGP_ASSERT_EQ_U64(3u, out.count);
    assert_sent_notification(&out, 2u, 4u, 0u);
    LIBBGP_ASSERT_EQ_U64(2u, events.count);
    LIBBGP_ASSERT_EQ_U64(LIBBGP_EVENT_SESSION_DOWN, events.types[1]);

    libbgp_packet_destroy(&unknown);
    libbgp_fsm_destroy(&fsm);
    libbgp_event_bus_destroy(&bus);
    libbgp_out_handler_destroy(&out_handler);
}

int main(void)
{
    const libbgp_test_case_t tests[] = {
        { "fsm_init_defaults_and_custom_config", fsm_init_defaults_and_custom_config },
        { "fsm_start_sends_open_and_moves_open_sent", fsm_start_sends_open_and_moves_open_sent },
        { "fsm_start_send_failure_leaves_idle_and_retryable", fsm_start_send_failure_leaves_idle_and_retryable },
        { "fsm_open_sent_accepts_open_records_peer_and_sends_keepalive", fsm_open_sent_accepts_open_records_peer_and_sends_keepalive },
        { "fsm_open_sent_rejects_invalid_open_version_with_open_error", fsm_open_sent_rejects_invalid_open_version_with_open_error },
        { "fsm_open_sent_rejects_invalid_open_hold_time", fsm_open_sent_rejects_invalid_open_hold_time },
        { "fsm_open_sent_rejects_invalid_open_bgp_id", fsm_open_sent_rejects_invalid_open_bgp_id },
        { "fsm_open_confirm_keepalive_establishes_and_events", fsm_open_confirm_keepalive_establishes_and_events },
        { "fsm_established_keepalive_stays_established", fsm_established_keepalive_stays_established },
        { "fsm_established_update_adds_route_and_event", fsm_established_update_adds_route_and_event },
        { "fsm_established_update_withdraws_route_and_event", fsm_established_update_withdraws_route_and_event },
        { "fsm_notification_moves_idle_and_session_down", fsm_notification_moves_idle_and_session_down },
        { "fsm_wrong_packet_in_open_sent_returns_bad_type_and_idle", fsm_wrong_packet_in_open_sent_returns_bad_type_and_idle },
        { "fsm_tick_keepalive_and_hold_timeout", fsm_tick_keepalive_and_hold_timeout },
        { "fsm_unexpected_packet_does_not_refresh_hold_timer", fsm_unexpected_packet_does_not_refresh_hold_timer }
    };

    return libbgp_run_tests("fsm", tests, LIBBGP_ARRAY_LEN(tests));
}
