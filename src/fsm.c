#include "libbgp/fsm.h"

#include <string.h>

#include "internal.h"
#include "libbgp/capability.h"
#include "libbgp/notification.h"
#include "rib_internal.h"

#define FSM_NOTIFY_MESSAGE_HEADER_ERROR 1u
#define FSM_NOTIFY_OPEN_MESSAGE_ERROR 2u
#define FSM_NOTIFY_UPDATE_MESSAGE_ERROR 3u
#define FSM_NOTIFY_HOLD_TIMER_EXPIRED 4u
#define FSM_NOTIFY_FSM_ERROR 5u
#define FSM_NOTIFY_CEASE 6u
#define FSM_OPEN_ERR_UNSUPPORTED_VERSION 1u
#define FSM_OPEN_ERR_BAD_BGP_ID 3u
#define FSM_OPEN_ERR_UNACCEPTABLE_HOLD_TIME 6u
#define FSM_UPDATE_ERR_MALFORMED_ATTR_LIST 1u
#define FSM_UPDATE_ERR_MISSING_WELL_KNOWN 3u
#define FSM_UPDATE_ERR_ATTR_LEN 5u
#define FSM_ERR_OPEN_SENT 1u
#define FSM_ERR_OPEN_CONFIRM 2u
#define FSM_ERR_ESTABLISHED 3u

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
    bool peer_mpbgp_ipv6;
    libbgp_rib4_t *rib4;
    libbgp_rib6_t *rib6;
    libbgp_event_bus_t *bus;
    libbgp_out_handler_t *out;
    uint64_t session_generation;
    bool local_keepalive_send_pending;
    bool local_keepalive_pending;
    bool passive_open_send_pending;
    bool passive_keepalive_pending;
    bgp_lock_t lock;
} fsm_impl_t;

typedef struct fsm_applied_route4 {
    libbgp_prefix4_t prefix;
    uint64_t update_id;
    bool restore_replaced;
    libbgp_rib4_saved_route_t replaced;
} fsm_applied_route4_t;

typedef struct fsm_applied_route6 {
    libbgp_prefix6_t prefix;
    uint64_t update_id;
    bool restore_replaced;
    libbgp_rib6_saved_route_t replaced;
} fsm_applied_route6_t;

typedef struct fsm_withdrawn_route4 {
    libbgp_rib4_saved_route_t saved;
} fsm_withdrawn_route4_t;

typedef struct fsm_withdrawn_route6 {
    libbgp_rib6_saved_route_t saved;
} fsm_withdrawn_route6_t;

typedef struct fsm_update_journal {
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

static void fsm_default_config(struct libbgp_fsm_config *config)
{
    config->local_asn = LIBBGP_AS_TRANS;
    config->local_bgp_id = 0u;
    config->hold_time = 90u;
    config->keepalive_time = 30u;
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

static libbgp_err_t fsm_send_open(libbgp_out_handler_t *out, const struct libbgp_fsm_config *config)
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
    if (config->enable_mpbgp_ipv6) {
        libbgp_capability_t *cap = libbgp_capability_new(LIBBGP_CAP_MP_BGP);
        if (cap == NULL) {
            libbgp_packet_destroy(&pkt);
            return LIBBGP_ERR_NOMEM;
        }
        cap->data.mp_bgp.afi = LIBBGP_AFI_IPV6;
        cap->data.mp_bgp.safi = LIBBGP_SAFI_UNICAST;
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

static void fsm_publish_event6(
    libbgp_event_bus_t *bus,
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
    (void)libbgp_event_bus_publish(bus, &event);
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
        libbgp_rib4_saved_route_destroy(&journal->routes4[i].replaced);
    }
    for (i = 0u; i < journal->routes6_count; i++) {
        libbgp_rib6_saved_route_destroy(&journal->routes6[i].replaced);
    }
    for (i = 0u; i < journal->withdrawn4_count; i++) {
        libbgp_rib4_saved_route_destroy(&journal->withdrawn4[i].saved);
    }
    for (i = 0u; i < journal->withdrawn6_count; i++) {
        libbgp_rib6_saved_route_destroy(&journal->withdrawn6[i].saved);
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
    libbgp_rib4_saved_route_t *replaced)
{
    libbgp_err_t err;

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
    journal->routes4[journal->routes4_count].prefix = *prefix;
    journal->routes4[journal->routes4_count].update_id = update_id;
    journal->routes4[journal->routes4_count].restore_replaced = restore_replaced;
    memset(&journal->routes4[journal->routes4_count].replaced, 0, sizeof(journal->routes4[journal->routes4_count].replaced));
    if (replaced != NULL) {
        journal->routes4[journal->routes4_count].replaced = *replaced;
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
    libbgp_rib6_saved_route_t *replaced)
{
    libbgp_err_t err;

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
    journal->routes6[journal->routes6_count].prefix = *prefix;
    journal->routes6[journal->routes6_count].update_id = update_id;
    journal->routes6[journal->routes6_count].restore_replaced = restore_replaced;
    memset(&journal->routes6[journal->routes6_count].replaced, 0, sizeof(journal->routes6[journal->routes6_count].replaced));
    if (replaced != NULL) {
        journal->routes6[journal->routes6_count].replaced = *replaced;
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
    bool had_route = false;
    fsm_withdrawn_route4_t *entry;

    if (journal == NULL || rib4 == NULL) {
        return LIBBGP_OK;
    }
    err = fsm_update_journal_reserve_withdrawn4(journal);
    if (err != LIBBGP_OK) {
        return err;
    }
    entry = &journal->withdrawn4[journal->withdrawn4_count];
    memset(entry, 0, sizeof(*entry));
    err = libbgp_rib4_withdraw_exact_save(rib4, peer_bgp_id, prefix, &entry->saved, &had_route);
    if (err == LIBBGP_OK && had_route) {
        journal->withdrawn4_count++;
    }
    return err;
}

static libbgp_err_t fsm_update_journal_record_withdraw6(
    fsm_update_journal_t *journal,
    libbgp_rib6_t *rib6,
    uint32_t peer_bgp_id,
    const libbgp_prefix6_t *prefix)
{
    libbgp_err_t err;
    bool had_route = false;
    fsm_withdrawn_route6_t *entry;

    if (journal == NULL || rib6 == NULL) {
        return LIBBGP_OK;
    }
    err = fsm_update_journal_reserve_withdrawn6(journal);
    if (err != LIBBGP_OK) {
        return err;
    }
    entry = &journal->withdrawn6[journal->withdrawn6_count];
    memset(entry, 0, sizeof(*entry));
    err = libbgp_rib6_withdraw_exact_save(rib6, peer_bgp_id, prefix, &entry->saved, &had_route);
    if (err == LIBBGP_OK && had_route) {
        journal->withdrawn6_count++;
    }
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
            (void)libbgp_rib4_withdraw_exact_if_update_id(
                rib4,
                peer_bgp_id,
                &journal->routes4[i - 1u].prefix,
                journal->routes4[i - 1u].update_id);
        }
    }
    if (rib6 != NULL) {
        for (i = journal->routes6_count; i > 0u; i--) {
            (void)libbgp_rib6_withdraw_exact_if_update_id(
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
                (void)libbgp_rib4_restore_saved_if_absent(rib4, peer_bgp_id, &journal->routes4[i].replaced);
            }
        }
    }
    if (rib6 != NULL) {
        for (i = 0u; i < journal->routes6_count; i++) {
            if (journal->routes6[i].restore_replaced) {
                (void)libbgp_rib6_restore_saved_if_absent(rib6, peer_bgp_id, &journal->routes6[i].replaced);
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
            (void)libbgp_rib4_restore_saved_if_absent(rib4, peer_bgp_id, &journal->withdrawn4[i].saved);
        }
    }
    if (rib6 != NULL) {
        for (i = 0u; i < journal->withdrawn6_count; i++) {
            (void)libbgp_rib6_restore_saved_if_absent(rib6, peer_bgp_id, &journal->withdrawn6[i].saved);
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
    const libbgp_pattr_t *mp_reach)
{
    libbgp_pattr_t *attr;

    route->local_pref = 100u;
    memcpy(route->next_hop, mp_reach->data.mp_reach_ipv6.nexthop, sizeof(route->next_hop));

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
    fsm_fill_route6_attrs(route, update, mp_reach);
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
    uint8_t *notify_subcode)
{
    size_t i;
    libbgp_err_t err;

    err = fsm_validate_update(update, notify_subcode);
    if (err != LIBBGP_OK) {
        return err;
    }
    err = fsm_update_journal_reserve_update(journal, rib4, rib6, update);
    if (err != LIBBGP_OK) {
        return err;
    }

    for (i = 0u; i < update->withdrawn_count; i++) {
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
    for (i = 0u; i < update->nlri_count; i++) {
        libbgp_rib4_route_t route;
        libbgp_rib4_saved_route_t replaced;
        bool had_replaced = false;
        bool restore_replaced = false;
        uint64_t update_id = 0u;
        err = LIBBGP_OK;
        memset(&replaced, 0, sizeof(replaced));

        if (!fsm_update_session_current(impl, session_generation)) {
            return LIBBGP_OK;
        }

        memset(&route, 0, sizeof(route));
        route.prefix = update->nlri[i];
        route.source_router_id = peer_bgp_id;
        fsm_fill_route_attrs(&route, update);
        if (rib4 != NULL) {
            err = libbgp_rib4_insert_save_replaced(rib4, &route, &replaced, &had_replaced, &update_id);
            if (err == LIBBGP_OK && had_replaced) {
                uint64_t replaced_update_id = 0u;

                err = libbgp_rib4_saved_route_update_id(&replaced, &replaced_update_id);
                if (err == LIBBGP_OK) {
                    restore_replaced = !fsm_update_journal_has_route4(journal, &route.prefix, replaced_update_id);
                }
            }
        }
        if (err == LIBBGP_OK) {
            err = fsm_update_journal_record4(journal, &route.prefix, update_id, restore_replaced, &replaced);
        }
        if (err != LIBBGP_OK && rib4 != NULL) {
            (void)libbgp_rib4_withdraw_exact_if_update_id(rib4, peer_bgp_id, &route.prefix, update_id);
            (void)libbgp_rib4_restore_saved_if_absent(rib4, peer_bgp_id, &replaced);
        }
        libbgp_rib4_saved_route_destroy(&replaced);
        if (err != LIBBGP_OK) {
            return err;
        }
    }
    for (i = 0u; i < update->attr_count; i++) {
        const libbgp_pattr_t *attr = update->attrs[i];
        size_t j;

        if (attr->type == LIBBGP_PATTR_MP_UNREACH_IPV6) {
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
        } else if (attr->type == LIBBGP_PATTR_MP_REACH_IPV6) {
            for (j = 0u; j < attr->data.mp_reach_ipv6.nlri_count; j++) {
                libbgp_rib6_saved_route_t replaced;
                bool had_replaced = false;
                bool restore_replaced = false;
                uint64_t update_id = 0u;
                err = LIBBGP_OK;
                memset(&replaced, 0, sizeof(replaced));

                if (!fsm_update_session_current(impl, session_generation)) {
                    return LIBBGP_OK;
                }

                if (rib6 != NULL) {
                    libbgp_rib6_route_t route;

                    err = fsm_make_route6(peer_bgp_id, update, attr, &attr->data.mp_reach_ipv6.nlri[j], &route);
                    if (err == LIBBGP_OK) {
                        err = libbgp_rib6_insert_save_replaced(rib6, &route, &replaced, &had_replaced, &update_id);
                        if (err == LIBBGP_OK && had_replaced) {
                            uint64_t replaced_update_id = 0u;

                            err = libbgp_rib6_saved_route_update_id(&replaced, &replaced_update_id);
                            if (err == LIBBGP_OK) {
                                restore_replaced = !fsm_update_journal_has_route6(
                                    journal,
                                    &attr->data.mp_reach_ipv6.nlri[j],
                                    replaced_update_id);
                            }
                        }
                        fsm_made_route6_destroy(&route);
                    }
                }
                if (err == LIBBGP_OK) {
                    err = fsm_update_journal_record6(
                        journal,
                        &attr->data.mp_reach_ipv6.nlri[j],
                        update_id,
                        restore_replaced,
                        &replaced);
                }
                if (err != LIBBGP_OK && rib6 != NULL) {
                    (void)libbgp_rib6_withdraw_exact_if_update_id(
                        rib6,
                        peer_bgp_id,
                        &attr->data.mp_reach_ipv6.nlri[j],
                        update_id);
                    (void)libbgp_rib6_restore_saved_if_absent(rib6, peer_bgp_id, &replaced);
                }
                libbgp_rib6_saved_route_destroy(&replaced);
                if (err != LIBBGP_OK) {
                    return err;
                }
            }
        }
    }
    return LIBBGP_OK;
}

static void fsm_publish_update_events(
    fsm_impl_t *impl,
    uint64_t session_generation,
    libbgp_event_bus_t *bus,
    uint32_t peer_bgp_id,
    const libbgp_update_msg_t *update)
{
    size_t i;

    if (update == NULL) {
        return;
    }
    for (i = 0u; i < update->withdrawn_count; i++) {
        bool current;

        bgp_lock(&impl->lock);
        current = fsm_update_session_current(impl, session_generation);
        bgp_unlock(&impl->lock);
        if (!current) {
            return;
        }
        fsm_publish_event(bus, LIBBGP_EVENT_ROUTE_WITHDRAWN, peer_bgp_id, &update->withdrawn[i], update);
        bgp_lock(&impl->lock);
        current = fsm_update_session_current(impl, session_generation);
        bgp_unlock(&impl->lock);
        if (!current) {
            return;
        }
    }
    for (i = 0u; i < update->nlri_count; i++) {
        bool current;

        bgp_lock(&impl->lock);
        current = fsm_update_session_current(impl, session_generation);
        bgp_unlock(&impl->lock);
        if (!current) {
            return;
        }
        fsm_publish_event(bus, LIBBGP_EVENT_ROUTE_ADDED, peer_bgp_id, &update->nlri[i], update);
        bgp_lock(&impl->lock);
        current = fsm_update_session_current(impl, session_generation);
        bgp_unlock(&impl->lock);
        if (!current) {
            return;
        }
    }
    for (i = 0u; i < update->attr_count; i++) {
        const libbgp_pattr_t *attr = update->attrs[i];
        size_t j;

        if (attr->type == LIBBGP_PATTR_MP_UNREACH_IPV6) {
            for (j = 0u; j < attr->data.mp_unreach_ipv6.withdrawn_count; j++) {
                bool current;

                bgp_lock(&impl->lock);
                current = fsm_update_session_current(impl, session_generation);
                bgp_unlock(&impl->lock);
                if (!current) {
                    return;
                }
                fsm_publish_event6(
                    bus,
                    LIBBGP_EVENT_ROUTE_WITHDRAWN,
                    peer_bgp_id,
                    &attr->data.mp_unreach_ipv6.withdrawn[j],
                    update);
                bgp_lock(&impl->lock);
                current = fsm_update_session_current(impl, session_generation);
                bgp_unlock(&impl->lock);
                if (!current) {
                    return;
                }
            }
        } else if (attr->type == LIBBGP_PATTR_MP_REACH_IPV6) {
            for (j = 0u; j < attr->data.mp_reach_ipv6.nlri_count; j++) {
                bool current;

                bgp_lock(&impl->lock);
                current = fsm_update_session_current(impl, session_generation);
                bgp_unlock(&impl->lock);
                if (!current) {
                    return;
                }
                fsm_publish_event6(
                    bus,
                    LIBBGP_EVENT_ROUTE_ADDED,
                    peer_bgp_id,
                    &attr->data.mp_reach_ipv6.nlri[j],
                    update);
                bgp_lock(&impl->lock);
                current = fsm_update_session_current(impl, session_generation);
                bgp_unlock(&impl->lock);
                if (!current) {
                    return;
                }
            }
        }
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
    impl->state = LIBBGP_FSM_IDLE;
    impl->peer_asn = 0u;
    impl->peer_bgp_id = 0u;
    impl->negotiated_hold_time = impl->config.hold_time;
    impl->peer_mpbgp_ipv6 = false;
    impl->clock_initialized = false;
    impl->local_keepalive_send_pending = false;
    impl->local_keepalive_pending = false;
    impl->passive_open_send_pending = false;
    impl->passive_keepalive_pending = false;
    impl->session_generation++;
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
    libbgp_rib4_t *rib4 = NULL;
    libbgp_rib6_t *rib6 = NULL;
    uint32_t peer_bgp_id = 0u;
    bool discard_routes = false;

    if (impl == NULL) {
        return;
    }
    bgp_lock(&impl->lock);
    if (impl->state == LIBBGP_FSM_ESTABLISHED && impl->peer_bgp_id != 0u) {
        rib4 = impl->rib4;
        rib6 = impl->rib6;
        peer_bgp_id = impl->peer_bgp_id;
        discard_routes = true;
    }
    bgp_unlock(&impl->lock);
    if (discard_routes) {
        fsm_discard_peer_routes(rib4, rib6, peer_bgp_id);
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

void libbgp_fsm_set_rib6(libbgp_fsm_t *fsm, libbgp_rib6_t *rib6)
{
    fsm_impl_t *impl = fsm_impl_get(fsm);

    if (impl == NULL) {
        return;
    }
    bgp_lock(&impl->lock);
    impl->rib6 = rib6;
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

static libbgp_err_t fsm_enter_pre_open_state(libbgp_fsm_t *fsm, libbgp_fsm_state_t state)
{
    fsm_impl_t *impl = fsm_impl_get(fsm);

    if (impl == NULL) {
        return LIBBGP_ERR_INVALID;
    }
    bgp_lock(&impl->lock);
    if (!fsm_state_pre_open(impl->state)) {
        bgp_unlock(&impl->lock);
        return LIBBGP_ERR_INVALID;
    }
    impl->state = state;
    impl->peer_asn = 0u;
    impl->peer_bgp_id = 0u;
    impl->negotiated_hold_time = impl->config.hold_time;
    impl->peer_mpbgp_ipv6 = false;
    impl->clock_initialized = false;
    impl->local_keepalive_send_pending = false;
    impl->local_keepalive_pending = false;
    impl->passive_open_send_pending = false;
    impl->passive_keepalive_pending = false;
    impl->session_generation++;
    bgp_unlock(&impl->lock);
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
    fsm_impl_t *impl = fsm_impl_get(fsm);
    struct libbgp_fsm_config config;
    libbgp_out_handler_t *out;
    libbgp_fsm_state_t start_state;
    uint64_t session_generation;
    libbgp_err_t err;

    if (impl == NULL) {
        return LIBBGP_ERR_INVALID;
    }
    bgp_lock(&impl->lock);
    if (!fsm_local_open_config_valid(&impl->config)) {
        bgp_unlock(&impl->lock);
        return LIBBGP_ERR_INVALID;
    }
    if (impl->state != LIBBGP_FSM_IDLE &&
        impl->state != LIBBGP_FSM_ACTIVE &&
        impl->state != LIBBGP_FSM_CONNECT) {
        bgp_unlock(&impl->lock);
        return LIBBGP_OK;
    }
    start_state = impl->state;
    impl->state = LIBBGP_FSM_OPEN_SENT;
    impl->session_generation++;
    session_generation = impl->session_generation;
    impl->peer_asn = 0u;
    impl->peer_bgp_id = 0u;
    impl->negotiated_hold_time = impl->config.hold_time;
    impl->peer_mpbgp_ipv6 = false;
    impl->clock_initialized = false;
    impl->local_keepalive_send_pending = false;
    impl->local_keepalive_pending = false;
    impl->passive_open_send_pending = false;
    impl->passive_keepalive_pending = false;
    config = impl->config;
    out = impl->out;
    bgp_unlock(&impl->lock);

    err = fsm_send_open(out, &config);
    bgp_lock(&impl->lock);
    if (err != LIBBGP_OK && impl->state == LIBBGP_FSM_OPEN_SENT &&
        impl->session_generation == session_generation) {
        impl->state = start_state;
        impl->local_keepalive_send_pending = false;
        impl->local_keepalive_pending = false;
        impl->passive_open_send_pending = false;
        impl->passive_keepalive_pending = false;
        impl->session_generation++;
    }
    bgp_unlock(&impl->lock);
    return err;
}

libbgp_err_t libbgp_fsm_stop(libbgp_fsm_t *fsm)
{
    fsm_impl_t *impl = fsm_impl_get(fsm);
    libbgp_out_handler_t *out;
    libbgp_event_bus_t *bus = NULL;
    libbgp_rib4_t *rib4 = NULL;
    libbgp_rib6_t *rib6 = NULL;
    uint32_t peer_bgp_id = 0u;
    bool notify;
    bool was_established;
    libbgp_err_t err;

    if (impl == NULL) {
        return LIBBGP_ERR_INVALID;
    }
    bgp_lock(&impl->lock);
    notify = impl->state != LIBBGP_FSM_IDLE;
    was_established = impl->state == LIBBGP_FSM_ESTABLISHED;
    fsm_snapshot_teardown(impl, &out, &bus, &rib4, &rib6, &peer_bgp_id);
    bgp_unlock(&impl->lock);

    err = notify ? fsm_send_notification(out, FSM_NOTIFY_CEASE, 0u) : LIBBGP_OK;
    if (was_established) {
        fsm_discard_peer_routes(rib4, rib6, peer_bgp_id);
        fsm_publish_event(bus, LIBBGP_EVENT_SESSION_DOWN, 0u, NULL, NULL);
    }
    return err;
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
    impl->state = LIBBGP_FSM_IDLE;
    impl->peer_asn = 0u;
    impl->peer_bgp_id = 0u;
    impl->negotiated_hold_time = impl->config.hold_time;
    impl->peer_mpbgp_ipv6 = false;
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
    impl->state = LIBBGP_FSM_ESTABLISHED;
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
    libbgp_event_bus_t *bus = NULL;
    uint16_t local_hold;
    uint16_t peer_hold;
    uint32_t peer_asn;
    uint32_t peer_bgp_id;
    uint16_t negotiated_hold_time;
    bool peer_mpbgp_ipv6;
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
    if (pkt->data.open.bgp_id == 0u) {
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
    peer_bgp_id = pkt->data.open.bgp_id;
    peer_mpbgp_ipv6 = impl->config.enable_mpbgp_ipv6 &&
        libbgp_open_has_mpbgp(&pkt->data.open, LIBBGP_AFI_IPV6, LIBBGP_SAFI_UNICAST);
    negotiated_hold_time = (local_hold == 0u || peer_hold == 0u) ? 0u :
        (local_hold < peer_hold ? local_hold : peer_hold);
    impl->peer_asn = peer_asn;
    impl->peer_bgp_id = peer_bgp_id;
    impl->negotiated_hold_time = negotiated_hold_time;
    impl->peer_mpbgp_ipv6 = peer_mpbgp_ipv6;
    impl->state = LIBBGP_FSM_OPEN_CONFIRM;
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
            bus = impl->bus;
        }
    }
    bgp_unlock(&impl->lock);
    if (bus != NULL) {
        fsm_publish_event(bus, LIBBGP_EVENT_SESSION_UP, 0u, NULL, NULL);
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
    bool peer_mpbgp_ipv6;
    bool still_current;
    libbgp_event_bus_t *bus = NULL;
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
    if (pkt->data.open.bgp_id == 0u) {
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
    peer_bgp_id = pkt->data.open.bgp_id;
    peer_mpbgp_ipv6 = impl->config.enable_mpbgp_ipv6 &&
        libbgp_open_has_mpbgp(&pkt->data.open, LIBBGP_AFI_IPV6, LIBBGP_SAFI_UNICAST);
    negotiated_hold_time = (local_hold == 0u || peer_hold == 0u) ? 0u :
        (local_hold < peer_hold ? local_hold : peer_hold);
    config = impl->config;
    impl->peer_asn = peer_asn;
    impl->peer_bgp_id = peer_bgp_id;
    impl->negotiated_hold_time = negotiated_hold_time;
    impl->peer_mpbgp_ipv6 = peer_mpbgp_ipv6;
    impl->state = LIBBGP_FSM_OPEN_CONFIRM;
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

    err = fsm_send_open(out, &config);
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
            bus = impl->bus;
        }
    } else if (impl->state == LIBBGP_FSM_OPEN_CONFIRM &&
        impl->session_generation == session_generation) {
        impl->local_keepalive_send_pending = false;
    }
    if (bus != NULL) {
        bus = impl->bus;
        bgp_unlock(&impl->lock);
        fsm_publish_event(bus, LIBBGP_EVENT_SESSION_UP, 0u, NULL, NULL);
        return LIBBGP_OK;
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
    libbgp_event_bus_t *bus = NULL;
    libbgp_out_handler_t *out = NULL;

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
        if (pkt->data.open.bgp_id == 0u) {
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
        impl->state = LIBBGP_FSM_ESTABLISHED;
        impl->session_generation++;
        impl->local_keepalive_send_pending = false;
        impl->local_keepalive_pending = false;
        impl->passive_open_send_pending = false;
        impl->passive_keepalive_pending = false;
        bus = impl->bus;
        bgp_unlock(&impl->lock);
        fsm_publish_event(bus, LIBBGP_EVENT_SESSION_UP, 0u, NULL, NULL);
        return LIBBGP_OK;
    }
    if (pkt->type == LIBBGP_PACKET_NOTIFICATION) {
        impl->state = LIBBGP_FSM_IDLE;
        impl->session_generation++;
        impl->local_keepalive_send_pending = false;
        impl->local_keepalive_pending = false;
        impl->passive_open_send_pending = false;
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
    fsm_update_journal_t journal;
    uint8_t update_err_subcode = FSM_UPDATE_ERR_MALFORMED_ATTR_LIST;
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
        fsm_discard_peer_routes(rib4, rib6, peer_bgp_id);
        fsm_publish_event(bus, LIBBGP_EVENT_SESSION_DOWN, 0u, NULL, NULL);
        return LIBBGP_OK;
    }
    if (pkt->type != LIBBGP_PACKET_UPDATE) {
        fsm_snapshot_teardown(impl, &out, &bus, &rib4, &rib6, &peer_bgp_id);
        bgp_unlock(&impl->lock);
        (void)fsm_send_notification(out, FSM_NOTIFY_FSM_ERROR, FSM_ERR_ESTABLISHED);
        fsm_discard_peer_routes(rib4, rib6, peer_bgp_id);
        fsm_publish_event(bus, LIBBGP_EVENT_SESSION_DOWN, 0u, NULL, NULL);
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
                send_err = fsm_send_notification(
                    out,
                    FSM_NOTIFY_UPDATE_MESSAGE_ERROR,
                    FSM_UPDATE_ERR_MALFORMED_ATTR_LIST);
                fsm_discard_peer_routes(rib4, rib6, peer_bgp_id);
                fsm_publish_event(bus, LIBBGP_EVENT_SESSION_DOWN, 0u, NULL, NULL);
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
        fsm_rollback_update_journal(&journal, rib4, rib6, peer_bgp_id);
        send_err = fsm_send_notification(out, FSM_NOTIFY_UPDATE_MESSAGE_ERROR, update_err_subcode);
        fsm_discard_peer_routes(rib4, rib6, peer_bgp_id);
        fsm_publish_event(bus, LIBBGP_EVENT_SESSION_DOWN, 0u, NULL, NULL);
        fsm_update_journal_destroy(&journal);
        return send_err == LIBBGP_OK ? err : send_err;
    }
    if (err == LIBBGP_OK && impl->clock_initialized) {
        impl->last_rx_ms = rx_ms;
    }
    bgp_unlock(&impl->lock);
    if (err == LIBBGP_OK) {
        fsm_publish_update_events(impl, session_generation, bus, peer_bgp_id, &pkt->data.update);
    }
    fsm_update_journal_destroy(&journal);
    return err;
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
        libbgp_event_bus_t *bus = NULL;
        libbgp_rib4_t *rib4 = NULL;
        libbgp_rib6_t *rib6 = NULL;
        uint32_t peer_bgp_id = 0u;

        fsm_snapshot_teardown(impl, NULL, &bus, &rib4, &rib6, &peer_bgp_id);
        bgp_unlock(&impl->lock);
        if (state == LIBBGP_FSM_ESTABLISHED) {
            fsm_discard_peer_routes(rib4, rib6, peer_bgp_id);
            fsm_publish_event(bus, LIBBGP_EVENT_SESSION_DOWN, 0u, NULL, NULL);
        }
        return LIBBGP_OK;
    }

    switch (state) {
    case LIBBGP_FSM_IDLE:
        if (pkt->type == LIBBGP_PACKET_OPEN) {
            return fsm_on_pre_open_open(impl, pkt);
        }
        bgp_unlock(&impl->lock);
        return LIBBGP_OK;
    case LIBBGP_FSM_CONNECT:
    case LIBBGP_FSM_ACTIVE:
        if (pkt->type == LIBBGP_PACKET_OPEN) {
            return fsm_on_pre_open_open(impl, pkt);
        }
        bgp_unlock(&impl->lock);
        return LIBBGP_OK;
    case LIBBGP_FSM_OPEN_SENT:
        return fsm_on_open_sent(impl, pkt);
    case LIBBGP_FSM_OPEN_CONFIRM:
        return fsm_on_open_confirm(impl, pkt);
    case LIBBGP_FSM_ESTABLISHED:
        return fsm_on_established(impl, pkt);
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
    libbgp_rib4_t *rib4 = NULL;
    libbgp_rib6_t *rib6 = NULL;
    uint32_t peer_bgp_id = 0u;
    bool send_keepalive = false;
    bool send_hold_expired = false;
    bool was_established = false;
    libbgp_fsm_state_t keepalive_state = LIBBGP_FSM_IDLE;
    uint64_t keepalive_generation = 0u;
    uint16_t keepalive_time = 0u;

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
        fsm_state_hold_timer_active(impl->state) &&
        now_ms - impl->last_rx_ms >= (uint64_t)impl->negotiated_hold_time * 1000u) {
        send_hold_expired = true;
        was_established = impl->state == LIBBGP_FSM_ESTABLISHED;
        fsm_snapshot_teardown(impl, &out, &bus, &rib4, &rib6, &peer_bgp_id);
        bgp_unlock(&impl->lock);
        (void)fsm_send_notification(out, FSM_NOTIFY_HOLD_TIMER_EXPIRED, 0u);
        if (was_established) {
            fsm_discard_peer_routes(rib4, rib6, peer_bgp_id);
            fsm_publish_event(bus, LIBBGP_EVENT_SESSION_DOWN, 0u, NULL, NULL);
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
            if (was_established) {
                fsm_discard_peer_routes(rib4, rib6, peer_bgp_id);
                fsm_publish_event(bus, LIBBGP_EVENT_SESSION_DOWN, 0u, NULL, NULL);
            }
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
