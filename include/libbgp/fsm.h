#ifndef LIBBGP_FSM_H
#define LIBBGP_FSM_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "libbgp/types.h"
#include "libbgp/open.h"
#include "libbgp/update.h"
#include "libbgp/packet.h"
#include "libbgp/rib4.h"
#include "libbgp/rib6.h"
#include "libbgp/event.h"
#include "libbgp/out_handler.h"

typedef enum libbgp_fsm_state {
    LIBBGP_FSM_IDLE,
    LIBBGP_FSM_CONNECT,
    LIBBGP_FSM_ACTIVE,
    LIBBGP_FSM_OPEN_SENT,
    LIBBGP_FSM_OPEN_CONFIRM,
    LIBBGP_FSM_ESTABLISHED
} libbgp_fsm_state_t;

typedef void (*libbgp_fsm_state_change_fn)(
    libbgp_fsm_state_t old_state,
    libbgp_fsm_state_t new_state,
    void *ctx);

struct libbgp_fsm_config {
    uint32_t local_asn;
    uint32_t local_bgp_id;
    uint16_t hold_time;
    uint16_t keepalive_time;
    bool enable_4byte_asn;
    bool enable_mpbgp_ipv6;
};

struct libbgp_fsm {
    void *impl;
};

LIBBGP_API libbgp_err_t libbgp_fsm_init(libbgp_fsm_t *fsm, const struct libbgp_fsm_config *config);
LIBBGP_API void libbgp_fsm_destroy(libbgp_fsm_t *fsm);
LIBBGP_API libbgp_fsm_state_t libbgp_fsm_state(const libbgp_fsm_t *fsm);
/*
 * Attached RIBs, event buses, and output handlers are borrowed pointers.
 * Keep them alive while attached and externally synchronize destroy/replace.
 */
LIBBGP_API void libbgp_fsm_set_rib4(libbgp_fsm_t *fsm, libbgp_rib4_t *rib4);
LIBBGP_API void libbgp_fsm_set_rib6(libbgp_fsm_t *fsm, libbgp_rib6_t *rib6);
LIBBGP_API libbgp_rib4_t *libbgp_fsm_get_rib4(libbgp_fsm_t *fsm);
LIBBGP_API libbgp_rib6_t *libbgp_fsm_get_rib6(libbgp_fsm_t *fsm);
LIBBGP_API void libbgp_fsm_set_event_bus(libbgp_fsm_t *fsm, libbgp_event_bus_t *bus);
LIBBGP_API void libbgp_fsm_set_out_handler(libbgp_fsm_t *fsm, libbgp_out_handler_t *out);
LIBBGP_API void libbgp_fsm_set_state_change_cb(
    libbgp_fsm_t *fsm,
    libbgp_fsm_state_change_fn cb,
    void *ctx);
/* Pass 0 to accept any peer ASN. */
LIBBGP_API void libbgp_fsm_set_expected_peer_asn(libbgp_fsm_t *fsm, uint32_t peer_asn);
LIBBGP_API void libbgp_fsm_set_mpbgp_ipv4(libbgp_fsm_t *fsm, bool enabled);
LIBBGP_API void libbgp_fsm_set_no_collision_detection(libbgp_fsm_t *fsm, bool disabled);
LIBBGP_API void libbgp_fsm_set_allow_local_as(libbgp_fsm_t *fsm, uint8_t allow_count);
LIBBGP_API void libbgp_fsm_set_route_weight(libbgp_fsm_t *fsm, int32_t weight);
LIBBGP_API void libbgp_fsm_set_in_filter4(libbgp_fsm_t *fsm, const libbgp_filter_t *filter);
LIBBGP_API void libbgp_fsm_set_out_filter4(libbgp_fsm_t *fsm, const libbgp_filter_t *filter);
LIBBGP_API void libbgp_fsm_set_in_filter6(libbgp_fsm_t *fsm, const libbgp_filter_t *filter);
LIBBGP_API void libbgp_fsm_set_out_filter6(libbgp_fsm_t *fsm, const libbgp_filter_t *filter);
LIBBGP_API void libbgp_fsm_set_peering_lan4(libbgp_fsm_t *fsm, const libbgp_prefix4_t *prefix);
LIBBGP_API void libbgp_fsm_set_no_nexthop_check4(libbgp_fsm_t *fsm, bool disabled);
LIBBGP_API void libbgp_fsm_set_default_nexthop4(libbgp_fsm_t *fsm, uint32_t next_hop);
LIBBGP_API void libbgp_fsm_set_force_default_nexthop4(libbgp_fsm_t *fsm, bool forced);
LIBBGP_API void libbgp_fsm_set_peering_lan6(libbgp_fsm_t *fsm, const libbgp_prefix6_t *prefix);
LIBBGP_API void libbgp_fsm_set_no_nexthop_check6(libbgp_fsm_t *fsm, bool disabled);
LIBBGP_API void libbgp_fsm_set_default_nexthop6(libbgp_fsm_t *fsm, const uint8_t next_hop[16]);
LIBBGP_API void libbgp_fsm_set_default_nexthop6_linklocal(libbgp_fsm_t *fsm, const uint8_t next_hop[16]);
LIBBGP_API void libbgp_fsm_set_force_default_nexthop6(libbgp_fsm_t *fsm, bool forced);
LIBBGP_API void libbgp_fsm_set_ibgp_alter_nexthop(libbgp_fsm_t *fsm, bool enabled);
LIBBGP_API libbgp_err_t libbgp_fsm_enter_connect(libbgp_fsm_t *fsm);
LIBBGP_API libbgp_err_t libbgp_fsm_enter_active(libbgp_fsm_t *fsm);
LIBBGP_API libbgp_err_t libbgp_fsm_start(libbgp_fsm_t *fsm);
LIBBGP_API libbgp_err_t libbgp_fsm_stop(libbgp_fsm_t *fsm);
LIBBGP_API libbgp_err_t libbgp_fsm_reset_soft(libbgp_fsm_t *fsm);
LIBBGP_API libbgp_err_t libbgp_fsm_reset_hard(libbgp_fsm_t *fsm);
LIBBGP_API libbgp_err_t libbgp_fsm_on_packet(libbgp_fsm_t *fsm, const libbgp_packet_t *pkt);
/*
 * Parses and handles exactly one complete BGP message. Extra or partial trailing
 * bytes are a message length error and may send a NOTIFICATION before teardown.
 */
LIBBGP_API libbgp_err_t libbgp_fsm_on_raw_packet(libbgp_fsm_t *fsm, const uint8_t *buf, size_t len);
LIBBGP_API libbgp_err_t libbgp_fsm_tick(libbgp_fsm_t *fsm, uint64_t now_ms);
LIBBGP_API uint32_t libbgp_fsm_peer_asn(const libbgp_fsm_t *fsm);
LIBBGP_API uint32_t libbgp_fsm_peer_bgp_id(const libbgp_fsm_t *fsm);
LIBBGP_API uint16_t libbgp_fsm_negotiated_hold_time(const libbgp_fsm_t *fsm);

#endif
