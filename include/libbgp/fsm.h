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

struct libbgp_fsm_config {
    uint32_t local_asn;
    uint32_t local_bgp_id;
    uint16_t hold_time;
    uint16_t keepalive_time;
    bool enable_4byte_asn;
};

struct libbgp_fsm {
    void *impl;
};

LIBBGP_API libbgp_err_t libbgp_fsm_init(libbgp_fsm_t *fsm, const struct libbgp_fsm_config *config);
LIBBGP_API void libbgp_fsm_destroy(libbgp_fsm_t *fsm);
LIBBGP_API libbgp_fsm_state_t libbgp_fsm_state(const libbgp_fsm_t *fsm);
LIBBGP_API void libbgp_fsm_set_rib4(libbgp_fsm_t *fsm, libbgp_rib4_t *rib4);
LIBBGP_API void libbgp_fsm_set_event_bus(libbgp_fsm_t *fsm, libbgp_event_bus_t *bus);
LIBBGP_API void libbgp_fsm_set_out_handler(libbgp_fsm_t *fsm, libbgp_out_handler_t *out);
LIBBGP_API libbgp_err_t libbgp_fsm_start(libbgp_fsm_t *fsm);
LIBBGP_API libbgp_err_t libbgp_fsm_stop(libbgp_fsm_t *fsm);
LIBBGP_API libbgp_err_t libbgp_fsm_on_packet(libbgp_fsm_t *fsm, const libbgp_packet_t *pkt);
LIBBGP_API libbgp_err_t libbgp_fsm_tick(libbgp_fsm_t *fsm, uint64_t now_ms);
LIBBGP_API uint32_t libbgp_fsm_peer_asn(const libbgp_fsm_t *fsm);
LIBBGP_API uint32_t libbgp_fsm_peer_bgp_id(const libbgp_fsm_t *fsm);

#endif
