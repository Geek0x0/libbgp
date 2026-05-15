#ifndef LIBBGP_H
#define LIBBGP_H

/**
 * @file libbgp.h
 * @brief Umbrella public header for the libbgp C API.
 */

/**
 * @defgroup libbgp_core Core
 * @brief Core constants, error codes, allocator hooks, and logging.
 */

/**
 * @defgroup libbgp_prefix Prefix
 * @brief IPv4 and IPv6 prefix parsing, serialization, comparison, and containment.
 */

/**
 * @defgroup libbgp_messages Messages
 * @brief BGP OPEN, UPDATE, KEEPALIVE, and NOTIFICATION message helpers.
 */

/**
 * @defgroup libbgp_packet Packet
 * @brief Top-level BGP packet parsing and serialization.
 */

/**
 * @defgroup libbgp_rib RIB
 * @brief IPv4 and IPv6 routing information bases with best-path lookup.
 */

/**
 * @defgroup libbgp_filter Filter
 * @brief Ordered route filter rules for IPv4 and IPv6 routes.
 */

/**
 * @defgroup libbgp_event Event
 * @brief Synchronous event bus for session, route, collision, and custom events.
 */

/**
 * @defgroup libbgp_io I/O
 * @brief Incremental packet sink and output handler abstractions.
 */

/**
 * @defgroup libbgp_fsm FSM
 * @brief BGP finite state machine lifecycle, packet input, timers, and route import/export.
 */

#include "libbgp/types.h"
#include "libbgp/alloc.h"
#include "libbgp/log.h"
#include "libbgp/prefix4.h"
#include "libbgp/prefix6.h"
#include "libbgp/capability.h"
#include "libbgp/pattr.h"
#include "libbgp/open.h"
#include "libbgp/update.h"
#include "libbgp/keepalive.h"
#include "libbgp/notification.h"
#include "libbgp/packet.h"
#include "libbgp/rib4.h"
#include "libbgp/rib6.h"
#include "libbgp/filter.h"
#include "libbgp/event.h"
#include "libbgp/sink.h"
#include "libbgp/out_handler.h"
#include "libbgp/fsm.h"

#endif
