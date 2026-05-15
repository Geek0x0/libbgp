#ifndef LIBBGP_TYPES_H
#define LIBBGP_TYPES_H

/**
 * @file types.h
 * @brief Core libbgp constants, error codes, address families, and forward declarations.
 * @ingroup libbgp_core
 */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#if defined(LIBBGP_SHARED) && defined(__GNUC__)
#define LIBBGP_API __attribute__((visibility("default")))
#else
#define LIBBGP_API
#endif

/** @brief Length in bytes of the BGP message marker field. */
#define LIBBGP_BGP_MARKER_LEN 16u
/** @brief Length in bytes of a BGP message header. */
#define LIBBGP_BGP_HEADER_LEN 19u
/** @brief Minimum valid BGP packet length in bytes (header only). */
#define LIBBGP_BGP_MIN_PACKET_LEN 19u
/** @brief Maximum valid BGP packet length in bytes. */
#define LIBBGP_BGP_MAX_PACKET_LEN 4096u
/** @brief AS_TRANS value used when a 4-byte ASN must be encoded in a 2-byte field. */
#define LIBBGP_AS_TRANS 23456u

typedef enum libbgp_err {
    LIBBGP_OK            =  0,  ///< Operation completed successfully.
    LIBBGP_ERR           = -1,  ///< Generic operation failure.
    LIBBGP_ERR_PARSE     = -2,  ///< Input bytes could not be parsed as the requested BGP object.
    LIBBGP_ERR_WRITE     = -3,  ///< Object could not be serialized into the supplied output buffer.
    LIBBGP_ERR_BAD_TYPE  = -4,  ///< Input contained an unsupported or unexpected type code.
    LIBBGP_ERR_BAD_LEN   = -5,  ///< Input or output length was invalid for the requested operation.
    LIBBGP_ERR_BUFFER    = -6,  ///< Supplied buffer was too small or incomplete.
    LIBBGP_ERR_INVALID   = -7,  ///< Caller supplied invalid arguments or object state.
    LIBBGP_ERR_EXISTS    = -8,  ///< Requested object already exists.
    LIBBGP_ERR_NOT_FOUND = -9,  ///< Requested object was not found.
    LIBBGP_ERR_NOMEM     = -10  ///< Memory allocation failed.
} libbgp_err_t;

typedef enum libbgp_afi {
    LIBBGP_AFI_IPV4 = 1, ///< IPv4 address family.
    LIBBGP_AFI_IPV6 = 2  ///< IPv6 address family.
} libbgp_afi_t;

typedef enum libbgp_safi {
    LIBBGP_SAFI_UNICAST = 1 ///< Unicast subsequent address family.
} libbgp_safi_t;

typedef struct libbgp_logger libbgp_logger_t;
typedef struct libbgp_prefix4 libbgp_prefix4_t;
typedef struct libbgp_prefix6 libbgp_prefix6_t;
typedef struct libbgp_capability libbgp_capability_t;
typedef struct libbgp_pattr libbgp_pattr_t;
typedef struct libbgp_open_msg libbgp_open_msg_t;
typedef struct libbgp_update_msg libbgp_update_msg_t;
typedef struct libbgp_notification_msg libbgp_notification_msg_t;
typedef struct libbgp_packet libbgp_packet_t;
typedef struct libbgp_rib4 libbgp_rib4_t;
typedef struct libbgp_rib6 libbgp_rib6_t;
typedef struct libbgp_filter libbgp_filter_t;
typedef struct libbgp_event_bus libbgp_event_bus_t;
typedef struct libbgp_sink libbgp_sink_t;
typedef struct libbgp_out_handler libbgp_out_handler_t;
typedef struct libbgp_fsm libbgp_fsm_t;

/**
 * @brief Return a stable human-readable string for a libbgp error code.
 *
 * @param err Error code returned by a libbgp API.
 * @return Static string describing `err`; never `NULL`.
 */
LIBBGP_API const char *libbgp_strerror(libbgp_err_t err);

#endif
