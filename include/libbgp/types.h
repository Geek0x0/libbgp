#ifndef LIBBGP_TYPES_H
#define LIBBGP_TYPES_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#if defined(LIBBGP_SHARED) && defined(__GNUC__)
#define LIBBGP_API __attribute__((visibility("default")))
#else
#define LIBBGP_API
#endif

#define LIBBGP_BGP_MARKER_LEN 16u
#define LIBBGP_BGP_HEADER_LEN 19u
#define LIBBGP_BGP_MIN_PACKET_LEN 19u
#define LIBBGP_BGP_MAX_PACKET_LEN 4096u
#define LIBBGP_AS_TRANS 23456u

typedef enum libbgp_err {
    LIBBGP_OK            =  0,
    LIBBGP_ERR           = -1,
    LIBBGP_ERR_PARSE     = -2,
    LIBBGP_ERR_WRITE     = -3,
    LIBBGP_ERR_BAD_TYPE  = -4,
    LIBBGP_ERR_BAD_LEN   = -5,
    LIBBGP_ERR_BUFFER    = -6,
    LIBBGP_ERR_INVALID   = -7,
    LIBBGP_ERR_EXISTS    = -8,
    LIBBGP_ERR_NOT_FOUND = -9,
    LIBBGP_ERR_NOMEM     = -10
} libbgp_err_t;

typedef enum libbgp_afi {
    LIBBGP_AFI_IPV4 = 1,
    LIBBGP_AFI_IPV6 = 2
} libbgp_afi_t;

typedef enum libbgp_safi {
    LIBBGP_SAFI_UNICAST = 1
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

LIBBGP_API const char *libbgp_strerror(libbgp_err_t err);

#endif
