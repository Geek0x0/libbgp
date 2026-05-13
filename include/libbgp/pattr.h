#ifndef LIBBGP_PATTR_H
#define LIBBGP_PATTR_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "libbgp/types.h"
#include "libbgp/prefix6.h"

#define LIBBGP_PATTR_FLAG_OPTIONAL 0x80u
#define LIBBGP_PATTR_FLAG_TRANSITIVE 0x40u
#define LIBBGP_PATTR_FLAG_PARTIAL 0x20u
#define LIBBGP_PATTR_FLAG_EXTENDED_LENGTH 0x10u

#define LIBBGP_PATTR_CODE_ORIGIN 1u
#define LIBBGP_PATTR_CODE_AS_PATH 2u
#define LIBBGP_PATTR_CODE_NEXT_HOP 3u
#define LIBBGP_PATTR_CODE_MED 4u
#define LIBBGP_PATTR_CODE_LOCAL_PREF 5u
#define LIBBGP_PATTR_CODE_ATOMIC_AGGREGATE 6u
#define LIBBGP_PATTR_CODE_AGGREGATOR 7u
#define LIBBGP_PATTR_CODE_COMMUNITY 8u
#define LIBBGP_PATTR_CODE_MP_REACH_NLRI 14u
#define LIBBGP_PATTR_CODE_MP_UNREACH_NLRI 15u
#define LIBBGP_PATTR_CODE_AS4_PATH 17u
#define LIBBGP_PATTR_CODE_AS4_AGGREGATOR 18u

typedef enum libbgp_pattr_type {
    LIBBGP_PATTR_ORIGIN,
    LIBBGP_PATTR_AS_PATH,
    LIBBGP_PATTR_NEXT_HOP,
    LIBBGP_PATTR_MED,
    LIBBGP_PATTR_LOCAL_PREF,
    LIBBGP_PATTR_ATOMIC_AGGREGATE,
    LIBBGP_PATTR_AGGREGATOR,
    LIBBGP_PATTR_COMMUNITY,
    LIBBGP_PATTR_AS4_PATH,
    LIBBGP_PATTR_AS4_AGGREGATOR,
    LIBBGP_PATTR_MP_REACH_IPV6,
    LIBBGP_PATTR_MP_UNREACH_IPV6,
    LIBBGP_PATTR_UNKNOWN
} libbgp_pattr_type_t;

typedef struct libbgp_as_path_segment {
    uint8_t type;
    size_t asn_count;
    uint32_t *asns;
} libbgp_as_path_segment_t;

struct libbgp_pattr {
    uint32_t refcount;
    uint8_t flags;
    uint8_t type_code;
    libbgp_pattr_type_t type;
    union {
        struct { uint8_t origin; } origin;
        struct {
            libbgp_as_path_segment_t *segments;
            size_t segment_count;
            bool is_4b;
        } as_path;
        struct { uint32_t next_hop; } next_hop;
        struct { uint32_t value; } med;
        struct { uint32_t value; } local_pref;
        struct {
            uint32_t asn;
            uint32_t router_id;
            bool is_4b;
        } aggregator;
        struct {
            uint32_t *values;
            size_t count;
        } community;
        struct {
            uint8_t nexthop[32];
            size_t nexthop_len;
            libbgp_prefix6_t *nlri;
            size_t nlri_count;
        } mp_reach_ipv6;
        struct {
            libbgp_prefix6_t *withdrawn;
            size_t withdrawn_count;
        } mp_unreach_ipv6;
        struct {
            uint8_t *value;
            size_t len;
        } unknown;
    } data;
};

LIBBGP_API libbgp_pattr_t *libbgp_pattr_new(libbgp_pattr_type_t type);
LIBBGP_API libbgp_pattr_t *libbgp_pattr_ref(libbgp_pattr_t *attr);
LIBBGP_API void libbgp_pattr_unref(libbgp_pattr_t *attr);

LIBBGP_API libbgp_pattr_type_t libbgp_pattr_type_from_buf(const uint8_t *buf, size_t len);
LIBBGP_API const char *libbgp_pattr_type_name(libbgp_pattr_type_t type);

LIBBGP_API libbgp_err_t libbgp_pattr_parse(
    libbgp_pattr_t *attr,
    const uint8_t *buf,
    size_t len,
    size_t *consumed);

LIBBGP_API libbgp_err_t libbgp_pattr_parse_as4(
    libbgp_pattr_t *attr,
    const uint8_t *buf,
    size_t len,
    bool use_4b_asn,
    size_t *consumed);

LIBBGP_API libbgp_err_t libbgp_pattr_wire_len(const libbgp_pattr_t *attr, size_t *out_len);

LIBBGP_API libbgp_err_t libbgp_pattr_write(
    const libbgp_pattr_t *attr,
    uint8_t *buf,
    size_t buf_len,
    size_t *out_len);

LIBBGP_API libbgp_err_t libbgp_pattr_prepare_for_ebgp_forward(libbgp_pattr_t *attr);

LIBBGP_API libbgp_err_t libbgp_pattr_format(
    const libbgp_pattr_t *attr,
    char *buf,
    size_t buf_len,
    size_t *out_len);

#endif
