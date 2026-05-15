#ifndef LIBBGP_FILTER_H
#define LIBBGP_FILTER_H


/**
 * @file filter.h
 * @brief Ordered IPv4 and IPv6 route filter rules.
 * @ingroup libbgp_filter
 */
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "libbgp/types.h"
#include "libbgp/prefix4.h"
#include "libbgp/prefix6.h"
#include "libbgp/pattr.h"
#include "libbgp/rib4.h"
#include "libbgp/rib6.h"

typedef enum libbgp_filter_decision {
    LIBBGP_FILTER_DENY = 0,
    LIBBGP_FILTER_PERMIT = 1
} libbgp_filter_decision_t;

typedef enum libbgp_filter_match_type {
    LIBBGP_FILTER_MATCH_PREFIX4,
    LIBBGP_FILTER_MATCH_AS_PATH_CONTAINS,
    LIBBGP_FILTER_MATCH_COMMUNITY_CONTAINS,
    LIBBGP_FILTER_MATCH_ANY,
    LIBBGP_FILTER_MATCH_PREFIX4_EXACT,
    LIBBGP_FILTER_MATCH_PREFIX4_MORE_SPECIFIC,
    LIBBGP_FILTER_MATCH_PREFIX4_MORE_OR_EQUAL,
    LIBBGP_FILTER_MATCH_PREFIX4_LESS_SPECIFIC,
    LIBBGP_FILTER_MATCH_PREFIX4_LESS_OR_EQUAL,
    LIBBGP_FILTER_MATCH_AS_PATH_NOT_CONTAINS,
    LIBBGP_FILTER_MATCH_AS_PATH_ORIGIN,
    LIBBGP_FILTER_MATCH_AS_PATH_NOT_ORIGIN,
    LIBBGP_FILTER_MATCH_COMMUNITY_NOT_CONTAINS,
    LIBBGP_FILTER_MATCH_PREFIX6,
    LIBBGP_FILTER_MATCH_PREFIX6_EXACT,
    LIBBGP_FILTER_MATCH_PREFIX6_MORE_SPECIFIC,
    LIBBGP_FILTER_MATCH_PREFIX6_MORE_OR_EQUAL,
    LIBBGP_FILTER_MATCH_PREFIX6_LESS_SPECIFIC,
    LIBBGP_FILTER_MATCH_PREFIX6_LESS_OR_EQUAL
} libbgp_filter_match_type_t;

typedef struct libbgp_filter_rule {
    libbgp_filter_match_type_t match_type;
    libbgp_filter_decision_t decision;
    union {
        libbgp_prefix4_t prefix4;
        libbgp_prefix6_t prefix6;
        uint32_t asn;
        uint32_t community;
    } match;
} libbgp_filter_rule_t;

struct libbgp_filter {
    void *impl;
};

LIBBGP_API libbgp_err_t libbgp_filter_init(libbgp_filter_t *filter);
LIBBGP_API void libbgp_filter_destroy(libbgp_filter_t *filter);
LIBBGP_API libbgp_err_t libbgp_filter_add_rule(libbgp_filter_t *filter, const libbgp_filter_rule_t *rule);
LIBBGP_API void libbgp_filter_clear(libbgp_filter_t *filter);
LIBBGP_API libbgp_filter_decision_t libbgp_filter_apply_route(
    const libbgp_filter_t *filter,
    const libbgp_rib4_route_t *route,
    libbgp_filter_decision_t default_decision);
LIBBGP_API libbgp_filter_decision_t libbgp_filter_apply_route6(
    const libbgp_filter_t *filter,
    const libbgp_rib6_route_t *route,
    libbgp_filter_decision_t default_decision);
LIBBGP_API size_t libbgp_filter_rule_count(const libbgp_filter_t *filter);

#endif
