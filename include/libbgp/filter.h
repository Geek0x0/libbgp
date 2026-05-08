#ifndef LIBBGP_FILTER_H
#define LIBBGP_FILTER_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "libbgp/types.h"
#include "libbgp/prefix4.h"
#include "libbgp/pattr.h"
#include "libbgp/rib4.h"

typedef enum libbgp_filter_decision {
    LIBBGP_FILTER_DENY = 0,
    LIBBGP_FILTER_PERMIT = 1
} libbgp_filter_decision_t;

typedef enum libbgp_filter_match_type {
    LIBBGP_FILTER_MATCH_PREFIX4,
    LIBBGP_FILTER_MATCH_AS_PATH_CONTAINS,
    LIBBGP_FILTER_MATCH_COMMUNITY_CONTAINS,
    LIBBGP_FILTER_MATCH_ANY
} libbgp_filter_match_type_t;

typedef struct libbgp_filter_rule {
    libbgp_filter_match_type_t match_type;
    libbgp_filter_decision_t decision;
    union {
        libbgp_prefix4_t prefix4;
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
LIBBGP_API size_t libbgp_filter_rule_count(const libbgp_filter_t *filter);

#endif
