#include "test_main.h"

#include "libbgp/filter.h"
#include "libbgp/alloc.h"

#include <stdint.h>
#include <stdlib.h>

typedef struct fail_realloc_ctx {
    size_t realloc_calls;
    size_t fail_realloc_at;
} fail_realloc_ctx_t;

typedef struct fail_calloc_ctx {
    size_t calloc_calls;
    size_t fail_calloc_at;
} fail_calloc_ctx_t;

static void *filter_fail_malloc(size_t size, void *ctx)
{
    (void)ctx;
    return malloc(size);
}

static void *filter_fail_calloc(size_t nmemb, size_t size, void *ctx)
{
    fail_calloc_ctx_t *fail = (fail_calloc_ctx_t *)ctx;

    if (fail != NULL) {
        fail->calloc_calls++;
        if (fail->fail_calloc_at != 0u && fail->calloc_calls == fail->fail_calloc_at) {
            return NULL;
        }
    }
    return calloc(nmemb, size);
}

static void *filter_fail_realloc(void *ptr, size_t size, void *ctx)
{
    fail_realloc_ctx_t *fail = (fail_realloc_ctx_t *)ctx;

    fail->realloc_calls++;
    if (fail->fail_realloc_at != 0u && fail->realloc_calls == fail->fail_realloc_at) {
        return NULL;
    }
    return realloc(ptr, size);
}

static void filter_fail_free(void *ptr, void *ctx)
{
    (void)ctx;
    free(ptr);
}

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

static libbgp_prefix6_t p6(const uint8_t addr[16], uint8_t len)
{
    libbgp_prefix6_t p;
    uint8_t mask[16];
    size_t i;

    memcpy(p.addr, addr, 16u);
    libbgp_cidr6_to_mask(len, mask);
    for (i = 0u; i < 16u; i++) {
        p.addr[i] &= mask[i];
    }
    p.len = len;
    return p;
}

static libbgp_rib4_route_t route4(libbgp_prefix4_t prefix)
{
    libbgp_rib4_route_t route;

    memset(&route, 0, sizeof(route));
    route.prefix = prefix;
    return route;
}

static libbgp_rib6_route_t route6(libbgp_prefix6_t prefix)
{
    libbgp_rib6_route_t route;

    memset(&route, 0, sizeof(route));
    route.prefix = prefix;
    return route;
}

static void free_attr_payload(libbgp_pattr_t *attr)
{
    size_t i;

    if (attr == NULL) {
        return;
    }
    if (attr->type == LIBBGP_PATTR_AS_PATH || attr->type == LIBBGP_PATTR_AS4_PATH) {
        for (i = 0u; i < attr->data.as_path.segment_count; i++) {
            free(attr->data.as_path.segments[i].asns);
        }
        free(attr->data.as_path.segments);
        attr->data.as_path.segments = NULL;
        attr->data.as_path.segment_count = 0u;
    } else if (attr->type == LIBBGP_PATTR_COMMUNITY) {
        free(attr->data.community.values);
        attr->data.community.values = NULL;
        attr->data.community.count = 0u;
    }
}

static libbgp_pattr_t *make_as_path(libbgp_pattr_type_t type, const uint32_t *asns, size_t count)
{
    libbgp_pattr_t *attr = libbgp_pattr_new(type);

    LIBBGP_ASSERT(attr != NULL);
    attr->data.as_path.segments = (libbgp_as_path_segment_t *)calloc(1u, sizeof(*attr->data.as_path.segments));
    LIBBGP_ASSERT(attr->data.as_path.segments != NULL);
    attr->data.as_path.segment_count = 1u;
    attr->data.as_path.segments[0].type = 2u;
    attr->data.as_path.segments[0].asn_count = count;
    attr->data.as_path.segments[0].asns = (uint32_t *)calloc(count, sizeof(*attr->data.as_path.segments[0].asns));
    LIBBGP_ASSERT(attr->data.as_path.segments[0].asns != NULL);
    memcpy(attr->data.as_path.segments[0].asns, asns, count * sizeof(*asns));
    return attr;
}

static libbgp_pattr_t *make_community(const uint32_t *values, size_t count)
{
    libbgp_pattr_t *attr = libbgp_pattr_new(LIBBGP_PATTR_COMMUNITY);

    LIBBGP_ASSERT(attr != NULL);
    attr->data.community.values = (uint32_t *)calloc(count, sizeof(*attr->data.community.values));
    LIBBGP_ASSERT(attr->data.community.values != NULL);
    attr->data.community.count = count;
    memcpy(attr->data.community.values, values, count * sizeof(*values));
    return attr;
}

LIBBGP_TEST(filter_rule_order_last_match_wins)
{
    libbgp_filter_t filter;
    libbgp_filter_rule_t deny;
    libbgp_filter_rule_t permit;
    libbgp_rib4_route_t route = route4(p4(10u, 1u, 2u, 0u, 24u));

    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_filter_init(&filter));
    memset(&deny, 0, sizeof(deny));
    deny.match_type = LIBBGP_FILTER_MATCH_ANY;
    deny.decision = LIBBGP_FILTER_DENY;
    memset(&permit, 0, sizeof(permit));
    permit.match_type = LIBBGP_FILTER_MATCH_ANY;
    permit.decision = LIBBGP_FILTER_PERMIT;
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_filter_add_rule(&filter, &deny));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_filter_add_rule(&filter, &permit));

    LIBBGP_ASSERT_EQ_I64(LIBBGP_FILTER_PERMIT,
        libbgp_filter_apply_route(&filter, &route, LIBBGP_FILTER_PERMIT));
    libbgp_filter_destroy(&filter);
}

LIBBGP_TEST(filter_prefix_rule_priority_preserves_last_match_wins)
{
    libbgp_filter_t filter;
    libbgp_filter_rule_t deny;
    libbgp_filter_rule_t permit;
    libbgp_prefix4_t prefix = p4(10u, 0u, 0u, 0u, 8u);
    libbgp_rib4_route_t route = route4(prefix);

    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_filter_init(&filter));
    memset(&deny, 0, sizeof(deny));
    deny.decision = LIBBGP_FILTER_DENY;
    deny.match_type = LIBBGP_FILTER_MATCH_PREFIX4;
    deny.match.prefix4 = prefix;
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_filter_add_rule(&filter, &deny));

    memset(&permit, 0, sizeof(permit));
    permit.decision = LIBBGP_FILTER_PERMIT;
    permit.match_type = LIBBGP_FILTER_MATCH_PREFIX4;
    permit.match.prefix4 = prefix;
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_filter_add_rule(&filter, &permit));

    LIBBGP_ASSERT_EQ_I64(LIBBGP_FILTER_PERMIT,
        libbgp_filter_apply_route(&filter, &route, LIBBGP_FILTER_DENY));
    libbgp_filter_destroy(&filter);
}

LIBBGP_TEST(filter_default_decision_for_no_match_and_null_inputs)
{
    libbgp_filter_t filter;
    libbgp_filter_rule_t rule;
    libbgp_rib4_route_t route = route4(p4(10u, 1u, 2u, 0u, 24u));

    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_filter_init(&filter));
    memset(&rule, 0, sizeof(rule));
    rule.match_type = LIBBGP_FILTER_MATCH_PREFIX4;
    rule.decision = LIBBGP_FILTER_DENY;
    rule.match.prefix4 = p4(192u, 0u, 2u, 0u, 24u);
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_filter_add_rule(&filter, &rule));

    LIBBGP_ASSERT_EQ_I64(LIBBGP_FILTER_PERMIT,
        libbgp_filter_apply_route(&filter, &route, LIBBGP_FILTER_PERMIT));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_FILTER_DENY,
        libbgp_filter_apply_route(NULL, &route, LIBBGP_FILTER_DENY));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_FILTER_PERMIT,
        libbgp_filter_apply_route(&filter, NULL, LIBBGP_FILTER_PERMIT));
    libbgp_filter_destroy(&filter);
}

LIBBGP_TEST(filter_prefix_rule_matches_included_route_prefix)
{
    libbgp_filter_t filter;
    libbgp_filter_rule_t rule;
    libbgp_rib4_route_t inside = route4(p4(203u, 0u, 113u, 128u, 25u));
    libbgp_rib4_route_t outside = route4(p4(203u, 0u, 114u, 0u, 24u));

    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_filter_init(&filter));
    memset(&rule, 0, sizeof(rule));
    rule.match_type = LIBBGP_FILTER_MATCH_PREFIX4;
    rule.decision = LIBBGP_FILTER_PERMIT;
    rule.match.prefix4 = p4(203u, 0u, 113u, 0u, 24u);
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_filter_add_rule(&filter, &rule));

    LIBBGP_ASSERT_EQ_I64(LIBBGP_FILTER_PERMIT,
        libbgp_filter_apply_route(&filter, &inside, LIBBGP_FILTER_DENY));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_FILTER_DENY,
        libbgp_filter_apply_route(&filter, &outside, LIBBGP_FILTER_DENY));
    libbgp_filter_destroy(&filter);
}

LIBBGP_TEST(filter_prefix_rule_supports_legacy_match_operators)
{
    libbgp_filter_t filter;
    libbgp_filter_rule_t rule;
    libbgp_rib4_route_t exact = route4(p4(203u, 0u, 113u, 0u, 24u));
    libbgp_rib4_route_t more_specific = route4(p4(203u, 0u, 113u, 128u, 25u));
    libbgp_rib4_route_t less_specific = route4(p4(203u, 0u, 112u, 0u, 23u));

    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_filter_init(&filter));
    memset(&rule, 0, sizeof(rule));
    rule.decision = LIBBGP_FILTER_PERMIT;
    rule.match.prefix4 = p4(203u, 0u, 113u, 0u, 24u);

    rule.match_type = LIBBGP_FILTER_MATCH_PREFIX4_EXACT;
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_filter_add_rule(&filter, &rule));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_FILTER_PERMIT,
        libbgp_filter_apply_route(&filter, &exact, LIBBGP_FILTER_DENY));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_FILTER_DENY,
        libbgp_filter_apply_route(&filter, &more_specific, LIBBGP_FILTER_DENY));
    libbgp_filter_clear(&filter);

    rule.match_type = LIBBGP_FILTER_MATCH_PREFIX4_MORE_SPECIFIC;
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_filter_add_rule(&filter, &rule));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_FILTER_PERMIT,
        libbgp_filter_apply_route(&filter, &more_specific, LIBBGP_FILTER_DENY));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_FILTER_DENY,
        libbgp_filter_apply_route(&filter, &exact, LIBBGP_FILTER_DENY));
    libbgp_filter_clear(&filter);

    rule.match_type = LIBBGP_FILTER_MATCH_PREFIX4_LESS_SPECIFIC;
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_filter_add_rule(&filter, &rule));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_FILTER_PERMIT,
        libbgp_filter_apply_route(&filter, &less_specific, LIBBGP_FILTER_DENY));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_FILTER_DENY,
        libbgp_filter_apply_route(&filter, &exact, LIBBGP_FILTER_DENY));
    libbgp_filter_destroy(&filter);
}

LIBBGP_TEST(filter_prefix4_inclusive_match_operators_include_exact_boundary)
{
    libbgp_filter_t filter;
    libbgp_filter_rule_t rule;
    libbgp_rib4_route_t exact = route4(p4(203u, 0u, 113u, 0u, 24u));
    libbgp_rib4_route_t more_specific = route4(p4(203u, 0u, 113u, 128u, 25u));
    libbgp_rib4_route_t less_specific = route4(p4(203u, 0u, 112u, 0u, 23u));

    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_filter_init(&filter));
    memset(&rule, 0, sizeof(rule));
    rule.decision = LIBBGP_FILTER_PERMIT;
    rule.match.prefix4 = p4(203u, 0u, 113u, 0u, 24u);

    rule.match_type = LIBBGP_FILTER_MATCH_PREFIX4_MORE_OR_EQUAL;
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_filter_add_rule(&filter, &rule));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_FILTER_PERMIT,
        libbgp_filter_apply_route(&filter, &exact, LIBBGP_FILTER_DENY));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_FILTER_PERMIT,
        libbgp_filter_apply_route(&filter, &more_specific, LIBBGP_FILTER_DENY));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_FILTER_DENY,
        libbgp_filter_apply_route(&filter, &less_specific, LIBBGP_FILTER_DENY));
    libbgp_filter_clear(&filter);

    rule.match_type = LIBBGP_FILTER_MATCH_PREFIX4_LESS_OR_EQUAL;
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_filter_add_rule(&filter, &rule));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_FILTER_PERMIT,
        libbgp_filter_apply_route(&filter, &exact, LIBBGP_FILTER_DENY));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_FILTER_PERMIT,
        libbgp_filter_apply_route(&filter, &less_specific, LIBBGP_FILTER_DENY));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_FILTER_DENY,
        libbgp_filter_apply_route(&filter, &more_specific, LIBBGP_FILTER_DENY));
    libbgp_filter_destroy(&filter);
}

LIBBGP_TEST(filter_prefix6_rule_supports_legacy_match_operators)
{
    static const uint8_t rule_addr[16] = { 0x20u, 0x01u, 0x0du, 0xb8u, 0x20u };
    static const uint8_t exact_addr[16] = { 0x20u, 0x01u, 0x0du, 0xb8u, 0x20u };
    static const uint8_t more_addr[16] = { 0x20u, 0x01u, 0x0du, 0xb8u, 0x20u, 0x80u };
    static const uint8_t less_addr[16] = { 0x20u, 0x01u, 0x0du, 0xb8u };
    libbgp_filter_t filter;
    libbgp_filter_rule_t rule;
    libbgp_rib6_route_t exact = route6(p6(exact_addr, 40u));
    libbgp_rib6_route_t more_specific = route6(p6(more_addr, 48u));
    libbgp_rib6_route_t less_specific = route6(p6(less_addr, 32u));

    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_filter_init(&filter));
    memset(&rule, 0, sizeof(rule));
    rule.decision = LIBBGP_FILTER_PERMIT;
    rule.match.prefix6 = p6(rule_addr, 40u);

    rule.match_type = LIBBGP_FILTER_MATCH_PREFIX6_EXACT;
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_filter_add_rule(&filter, &rule));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_FILTER_PERMIT,
        libbgp_filter_apply_route6(&filter, &exact, LIBBGP_FILTER_DENY));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_FILTER_DENY,
        libbgp_filter_apply_route6(&filter, &more_specific, LIBBGP_FILTER_DENY));
    libbgp_filter_clear(&filter);

    rule.match_type = LIBBGP_FILTER_MATCH_PREFIX6_MORE_SPECIFIC;
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_filter_add_rule(&filter, &rule));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_FILTER_PERMIT,
        libbgp_filter_apply_route6(&filter, &more_specific, LIBBGP_FILTER_DENY));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_FILTER_DENY,
        libbgp_filter_apply_route6(&filter, &exact, LIBBGP_FILTER_DENY));
    libbgp_filter_clear(&filter);

    rule.match_type = LIBBGP_FILTER_MATCH_PREFIX6_LESS_SPECIFIC;
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_filter_add_rule(&filter, &rule));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_FILTER_PERMIT,
        libbgp_filter_apply_route6(&filter, &less_specific, LIBBGP_FILTER_DENY));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_FILTER_DENY,
        libbgp_filter_apply_route6(&filter, &exact, LIBBGP_FILTER_DENY));
    libbgp_filter_destroy(&filter);
}

LIBBGP_TEST(filter_prefix6_inclusive_match_operators_include_exact_boundary)
{
    static const uint8_t rule_addr[16] = { 0x20u, 0x01u, 0x0du, 0xb8u, 0x20u };
    static const uint8_t exact_addr[16] = { 0x20u, 0x01u, 0x0du, 0xb8u, 0x20u };
    static const uint8_t more_addr[16] = { 0x20u, 0x01u, 0x0du, 0xb8u, 0x20u, 0x80u };
    static const uint8_t less_addr[16] = { 0x20u, 0x01u, 0x0du, 0xb8u };
    libbgp_filter_t filter;
    libbgp_filter_rule_t rule;
    libbgp_rib6_route_t exact = route6(p6(exact_addr, 40u));
    libbgp_rib6_route_t more_specific = route6(p6(more_addr, 48u));
    libbgp_rib6_route_t less_specific = route6(p6(less_addr, 32u));

    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_filter_init(&filter));
    memset(&rule, 0, sizeof(rule));
    rule.decision = LIBBGP_FILTER_PERMIT;
    rule.match.prefix6 = p6(rule_addr, 40u);

    rule.match_type = LIBBGP_FILTER_MATCH_PREFIX6_MORE_OR_EQUAL;
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_filter_add_rule(&filter, &rule));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_FILTER_PERMIT,
        libbgp_filter_apply_route6(&filter, &exact, LIBBGP_FILTER_DENY));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_FILTER_PERMIT,
        libbgp_filter_apply_route6(&filter, &more_specific, LIBBGP_FILTER_DENY));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_FILTER_DENY,
        libbgp_filter_apply_route6(&filter, &less_specific, LIBBGP_FILTER_DENY));
    libbgp_filter_clear(&filter);

    rule.match_type = LIBBGP_FILTER_MATCH_PREFIX6_LESS_OR_EQUAL;
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_filter_add_rule(&filter, &rule));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_FILTER_PERMIT,
        libbgp_filter_apply_route6(&filter, &exact, LIBBGP_FILTER_DENY));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_FILTER_PERMIT,
        libbgp_filter_apply_route6(&filter, &less_specific, LIBBGP_FILTER_DENY));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_FILTER_DENY,
        libbgp_filter_apply_route6(&filter, &more_specific, LIBBGP_FILTER_DENY));
    libbgp_filter_destroy(&filter);
}

LIBBGP_TEST(filter_route6_supports_shared_path_attr_matchers)
{
    static const uint8_t prefix_addr[16] = { 0x20u, 0x01u, 0x0du, 0xb8u, 0x30u };
    libbgp_filter_t filter;
    libbgp_filter_rule_t rule;
    const uint32_t as_path_values[] = { 64512u, 64513u };
    libbgp_pattr_t *as_path = make_as_path(LIBBGP_PATTR_AS_PATH, as_path_values, LIBBGP_ARRAY_LEN(as_path_values));
    libbgp_pattr_t *attrs[] = { as_path };
    libbgp_rib6_route_t route = route6(p6(prefix_addr, 40u));

    route.attrs = attrs;
    route.attr_count = LIBBGP_ARRAY_LEN(attrs);
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_filter_init(&filter));
    memset(&rule, 0, sizeof(rule));
    rule.match_type = LIBBGP_FILTER_MATCH_AS_PATH_ORIGIN;
    rule.decision = LIBBGP_FILTER_PERMIT;
    rule.match.asn = 64513u;
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_filter_add_rule(&filter, &rule));

    LIBBGP_ASSERT_EQ_I64(LIBBGP_FILTER_PERMIT,
        libbgp_filter_apply_route6(&filter, &route, LIBBGP_FILTER_DENY));

    libbgp_filter_destroy(&filter);
    free_attr_payload(as_path);
    libbgp_pattr_unref(as_path);
}

LIBBGP_TEST(filter_as_path_and_as4_path_contains_asn)
{
    libbgp_filter_t filter;
    libbgp_filter_rule_t rule;
    const uint32_t as_path_values[] = { 64512u, 64513u };
    const uint32_t as4_path_values[] = { 4200000001u, 4200000002u };
    libbgp_pattr_t *as_path = make_as_path(LIBBGP_PATTR_AS_PATH, as_path_values, LIBBGP_ARRAY_LEN(as_path_values));
    libbgp_pattr_t *as4_path = make_as_path(LIBBGP_PATTR_AS4_PATH, as4_path_values, LIBBGP_ARRAY_LEN(as4_path_values));
    libbgp_pattr_t *attrs[] = { as_path, as4_path };
    libbgp_rib4_route_t route = route4(p4(198u, 51u, 100u, 0u, 24u));

    route.attrs = attrs;
    route.attr_count = LIBBGP_ARRAY_LEN(attrs);
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_filter_init(&filter));
    memset(&rule, 0, sizeof(rule));
    rule.match_type = LIBBGP_FILTER_MATCH_AS_PATH_CONTAINS;
    rule.decision = LIBBGP_FILTER_PERMIT;
    rule.match.asn = 4200000002u;
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_filter_add_rule(&filter, &rule));

    LIBBGP_ASSERT_EQ_I64(LIBBGP_FILTER_PERMIT,
        libbgp_filter_apply_route(&filter, &route, LIBBGP_FILTER_DENY));
    libbgp_filter_clear(&filter);
    rule.match.asn = 64514u;
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_filter_add_rule(&filter, &rule));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_FILTER_DENY,
        libbgp_filter_apply_route(&filter, &route, LIBBGP_FILTER_DENY));

    libbgp_filter_destroy(&filter);
    free_attr_payload(as_path);
    free_attr_payload(as4_path);
    libbgp_pattr_unref(as_path);
    libbgp_pattr_unref(as4_path);
}

LIBBGP_TEST(filter_as_path_origin_and_negative_matches)
{
    libbgp_filter_t filter;
    libbgp_filter_rule_t rule;
    const uint32_t as_path_values[] = { 64512u, 64513u };
    libbgp_pattr_t *as_path = make_as_path(LIBBGP_PATTR_AS_PATH, as_path_values, LIBBGP_ARRAY_LEN(as_path_values));
    libbgp_pattr_t *attrs[] = { as_path };
    libbgp_rib4_route_t route = route4(p4(198u, 51u, 100u, 0u, 24u));

    route.attrs = attrs;
    route.attr_count = LIBBGP_ARRAY_LEN(attrs);
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_filter_init(&filter));
    memset(&rule, 0, sizeof(rule));
    rule.decision = LIBBGP_FILTER_PERMIT;

    rule.match_type = LIBBGP_FILTER_MATCH_AS_PATH_ORIGIN;
    rule.match.asn = 64513u;
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_filter_add_rule(&filter, &rule));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_FILTER_PERMIT,
        libbgp_filter_apply_route(&filter, &route, LIBBGP_FILTER_DENY));
    libbgp_filter_clear(&filter);

    rule.match_type = LIBBGP_FILTER_MATCH_AS_PATH_NOT_CONTAINS;
    rule.match.asn = 64599u;
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_filter_add_rule(&filter, &rule));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_FILTER_PERMIT,
        libbgp_filter_apply_route(&filter, &route, LIBBGP_FILTER_DENY));
    libbgp_filter_clear(&filter);

    rule.match_type = LIBBGP_FILTER_MATCH_AS_PATH_NOT_ORIGIN;
    rule.match.asn = 64512u;
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_filter_add_rule(&filter, &rule));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_FILTER_PERMIT,
        libbgp_filter_apply_route(&filter, &route, LIBBGP_FILTER_DENY));

    libbgp_filter_destroy(&filter);
    free_attr_payload(as_path);
    libbgp_pattr_unref(as_path);
}

LIBBGP_TEST(filter_community_contains_exact_value)
{
    libbgp_filter_t filter;
    libbgp_filter_rule_t rule;
    const uint32_t communities[] = { 0x000a0001u, 0x000a0002u };
    libbgp_pattr_t *community = make_community(communities, LIBBGP_ARRAY_LEN(communities));
    libbgp_pattr_t *attrs[] = { community };
    libbgp_rib4_route_t route = route4(p4(192u, 0u, 2u, 0u, 24u));

    route.attrs = attrs;
    route.attr_count = LIBBGP_ARRAY_LEN(attrs);
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_filter_init(&filter));
    memset(&rule, 0, sizeof(rule));
    rule.match_type = LIBBGP_FILTER_MATCH_COMMUNITY_CONTAINS;
    rule.decision = LIBBGP_FILTER_DENY;
    rule.match.community = 0x000a0002u;
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_filter_add_rule(&filter, &rule));

    LIBBGP_ASSERT_EQ_I64(LIBBGP_FILTER_DENY,
        libbgp_filter_apply_route(&filter, &route, LIBBGP_FILTER_PERMIT));
    libbgp_filter_clear(&filter);
    rule.match.community = 0x000a0003u;
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_filter_add_rule(&filter, &rule));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_FILTER_PERMIT,
        libbgp_filter_apply_route(&filter, &route, LIBBGP_FILTER_PERMIT));

    libbgp_filter_destroy(&filter);
    free_attr_payload(community);
    libbgp_pattr_unref(community);
}

LIBBGP_TEST(filter_community_negative_match)
{
    libbgp_filter_t filter;
    libbgp_filter_rule_t rule;
    const uint32_t communities[] = { 0x000a0001u };
    libbgp_pattr_t *community = make_community(communities, LIBBGP_ARRAY_LEN(communities));
    libbgp_pattr_t *attrs[] = { community };
    libbgp_rib4_route_t route = route4(p4(192u, 0u, 2u, 0u, 24u));

    route.attrs = attrs;
    route.attr_count = LIBBGP_ARRAY_LEN(attrs);
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_filter_init(&filter));
    memset(&rule, 0, sizeof(rule));
    rule.match_type = LIBBGP_FILTER_MATCH_COMMUNITY_NOT_CONTAINS;
    rule.decision = LIBBGP_FILTER_PERMIT;
    rule.match.community = 0x000a0002u;
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_filter_add_rule(&filter, &rule));

    LIBBGP_ASSERT_EQ_I64(LIBBGP_FILTER_PERMIT,
        libbgp_filter_apply_route(&filter, &route, LIBBGP_FILTER_DENY));

    libbgp_filter_destroy(&filter);
    free_attr_payload(community);
    libbgp_pattr_unref(community);
}

LIBBGP_TEST(filter_duplicate_community_attrs_preserve_linear_scan_semantics)
{
    libbgp_filter_t filter;
    libbgp_filter_rule_t rule;
    const uint32_t first_values[] = { 0x000a0001u };
    const uint32_t second_values[] = { 0x000a0002u };
    libbgp_pattr_t *first = make_community(first_values, LIBBGP_ARRAY_LEN(first_values));
    libbgp_pattr_t *second = make_community(second_values, LIBBGP_ARRAY_LEN(second_values));
    libbgp_pattr_t *attrs[] = { first, second };
    libbgp_rib4_route_t route = route4(p4(192u, 0u, 2u, 0u, 24u));

    route.attrs = attrs;
    route.attr_count = LIBBGP_ARRAY_LEN(attrs);
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_filter_init(&filter));
    memset(&rule, 0, sizeof(rule));
    rule.decision = LIBBGP_FILTER_PERMIT;
    rule.match.community = 0x000a0002u;

    rule.match_type = LIBBGP_FILTER_MATCH_COMMUNITY_CONTAINS;
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_filter_add_rule(&filter, &rule));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_FILTER_PERMIT,
        libbgp_filter_apply_route(&filter, &route, LIBBGP_FILTER_DENY));
    libbgp_filter_clear(&filter);

    rule.match_type = LIBBGP_FILTER_MATCH_COMMUNITY_NOT_CONTAINS;
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_filter_add_rule(&filter, &rule));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_FILTER_DENY,
        libbgp_filter_apply_route(&filter, &route, LIBBGP_FILTER_DENY));

    libbgp_filter_destroy(&filter);
    free_attr_payload(first);
    free_attr_payload(second);
    libbgp_pattr_unref(first);
    libbgp_pattr_unref(second);
}

LIBBGP_TEST(filter_duplicate_as_path_attrs_preserve_linear_scan_semantics)
{
    libbgp_filter_t filter;
    libbgp_filter_rule_t rule;
    const uint32_t second_values[] = { 64512u, 64513u };
    libbgp_pattr_t *first = libbgp_pattr_new(LIBBGP_PATTR_AS_PATH);
    libbgp_pattr_t *second = make_as_path(LIBBGP_PATTR_AS_PATH, second_values, LIBBGP_ARRAY_LEN(second_values));
    libbgp_pattr_t *attrs[] = { first, second };
    libbgp_rib4_route_t route = route4(p4(198u, 51u, 100u, 0u, 24u));

    LIBBGP_ASSERT(first != NULL);
    first->data.as_path.segments =
        (libbgp_as_path_segment_t *)calloc(1u, sizeof(*first->data.as_path.segments));
    LIBBGP_ASSERT(first->data.as_path.segments != NULL);
    first->data.as_path.segment_count = 1u;
    first->data.as_path.segments[0].asn_count = 1u;
    first->data.as_path.segments[0].asns = NULL;
    route.attrs = attrs;
    route.attr_count = LIBBGP_ARRAY_LEN(attrs);

    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_filter_init(&filter));
    memset(&rule, 0, sizeof(rule));
    rule.decision = LIBBGP_FILTER_PERMIT;
    rule.match.asn = 64513u;

    rule.match_type = LIBBGP_FILTER_MATCH_AS_PATH_CONTAINS;
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_filter_add_rule(&filter, &rule));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_FILTER_PERMIT,
        libbgp_filter_apply_route(&filter, &route, LIBBGP_FILTER_DENY));
    libbgp_filter_clear(&filter);

    rule.match_type = LIBBGP_FILTER_MATCH_AS_PATH_NOT_CONTAINS;
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_filter_add_rule(&filter, &rule));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_FILTER_DENY,
        libbgp_filter_apply_route(&filter, &route, LIBBGP_FILTER_DENY));

    libbgp_filter_destroy(&filter);
    free_attr_payload(first);
    free_attr_payload(second);
    libbgp_pattr_unref(first);
    libbgp_pattr_unref(second);
}

LIBBGP_TEST(filter_as4_path_before_as_path_preserves_origin_order)
{
    libbgp_filter_t filter;
    libbgp_filter_rule_t rule;
    const uint32_t as4_values[] = { 4200000001u, 4200000002u };
    const uint32_t as_path_values[] = { 64512u, 64513u };
    libbgp_pattr_t *as4_path = make_as_path(LIBBGP_PATTR_AS4_PATH, as4_values, LIBBGP_ARRAY_LEN(as4_values));
    libbgp_pattr_t *as_path = make_as_path(LIBBGP_PATTR_AS_PATH, as_path_values, LIBBGP_ARRAY_LEN(as_path_values));
    libbgp_pattr_t *attrs[] = { as4_path, as_path };
    libbgp_rib4_route_t route = route4(p4(198u, 51u, 100u, 0u, 24u));

    route.attrs = attrs;
    route.attr_count = LIBBGP_ARRAY_LEN(attrs);
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_filter_init(&filter));
    memset(&rule, 0, sizeof(rule));
    rule.match_type = LIBBGP_FILTER_MATCH_AS_PATH_ORIGIN;
    rule.decision = LIBBGP_FILTER_PERMIT;

    rule.match.asn = 4200000002u;
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_filter_add_rule(&filter, &rule));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_FILTER_PERMIT,
        libbgp_filter_apply_route(&filter, &route, LIBBGP_FILTER_DENY));
    libbgp_filter_clear(&filter);

    rule.match.asn = 64513u;
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_filter_add_rule(&filter, &rule));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_FILTER_DENY,
        libbgp_filter_apply_route(&filter, &route, LIBBGP_FILTER_DENY));

    libbgp_filter_destroy(&filter);
    free_attr_payload(as4_path);
    free_attr_payload(as_path);
    libbgp_pattr_unref(as4_path);
    libbgp_pattr_unref(as_path);
}

LIBBGP_TEST(filter_stale_community_type_code_preserves_public_type_semantics)
{
    libbgp_filter_t filter;
    libbgp_filter_rule_t rule;
    const uint32_t communities[] = { 0x000a0002u };
    libbgp_pattr_t *community = make_community(communities, LIBBGP_ARRAY_LEN(communities));
    libbgp_pattr_t *attrs[] = { community };
    libbgp_rib4_route_t route = route4(p4(192u, 0u, 2u, 0u, 24u));

    community->type_code = 0u;
    route.attrs = attrs;
    route.attr_count = LIBBGP_ARRAY_LEN(attrs);
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_filter_init(&filter));
    memset(&rule, 0, sizeof(rule));
    rule.decision = LIBBGP_FILTER_PERMIT;
    rule.match.community = 0x000a0002u;

    rule.match_type = LIBBGP_FILTER_MATCH_COMMUNITY_CONTAINS;
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_filter_add_rule(&filter, &rule));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_FILTER_PERMIT,
        libbgp_filter_apply_route(&filter, &route, LIBBGP_FILTER_DENY));
    libbgp_filter_clear(&filter);

    rule.match_type = LIBBGP_FILTER_MATCH_COMMUNITY_NOT_CONTAINS;
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_filter_add_rule(&filter, &rule));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_FILTER_DENY,
        libbgp_filter_apply_route(&filter, &route, LIBBGP_FILTER_DENY));

    libbgp_filter_destroy(&filter);
    free_attr_payload(community);
    libbgp_pattr_unref(community);
}

LIBBGP_TEST(filter_stale_as_path_type_code_preserves_public_type_semantics)
{
    libbgp_filter_t filter;
    libbgp_filter_rule_t rule;
    const uint32_t asns[] = { 64512u, 64513u };
    libbgp_pattr_t *as_path = make_as_path(LIBBGP_PATTR_AS_PATH, asns, LIBBGP_ARRAY_LEN(asns));
    libbgp_pattr_t *attrs[] = { as_path };
    libbgp_rib4_route_t route = route4(p4(198u, 51u, 100u, 0u, 24u));

    as_path->type_code = 0u;
    route.attrs = attrs;
    route.attr_count = LIBBGP_ARRAY_LEN(attrs);
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_filter_init(&filter));
    memset(&rule, 0, sizeof(rule));
    rule.decision = LIBBGP_FILTER_PERMIT;
    rule.match.asn = 64513u;

    rule.match_type = LIBBGP_FILTER_MATCH_AS_PATH_CONTAINS;
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_filter_add_rule(&filter, &rule));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_FILTER_PERMIT,
        libbgp_filter_apply_route(&filter, &route, LIBBGP_FILTER_DENY));
    libbgp_filter_clear(&filter);

    rule.match_type = LIBBGP_FILTER_MATCH_AS_PATH_ORIGIN;
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_filter_add_rule(&filter, &rule));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_FILTER_PERMIT,
        libbgp_filter_apply_route(&filter, &route, LIBBGP_FILTER_DENY));

    libbgp_filter_destroy(&filter);
    free_attr_payload(as_path);
    libbgp_pattr_unref(as_path);
}

LIBBGP_TEST(filter_route6_duplicate_community_attrs_preserve_linear_scan_semantics)
{
    static const uint8_t prefix_addr[16] = { 0x20u, 0x01u, 0x0du, 0xb8u, 0x60u };
    libbgp_filter_t filter;
    libbgp_filter_rule_t rule;
    const uint32_t first_values[] = { 0x000a0001u };
    const uint32_t second_values[] = { 0x000a0002u };
    libbgp_pattr_t *first = make_community(first_values, LIBBGP_ARRAY_LEN(first_values));
    libbgp_pattr_t *second = make_community(second_values, LIBBGP_ARRAY_LEN(second_values));
    libbgp_pattr_t *attrs[] = { first, second };
    libbgp_rib6_route_t route = route6(p6(prefix_addr, 40u));

    route.attrs = attrs;
    route.attr_count = LIBBGP_ARRAY_LEN(attrs);
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_filter_init(&filter));
    memset(&rule, 0, sizeof(rule));
    rule.match_type = LIBBGP_FILTER_MATCH_COMMUNITY_CONTAINS;
    rule.decision = LIBBGP_FILTER_PERMIT;
    rule.match.community = 0x000a0002u;
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_filter_add_rule(&filter, &rule));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_FILTER_PERMIT,
        libbgp_filter_apply_route6(&filter, &route, LIBBGP_FILTER_DENY));

    libbgp_filter_destroy(&filter);
    free_attr_payload(first);
    free_attr_payload(second);
    libbgp_pattr_unref(first);
    libbgp_pattr_unref(second);
}

LIBBGP_TEST(filter_malformed_public_attr_structs_fail_closed)
{
    libbgp_filter_t filter;
    libbgp_filter_rule_t rule;
    libbgp_rib4_route_t route = route4(p4(192u, 0u, 2u, 0u, 24u));
    libbgp_pattr_t *as_path = libbgp_pattr_new(LIBBGP_PATTR_AS_PATH);
    libbgp_pattr_t *community = libbgp_pattr_new(LIBBGP_PATTR_COMMUNITY);
    libbgp_pattr_t *attrs[1];

    LIBBGP_ASSERT(as_path != NULL);
    LIBBGP_ASSERT(community != NULL);
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_filter_init(&filter));

    memset(&rule, 0, sizeof(rule));
    rule.match_type = LIBBGP_FILTER_MATCH_AS_PATH_CONTAINS;
    rule.decision = LIBBGP_FILTER_PERMIT;
    rule.match.asn = 64512u;
    route.attr_count = 1u;
    route.attrs = NULL;
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_filter_add_rule(&filter, &rule));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_FILTER_DENY,
        libbgp_filter_apply_route(&filter, &route, LIBBGP_FILTER_DENY));

    as_path->data.as_path.segments =
        (libbgp_as_path_segment_t *)calloc(1u, sizeof(*as_path->data.as_path.segments));
    LIBBGP_ASSERT(as_path->data.as_path.segments != NULL);
    as_path->data.as_path.segment_count = 1u;
    as_path->data.as_path.segments[0].asn_count = 1u;
    as_path->data.as_path.segments[0].asns = NULL;
    attrs[0] = as_path;
    route.attrs = attrs;
    LIBBGP_ASSERT_EQ_I64(LIBBGP_FILTER_DENY,
        libbgp_filter_apply_route(&filter, &route, LIBBGP_FILTER_DENY));

    libbgp_filter_clear(&filter);
    memset(&rule, 0, sizeof(rule));
    rule.match_type = LIBBGP_FILTER_MATCH_COMMUNITY_CONTAINS;
    rule.decision = LIBBGP_FILTER_PERMIT;
    rule.match.community = 0x000a0001u;
    community->data.community.count = 1u;
    community->data.community.values = NULL;
    attrs[0] = community;
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_filter_add_rule(&filter, &rule));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_FILTER_DENY,
        libbgp_filter_apply_route(&filter, &route, LIBBGP_FILTER_DENY));

    libbgp_filter_destroy(&filter);
    free_attr_payload(as_path);
    libbgp_pattr_unref(as_path);
    libbgp_pattr_unref(community);
}

LIBBGP_TEST(filter_route6_default_decision_for_null_inputs)
{
    static const uint8_t prefix_addr[16] = { 0x20u, 0x01u, 0x0du, 0xb8u };
    libbgp_filter_t filter;
    libbgp_filter_rule_t rule;
    libbgp_rib6_route_t route = route6(p6(prefix_addr, 32u));

    libbgp_filter_destroy(NULL);
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_filter_init(&filter));
    memset(&rule, 0, sizeof(rule));
    rule.match_type = LIBBGP_FILTER_MATCH_ANY;
    rule.decision = LIBBGP_FILTER_DENY;
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_filter_add_rule(&filter, &rule));

    LIBBGP_ASSERT_EQ_I64(LIBBGP_FILTER_PERMIT,
        libbgp_filter_apply_route6(&filter, NULL, LIBBGP_FILTER_PERMIT));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_FILTER_DENY,
        libbgp_filter_apply_route6(NULL, &route, LIBBGP_FILTER_DENY));
    libbgp_filter_destroy(&filter);
}

LIBBGP_TEST(filter_invalid_match_types_fail_closed_for_route4_and_route6)
{
    static const uint8_t prefix6_addr[16] = { 0x20u, 0x01u, 0x0du, 0xb8u };
    libbgp_filter_t filter;
    libbgp_filter_rule_t rule;
    libbgp_rib4_route_t route = route4(p4(198u, 51u, 100u, 0u, 24u));
    libbgp_rib6_route_t route6_value = route6(p6(prefix6_addr, 32u));

    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_filter_init(&filter));
    memset(&rule, 0, sizeof(rule));
    rule.match_type = (libbgp_filter_match_type_t)999u;
    rule.decision = LIBBGP_FILTER_PERMIT;
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_filter_add_rule(&filter, &rule));

    LIBBGP_ASSERT_EQ_I64(LIBBGP_FILTER_DENY,
        libbgp_filter_apply_route(&filter, &route, LIBBGP_FILTER_DENY));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_FILTER_DENY,
        libbgp_filter_apply_route6(&filter, &route6_value, LIBBGP_FILTER_DENY));
    libbgp_filter_destroy(&filter);
}

LIBBGP_TEST(filter_route6_path_and_community_negative_matchers)
{
    static const uint8_t prefix_addr[16] = { 0x20u, 0x01u, 0x0du, 0xb8u, 0x40u };
    libbgp_filter_t filter;
    libbgp_filter_rule_t rule;
    const uint32_t as_path_values[] = { 64512u, 64513u };
    const uint32_t communities[] = { 0x000a0001u };
    libbgp_pattr_t *as_path = make_as_path(LIBBGP_PATTR_AS_PATH, as_path_values, LIBBGP_ARRAY_LEN(as_path_values));
    libbgp_pattr_t *community = make_community(communities, LIBBGP_ARRAY_LEN(communities));
    libbgp_pattr_t *attrs[] = { as_path, community };
    libbgp_rib6_route_t route = route6(p6(prefix_addr, 40u));

    route.attrs = attrs;
    route.attr_count = LIBBGP_ARRAY_LEN(attrs);
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_filter_init(&filter));
    memset(&rule, 0, sizeof(rule));
    rule.decision = LIBBGP_FILTER_PERMIT;

    rule.match_type = LIBBGP_FILTER_MATCH_AS_PATH_CONTAINS;
    rule.match.asn = 64513u;
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_filter_add_rule(&filter, &rule));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_FILTER_PERMIT,
        libbgp_filter_apply_route6(&filter, &route, LIBBGP_FILTER_DENY));
    libbgp_filter_clear(&filter);

    rule.match_type = LIBBGP_FILTER_MATCH_AS_PATH_NOT_CONTAINS;
    rule.match.asn = 64599u;
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_filter_add_rule(&filter, &rule));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_FILTER_PERMIT,
        libbgp_filter_apply_route6(&filter, &route, LIBBGP_FILTER_DENY));
    libbgp_filter_clear(&filter);

    rule.match_type = LIBBGP_FILTER_MATCH_AS_PATH_NOT_ORIGIN;
    rule.match.asn = 64512u;
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_filter_add_rule(&filter, &rule));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_FILTER_PERMIT,
        libbgp_filter_apply_route6(&filter, &route, LIBBGP_FILTER_DENY));
    libbgp_filter_clear(&filter);

    rule.match_type = LIBBGP_FILTER_MATCH_COMMUNITY_CONTAINS;
    rule.match.community = 0x000a0001u;
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_filter_add_rule(&filter, &rule));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_FILTER_PERMIT,
        libbgp_filter_apply_route6(&filter, &route, LIBBGP_FILTER_DENY));
    libbgp_filter_clear(&filter);

    rule.match_type = LIBBGP_FILTER_MATCH_COMMUNITY_NOT_CONTAINS;
    rule.match.community = 0x000a0002u;
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_filter_add_rule(&filter, &rule));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_FILTER_PERMIT,
        libbgp_filter_apply_route6(&filter, &route, LIBBGP_FILTER_DENY));

    libbgp_filter_destroy(&filter);
    free_attr_payload(as_path);
    free_attr_payload(community);
    libbgp_pattr_unref(as_path);
    libbgp_pattr_unref(community);
}

LIBBGP_TEST(filter_route6_malformed_public_attr_structs_fail_closed)
{
    static const uint8_t prefix_addr[16] = { 0x20u, 0x01u, 0x0du, 0xb8u, 0x50u };
    libbgp_filter_t filter;
    libbgp_filter_rule_t rule;
    libbgp_rib6_route_t route = route6(p6(prefix_addr, 40u));
    libbgp_pattr_t *as_path = libbgp_pattr_new(LIBBGP_PATTR_AS_PATH);
    libbgp_pattr_t *community = libbgp_pattr_new(LIBBGP_PATTR_COMMUNITY);
    libbgp_pattr_t *attrs[1];

    LIBBGP_ASSERT(as_path != NULL);
    LIBBGP_ASSERT(community != NULL);
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_filter_init(&filter));
    memset(&rule, 0, sizeof(rule));
    rule.decision = LIBBGP_FILTER_PERMIT;

    route.attr_count = 1u;
    route.attrs = NULL;
    rule.match_type = LIBBGP_FILTER_MATCH_AS_PATH_CONTAINS;
    rule.match.asn = 64512u;
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_filter_add_rule(&filter, &rule));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_FILTER_DENY,
        libbgp_filter_apply_route6(&filter, &route, LIBBGP_FILTER_DENY));
    libbgp_filter_clear(&filter);

    as_path->data.as_path.segments =
        (libbgp_as_path_segment_t *)calloc(1u, sizeof(*as_path->data.as_path.segments));
    LIBBGP_ASSERT(as_path->data.as_path.segments != NULL);
    as_path->data.as_path.segment_count = 1u;
    as_path->data.as_path.segments[0].asn_count = 1u;
    as_path->data.as_path.segments[0].asns = NULL;
    attrs[0] = as_path;
    route.attrs = attrs;
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_filter_add_rule(&filter, &rule));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_FILTER_DENY,
        libbgp_filter_apply_route6(&filter, &route, LIBBGP_FILTER_DENY));
    libbgp_filter_clear(&filter);

    community->data.community.count = 1u;
    community->data.community.values = NULL;
    attrs[0] = community;
    rule.match_type = LIBBGP_FILTER_MATCH_COMMUNITY_CONTAINS;
    rule.match.community = 0x000a0001u;
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_filter_add_rule(&filter, &rule));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_FILTER_DENY,
        libbgp_filter_apply_route6(&filter, &route, LIBBGP_FILTER_DENY));
    libbgp_filter_clear(&filter);

    rule.match_type = LIBBGP_FILTER_MATCH_AS_PATH_ORIGIN;
    rule.match.asn = 64512u;
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_filter_add_rule(&filter, &rule));
    attrs[0] = as_path;
    LIBBGP_ASSERT_EQ_I64(LIBBGP_FILTER_DENY,
        libbgp_filter_apply_route6(&filter, &route, LIBBGP_FILTER_DENY));

    libbgp_filter_destroy(&filter);
    free_attr_payload(as_path);
    libbgp_pattr_unref(as_path);
    libbgp_pattr_unref(community);
}

LIBBGP_TEST(filter_as_path_origin_requires_sequence_with_asns)
{
    libbgp_filter_t filter;
    libbgp_filter_rule_t rule;
    libbgp_pattr_t *as_path = libbgp_pattr_new(LIBBGP_PATTR_AS_PATH);
    libbgp_pattr_t *attrs[] = { as_path };
    libbgp_rib4_route_t route = route4(p4(198u, 51u, 100u, 0u, 24u));

    LIBBGP_ASSERT(as_path != NULL);
    as_path->data.as_path.segments =
        (libbgp_as_path_segment_t *)calloc(1u, sizeof(*as_path->data.as_path.segments));
    LIBBGP_ASSERT(as_path->data.as_path.segments != NULL);
    as_path->data.as_path.segment_count = 1u;
    as_path->data.as_path.segments[0].type = 1u;
    as_path->data.as_path.segments[0].asn_count = 1u;
    as_path->data.as_path.segments[0].asns = (uint32_t *)calloc(1u, sizeof(uint32_t));
    LIBBGP_ASSERT(as_path->data.as_path.segments[0].asns != NULL);
    as_path->data.as_path.segments[0].asns[0] = 64512u;
    route.attrs = attrs;
    route.attr_count = LIBBGP_ARRAY_LEN(attrs);

    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_filter_init(&filter));
    memset(&rule, 0, sizeof(rule));
    rule.match_type = LIBBGP_FILTER_MATCH_AS_PATH_ORIGIN;
    rule.decision = LIBBGP_FILTER_PERMIT;
    rule.match.asn = 64512u;
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_filter_add_rule(&filter, &rule));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_FILTER_DENY,
        libbgp_filter_apply_route(&filter, &route, LIBBGP_FILTER_DENY));

    libbgp_filter_destroy(&filter);
    free_attr_payload(as_path);
    libbgp_pattr_unref(as_path);
}

LIBBGP_TEST(filter_init_reports_calloc_failure)
{
    libbgp_filter_t filter;
    fail_calloc_ctx_t ctx = { 0u, 1u };
    libbgp_alloc_t alloc = {
        filter_fail_malloc,
        filter_fail_calloc,
        filter_fail_realloc,
        filter_fail_free,
        &ctx
    };
    libbgp_err_t err;

    filter.impl = (void *)1;
    libbgp_set_alloc(&alloc);
    err = libbgp_filter_init(&filter);
    libbgp_set_alloc(NULL);

    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_NOMEM, err);
    LIBBGP_ASSERT_EQ_U64(1u, ctx.calloc_calls);
    LIBBGP_ASSERT(filter.impl == NULL);
}

LIBBGP_TEST(filter_attr_helpers_ignore_null_and_wrong_attr_types)
{
    libbgp_filter_t filter;
    libbgp_filter_rule_t rule;
    libbgp_rib4_route_t route = route4(p4(198u, 51u, 100u, 0u, 24u));
    libbgp_pattr_t *origin = libbgp_pattr_new(LIBBGP_PATTR_ORIGIN);
    libbgp_pattr_t *attrs[] = { NULL, origin };

    LIBBGP_ASSERT(origin != NULL);
    route.attrs = attrs;
    route.attr_count = LIBBGP_ARRAY_LEN(attrs);
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_filter_init(&filter));
    memset(&rule, 0, sizeof(rule));
    rule.decision = LIBBGP_FILTER_PERMIT;

    rule.match_type = LIBBGP_FILTER_MATCH_AS_PATH_CONTAINS;
    rule.match.asn = 64512u;
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_filter_add_rule(&filter, &rule));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_FILTER_DENY,
        libbgp_filter_apply_route(&filter, &route, LIBBGP_FILTER_DENY));
    libbgp_filter_clear(&filter);

    rule.match_type = LIBBGP_FILTER_MATCH_AS_PATH_NOT_CONTAINS;
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_filter_add_rule(&filter, &rule));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_FILTER_PERMIT,
        libbgp_filter_apply_route(&filter, &route, LIBBGP_FILTER_DENY));
    libbgp_filter_clear(&filter);

    rule.match_type = LIBBGP_FILTER_MATCH_AS_PATH_ORIGIN;
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_filter_add_rule(&filter, &rule));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_FILTER_DENY,
        libbgp_filter_apply_route(&filter, &route, LIBBGP_FILTER_DENY));
    libbgp_filter_clear(&filter);

    rule.match_type = LIBBGP_FILTER_MATCH_COMMUNITY_CONTAINS;
    rule.match.community = 0x000a0001u;
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_filter_add_rule(&filter, &rule));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_FILTER_DENY,
        libbgp_filter_apply_route(&filter, &route, LIBBGP_FILTER_DENY));

    libbgp_filter_destroy(&filter);
    libbgp_pattr_unref(origin);
}

LIBBGP_TEST(filter_as_path_origin_uses_last_sequence_segment)
{
    libbgp_filter_t filter;
    libbgp_filter_rule_t rule;
    libbgp_pattr_t *as_path = libbgp_pattr_new(LIBBGP_PATTR_AS_PATH);
    libbgp_pattr_t *attrs[] = { as_path };
    libbgp_rib4_route_t route = route4(p4(198u, 51u, 100u, 0u, 24u));
    uint32_t first_segment_asns[] = { 64512u };
    uint32_t last_segment_asns[] = { 64513u, 64514u };

    LIBBGP_ASSERT(as_path != NULL);
    as_path->data.as_path.segments =
        (libbgp_as_path_segment_t *)calloc(2u, sizeof(*as_path->data.as_path.segments));
    LIBBGP_ASSERT(as_path->data.as_path.segments != NULL);
    as_path->data.as_path.segment_count = 2u;
    as_path->data.as_path.segments[0].type = 2u;
    as_path->data.as_path.segments[0].asn_count = LIBBGP_ARRAY_LEN(first_segment_asns);
    as_path->data.as_path.segments[0].asns = first_segment_asns;
    as_path->data.as_path.segments[1].type = 2u;
    as_path->data.as_path.segments[1].asn_count = LIBBGP_ARRAY_LEN(last_segment_asns);
    as_path->data.as_path.segments[1].asns = last_segment_asns;
    route.attrs = attrs;
    route.attr_count = LIBBGP_ARRAY_LEN(attrs);

    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_filter_init(&filter));
    memset(&rule, 0, sizeof(rule));
    rule.match_type = LIBBGP_FILTER_MATCH_AS_PATH_ORIGIN;
    rule.decision = LIBBGP_FILTER_PERMIT;
    rule.match.asn = 64514u;
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_filter_add_rule(&filter, &rule));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_FILTER_PERMIT,
        libbgp_filter_apply_route(&filter, &route, LIBBGP_FILTER_DENY));

    libbgp_filter_destroy(&filter);
    as_path->data.as_path.segments[0].asns = NULL;
    as_path->data.as_path.segments[1].asns = NULL;
    free_attr_payload(as_path);
    libbgp_pattr_unref(as_path);
}

LIBBGP_TEST(filter_prefix_specificity_rejects_non_included_routes)
{
    static const uint8_t rule6_addr[16] = { 0x20u, 0x01u, 0x0du, 0xb8u, 0x20u };
    static const uint8_t outside_more6_addr[16] = { 0x20u, 0x01u, 0x0du, 0xb8u, 0x21u };
    static const uint8_t outside_less6_addr[16] = { 0x20u, 0x01u, 0x0du, 0xb9u };
    libbgp_filter_t filter;
    libbgp_filter_rule_t rule;
    libbgp_rib4_route_t outside_more4 = route4(p4(203u, 0u, 114u, 0u, 25u));
    libbgp_rib4_route_t outside_less4 = route4(p4(203u, 0u, 110u, 0u, 23u));
    libbgp_rib6_route_t outside_more6 = route6(p6(outside_more6_addr, 48u));
    libbgp_rib6_route_t outside_less6 = route6(p6(outside_less6_addr, 32u));

    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_filter_init(&filter));
    memset(&rule, 0, sizeof(rule));
    rule.decision = LIBBGP_FILTER_PERMIT;
    rule.match.prefix4 = p4(203u, 0u, 113u, 0u, 24u);

    rule.match_type = LIBBGP_FILTER_MATCH_PREFIX4_MORE_SPECIFIC;
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_filter_add_rule(&filter, &rule));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_FILTER_DENY,
        libbgp_filter_apply_route(&filter, &outside_more4, LIBBGP_FILTER_DENY));
    libbgp_filter_clear(&filter);

    rule.match_type = LIBBGP_FILTER_MATCH_PREFIX4_LESS_SPECIFIC;
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_filter_add_rule(&filter, &rule));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_FILTER_DENY,
        libbgp_filter_apply_route(&filter, &outside_less4, LIBBGP_FILTER_DENY));
    libbgp_filter_clear(&filter);

    rule.match.prefix6 = p6(rule6_addr, 40u);
    rule.match_type = LIBBGP_FILTER_MATCH_PREFIX6_MORE_SPECIFIC;
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_filter_add_rule(&filter, &rule));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_FILTER_DENY,
        libbgp_filter_apply_route6(&filter, &outside_more6, LIBBGP_FILTER_DENY));
    libbgp_filter_clear(&filter);

    rule.match_type = LIBBGP_FILTER_MATCH_PREFIX6_LESS_SPECIFIC;
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_filter_add_rule(&filter, &rule));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_FILTER_DENY,
        libbgp_filter_apply_route6(&filter, &outside_less6, LIBBGP_FILTER_DENY));
    libbgp_filter_destroy(&filter);
}

LIBBGP_TEST(filter_rule_order_still_last_match_after_capacity_growth)
{
    libbgp_filter_t filter;
    libbgp_filter_rule_t rule;
    libbgp_rib4_route_t route = route4(p4(203u, 0u, 113u, 0u, 24u));
    size_t i;

    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_filter_init(&filter));
    memset(&rule, 0, sizeof(rule));
    rule.match_type = LIBBGP_FILTER_MATCH_ANY;
    for (i = 0u; i < 5u; i++) {
        rule.decision = i == 4u ? LIBBGP_FILTER_PERMIT : LIBBGP_FILTER_DENY;
        LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_filter_add_rule(&filter, &rule));
    }

    LIBBGP_ASSERT_EQ_U64(5u, libbgp_filter_rule_count(&filter));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_FILTER_PERMIT,
        libbgp_filter_apply_route(&filter, &route, LIBBGP_FILTER_DENY));
    libbgp_filter_destroy(&filter);
}

LIBBGP_TEST(filter_clear_and_rule_count)
{
    libbgp_filter_t filter;
    libbgp_filter_rule_t rule;

    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_INVALID, libbgp_filter_init(NULL));
    LIBBGP_ASSERT_EQ_I64(0u, libbgp_filter_rule_count(NULL));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_filter_init(&filter));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_INVALID, libbgp_filter_add_rule(NULL, &rule));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_INVALID, libbgp_filter_add_rule(&filter, NULL));

    memset(&rule, 0, sizeof(rule));
    rule.match_type = LIBBGP_FILTER_MATCH_ANY;
    rule.decision = LIBBGP_FILTER_PERMIT;
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_filter_add_rule(&filter, &rule));
    LIBBGP_ASSERT_EQ_U64(1u, libbgp_filter_rule_count(&filter));
    libbgp_filter_clear(&filter);
    LIBBGP_ASSERT_EQ_U64(0u, libbgp_filter_rule_count(&filter));
    libbgp_filter_destroy(&filter);
}

LIBBGP_TEST(filter_operations_after_destroy_use_null_behavior)
{
    libbgp_filter_t filter;
    libbgp_filter_rule_t rule;
    libbgp_rib4_route_t route = route4(p4(203u, 0u, 113u, 0u, 24u));

    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_filter_init(&filter));
    memset(&rule, 0, sizeof(rule));
    rule.match_type = LIBBGP_FILTER_MATCH_ANY;
    rule.decision = LIBBGP_FILTER_PERMIT;
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_filter_add_rule(&filter, &rule));
    libbgp_filter_destroy(&filter);

    LIBBGP_ASSERT_EQ_U64(0u, libbgp_filter_rule_count(&filter));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_INVALID, libbgp_filter_add_rule(&filter, &rule));
    libbgp_filter_clear(&filter);
    LIBBGP_ASSERT_EQ_I64(LIBBGP_FILTER_DENY,
        libbgp_filter_apply_route(&filter, &route, LIBBGP_FILTER_DENY));
}

LIBBGP_TEST(filter_add_rule_reports_realloc_failure_and_preserves_rules)
{
    libbgp_filter_t filter;
    libbgp_filter_rule_t rule;
    libbgp_rib4_route_t route = route4(p4(203u, 0u, 113u, 0u, 24u));
    fail_realloc_ctx_t ctx = { 0u, 1u };
    libbgp_alloc_t alloc = {
        filter_fail_malloc,
        filter_fail_calloc,
        filter_fail_realloc,
        filter_fail_free,
        &ctx
    };
    libbgp_err_t err;

    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_filter_init(&filter));
    memset(&rule, 0, sizeof(rule));
    rule.match_type = LIBBGP_FILTER_MATCH_ANY;
    rule.decision = LIBBGP_FILTER_DENY;
    libbgp_set_alloc(&alloc);
    err = libbgp_filter_add_rule(&filter, &rule);
    libbgp_set_alloc(NULL);

    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_NOMEM, err);
    LIBBGP_ASSERT_EQ_U64(0u, libbgp_filter_rule_count(&filter));
    LIBBGP_ASSERT_EQ_U64(1u, ctx.realloc_calls);
    LIBBGP_ASSERT_EQ_I64(LIBBGP_FILTER_PERMIT,
        libbgp_filter_apply_route(&filter, &route, LIBBGP_FILTER_PERMIT));

    rule.decision = LIBBGP_FILTER_PERMIT;
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_filter_add_rule(&filter, &rule));
    LIBBGP_ASSERT_EQ_U64(1u, libbgp_filter_rule_count(&filter));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_FILTER_PERMIT,
        libbgp_filter_apply_route(&filter, &route, LIBBGP_FILTER_DENY));
    libbgp_filter_destroy(&filter);
}

LIBBGP_TEST(filter_route6_match_any_permits_non_null_route)
{
    static const uint8_t addr[16] = { 0x20u, 0x01u, 0x0du, 0xb8u };
    libbgp_filter_t filter;
    libbgp_filter_rule_t rule;
    libbgp_rib6_route_t rt = route6(p6(addr, 32u));

    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_filter_init(&filter));
    memset(&rule, 0, sizeof(rule));
    rule.match_type = LIBBGP_FILTER_MATCH_ANY;
    rule.decision = LIBBGP_FILTER_PERMIT;
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_filter_add_rule(&filter, &rule));

    LIBBGP_ASSERT_EQ_I64(LIBBGP_FILTER_PERMIT,
        libbgp_filter_apply_route6(&filter, &rt, LIBBGP_FILTER_DENY));
    libbgp_filter_destroy(&filter);
}

LIBBGP_TEST(filter_clear_keeps_capacity_for_reuse_without_allocator)
{
    libbgp_filter_t filter;
    libbgp_filter_rule_t rule;
    libbgp_rib4_route_t route = route4(p4(203u, 0u, 113u, 0u, 24u));
    fail_realloc_ctx_t ctx = { 0u, 1u };
    libbgp_alloc_t alloc = {
        filter_fail_malloc,
        filter_fail_calloc,
        filter_fail_realloc,
        filter_fail_free,
        &ctx
    };
    libbgp_err_t err;
    size_t i;

    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_filter_init(&filter));
    memset(&rule, 0, sizeof(rule));
    rule.match_type = LIBBGP_FILTER_MATCH_ANY;
    for (i = 0u; i < 4u; i++) {
        rule.decision = LIBBGP_FILTER_DENY;
        LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_filter_add_rule(&filter, &rule));
    }
    LIBBGP_ASSERT_EQ_U64(4u, libbgp_filter_rule_count(&filter));
    libbgp_filter_clear(&filter);
    LIBBGP_ASSERT_EQ_U64(0u, libbgp_filter_rule_count(&filter));

    rule.decision = LIBBGP_FILTER_PERMIT;
    libbgp_set_alloc(&alloc);
    err = libbgp_filter_add_rule(&filter, &rule);
    libbgp_set_alloc(NULL);

    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, err);
    LIBBGP_ASSERT_EQ_U64(0u, ctx.realloc_calls);
    LIBBGP_ASSERT_EQ_U64(1u, libbgp_filter_rule_count(&filter));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_FILTER_PERMIT,
        libbgp_filter_apply_route(&filter, &route, LIBBGP_FILTER_DENY));
    libbgp_filter_destroy(&filter);
}

LIBBGP_TEST(filter_as_path_not_origin_requires_origin_presence_rfc4271)
{
    libbgp_filter_t filter;
    libbgp_filter_rule_t rule;
    libbgp_rib4_route_t route = route4(p4(198u, 51u, 100u, 0u, 24u));
    libbgp_pattr_t *empty_path = libbgp_pattr_new(LIBBGP_PATTR_AS_PATH);
    libbgp_pattr_t *attrs[] = { empty_path };

    LIBBGP_ASSERT(empty_path != NULL);
    empty_path->data.as_path.segment_count = 0u;
    empty_path->data.as_path.segments = NULL;
    route.attrs = attrs;
    route.attr_count = LIBBGP_ARRAY_LEN(attrs);

    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_filter_init(&filter));
    memset(&rule, 0, sizeof(rule));
    rule.match_type = LIBBGP_FILTER_MATCH_AS_PATH_NOT_ORIGIN;
    rule.decision = LIBBGP_FILTER_PERMIT;
    rule.match.asn = 64512u;
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_filter_add_rule(&filter, &rule));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_FILTER_DENY,
        libbgp_filter_apply_route(&filter, &route, LIBBGP_FILTER_DENY));

    libbgp_filter_destroy(&filter);
    libbgp_pattr_unref(empty_path);
}

LIBBGP_TEST(filter_route6_as_path_not_origin_requires_origin_presence_rfc4271)
{
    static const uint8_t prefix_addr[16] = { 0x20u, 0x01u, 0x0du, 0xb8u, 0x70u };
    libbgp_filter_t filter;
    libbgp_filter_rule_t rule;
    libbgp_rib6_route_t route = route6(p6(prefix_addr, 40u));
    libbgp_pattr_t *empty_path = libbgp_pattr_new(LIBBGP_PATTR_AS_PATH);
    libbgp_pattr_t *attrs[] = { empty_path };

    LIBBGP_ASSERT(empty_path != NULL);
    empty_path->data.as_path.segment_count = 0u;
    empty_path->data.as_path.segments = NULL;
    route.attrs = attrs;
    route.attr_count = LIBBGP_ARRAY_LEN(attrs);

    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_filter_init(&filter));
    memset(&rule, 0, sizeof(rule));
    rule.match_type = LIBBGP_FILTER_MATCH_AS_PATH_NOT_ORIGIN;
    rule.decision = LIBBGP_FILTER_PERMIT;
    rule.match.asn = 64512u;
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_filter_add_rule(&filter, &rule));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_FILTER_DENY,
        libbgp_filter_apply_route6(&filter, &route, LIBBGP_FILTER_DENY));

    libbgp_filter_destroy(&filter);
    libbgp_pattr_unref(empty_path);
}

LIBBGP_TEST(filter_route6_as4_origin_matches_when_as_path_absent_rfc6793)
{
    static const uint8_t prefix_addr[16] = { 0x20u, 0x01u, 0x0du, 0xb8u, 0x71u };
    libbgp_filter_t filter;
    libbgp_filter_rule_t rule;
    const uint32_t as4_values[] = { 4200000001u, 4200000002u };
    libbgp_pattr_t *as4_path = make_as_path(LIBBGP_PATTR_AS4_PATH, as4_values, LIBBGP_ARRAY_LEN(as4_values));
    libbgp_pattr_t *attrs[] = { as4_path };
    libbgp_rib6_route_t route = route6(p6(prefix_addr, 40u));

    route.attrs = attrs;
    route.attr_count = LIBBGP_ARRAY_LEN(attrs);
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_filter_init(&filter));
    memset(&rule, 0, sizeof(rule));
    rule.match_type = LIBBGP_FILTER_MATCH_AS_PATH_ORIGIN;
    rule.decision = LIBBGP_FILTER_PERMIT;
    rule.match.asn = 4200000002u;
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_filter_add_rule(&filter, &rule));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_FILTER_PERMIT,
        libbgp_filter_apply_route6(&filter, &route, LIBBGP_FILTER_DENY));

    libbgp_filter_destroy(&filter);
    free_attr_payload(as4_path);
    libbgp_pattr_unref(as4_path);
}

LIBBGP_TEST(filter_route6_community_not_contains_denies_when_present_rfc1997)
{
    static const uint8_t prefix_addr[16] = { 0x20u, 0x01u, 0x0du, 0xb8u, 0x72u };
    libbgp_filter_t filter;
    libbgp_filter_rule_t rule;
    const uint32_t communities[] = { 0x000a0001u, 0x000a0002u };
    libbgp_pattr_t *community = make_community(communities, LIBBGP_ARRAY_LEN(communities));
    libbgp_pattr_t *attrs[] = { community };
    libbgp_rib6_route_t route = route6(p6(prefix_addr, 40u));

    route.attrs = attrs;
    route.attr_count = LIBBGP_ARRAY_LEN(attrs);
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_filter_init(&filter));
    memset(&rule, 0, sizeof(rule));
    rule.match_type = LIBBGP_FILTER_MATCH_COMMUNITY_NOT_CONTAINS;
    rule.decision = LIBBGP_FILTER_PERMIT;
    rule.match.community = 0x000a0002u;
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_filter_add_rule(&filter, &rule));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_FILTER_DENY,
        libbgp_filter_apply_route6(&filter, &route, LIBBGP_FILTER_DENY));

    libbgp_filter_destroy(&filter);
    free_attr_payload(community);
    libbgp_pattr_unref(community);
}

LIBBGP_TEST(filter_as_path_contains_fails_closed_on_missing_segments_rfc4271)
{
    libbgp_filter_t filter;
    libbgp_filter_rule_t rule;
    libbgp_rib4_route_t route = route4(p4(203u, 0u, 113u, 0u, 24u));
    libbgp_pattr_t *as_path = libbgp_pattr_new(LIBBGP_PATTR_AS_PATH);
    libbgp_pattr_t *attrs[] = { as_path };

    LIBBGP_ASSERT(as_path != NULL);
    as_path->data.as_path.segment_count = 1u;
    as_path->data.as_path.segments = NULL;
    route.attrs = attrs;
    route.attr_count = LIBBGP_ARRAY_LEN(attrs);

    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_filter_init(&filter));
    memset(&rule, 0, sizeof(rule));
    rule.match_type = LIBBGP_FILTER_MATCH_AS_PATH_CONTAINS;
    rule.decision = LIBBGP_FILTER_PERMIT;
    rule.match.asn = 64512u;
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_filter_add_rule(&filter, &rule));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_FILTER_DENY,
        libbgp_filter_apply_route(&filter, &route, LIBBGP_FILTER_DENY));

    libbgp_filter_destroy(&filter);
    as_path->data.as_path.segment_count = 0u;
    libbgp_pattr_unref(as_path);
}

LIBBGP_TEST(filter_as_path_origin_fails_closed_on_missing_segment_asns_rfc4271)
{
    libbgp_filter_t filter;
    libbgp_filter_rule_t rule;
    libbgp_rib4_route_t route = route4(p4(203u, 0u, 113u, 0u, 24u));
    libbgp_pattr_t *as_path = libbgp_pattr_new(LIBBGP_PATTR_AS_PATH);
    libbgp_pattr_t *attrs[] = { as_path };

    LIBBGP_ASSERT(as_path != NULL);
    as_path->data.as_path.segments = (libbgp_as_path_segment_t *)calloc(1u, sizeof(*as_path->data.as_path.segments));
    LIBBGP_ASSERT(as_path->data.as_path.segments != NULL);
    as_path->data.as_path.segment_count = 1u;
    as_path->data.as_path.segments[0].type = 2u;
    as_path->data.as_path.segments[0].asn_count = 1u;
    as_path->data.as_path.segments[0].asns = NULL;
    route.attrs = attrs;
    route.attr_count = LIBBGP_ARRAY_LEN(attrs);

    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_filter_init(&filter));
    memset(&rule, 0, sizeof(rule));
    rule.match_type = LIBBGP_FILTER_MATCH_AS_PATH_ORIGIN;
    rule.decision = LIBBGP_FILTER_PERMIT;
    rule.match.asn = 64512u;
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_filter_add_rule(&filter, &rule));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_FILTER_DENY,
        libbgp_filter_apply_route(&filter, &route, LIBBGP_FILTER_DENY));

    libbgp_filter_destroy(&filter);
    free_attr_payload(as_path);
    libbgp_pattr_unref(as_path);
}

LIBBGP_TEST(filter_duplicate_as_path_origin_ignores_as_set_tail_rfc4271)
{
    libbgp_filter_t filter;
    libbgp_filter_rule_t rule;
    libbgp_rib4_route_t route = route4(p4(203u, 0u, 113u, 0u, 24u));
    libbgp_pattr_t *path = libbgp_pattr_new(LIBBGP_PATTR_AS_PATH);
    libbgp_pattr_t *duplicate = libbgp_pattr_new(LIBBGP_PATTR_AS_PATH);
    libbgp_pattr_t *attrs[] = { path, duplicate };
    uint32_t path_asns[] = { 64512u, 64513u };
    uint32_t set_asns[] = { 64599u };

    LIBBGP_ASSERT(path != NULL);
    LIBBGP_ASSERT(duplicate != NULL);
    path->data.as_path.segments = (libbgp_as_path_segment_t *)calloc(2u, sizeof(*path->data.as_path.segments));
    LIBBGP_ASSERT(path->data.as_path.segments != NULL);
    path->data.as_path.segment_count = 2u;
    path->data.as_path.segments[0].type = 2u;
    path->data.as_path.segments[0].asn_count = LIBBGP_ARRAY_LEN(path_asns);
    path->data.as_path.segments[0].asns = path_asns;
    path->data.as_path.segments[1].type = 1u;
    path->data.as_path.segments[1].asn_count = LIBBGP_ARRAY_LEN(set_asns);
    path->data.as_path.segments[1].asns = set_asns;
    duplicate->data.as_path.segment_count = 0u;
    duplicate->data.as_path.segments = NULL;
    route.attrs = attrs;
    route.attr_count = LIBBGP_ARRAY_LEN(attrs);

    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_filter_init(&filter));
    memset(&rule, 0, sizeof(rule));
    rule.match_type = LIBBGP_FILTER_MATCH_AS_PATH_ORIGIN;
    rule.decision = LIBBGP_FILTER_PERMIT;
    rule.match.asn = 64513u;
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_filter_add_rule(&filter, &rule));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_FILTER_PERMIT,
        libbgp_filter_apply_route(&filter, &route, LIBBGP_FILTER_DENY));

    libbgp_filter_destroy(&filter);
    path->data.as_path.segments[0].asns = NULL;
    path->data.as_path.segments[1].asns = NULL;
    free_attr_payload(path);
    libbgp_pattr_unref(duplicate);
    libbgp_pattr_unref(path);
}

int main(void)
{
    const libbgp_test_case_t tests[] = {
        { "filter_rule_order_last_match_wins", filter_rule_order_last_match_wins },
        { "filter_prefix_rule_priority_preserves_last_match_wins", filter_prefix_rule_priority_preserves_last_match_wins },
        { "filter_default_decision_for_no_match_and_null_inputs", filter_default_decision_for_no_match_and_null_inputs },
        { "filter_prefix_rule_matches_included_route_prefix", filter_prefix_rule_matches_included_route_prefix },
        { "filter_prefix_rule_supports_legacy_match_operators", filter_prefix_rule_supports_legacy_match_operators },
        { "filter_prefix4_inclusive_match_operators_include_exact_boundary", filter_prefix4_inclusive_match_operators_include_exact_boundary },
        { "filter_prefix6_rule_supports_legacy_match_operators", filter_prefix6_rule_supports_legacy_match_operators },
        { "filter_prefix6_inclusive_match_operators_include_exact_boundary", filter_prefix6_inclusive_match_operators_include_exact_boundary },
        { "filter_route6_supports_shared_path_attr_matchers", filter_route6_supports_shared_path_attr_matchers },
        { "filter_as_path_and_as4_path_contains_asn", filter_as_path_and_as4_path_contains_asn },
        { "filter_as_path_origin_and_negative_matches", filter_as_path_origin_and_negative_matches },
        { "filter_community_contains_exact_value", filter_community_contains_exact_value },
        { "filter_community_negative_match", filter_community_negative_match },
        { "filter_duplicate_community_attrs_preserve_linear_scan_semantics", filter_duplicate_community_attrs_preserve_linear_scan_semantics },
        { "filter_duplicate_as_path_attrs_preserve_linear_scan_semantics", filter_duplicate_as_path_attrs_preserve_linear_scan_semantics },
        { "filter_as4_path_before_as_path_preserves_origin_order", filter_as4_path_before_as_path_preserves_origin_order },
        { "filter_stale_community_type_code_preserves_public_type_semantics", filter_stale_community_type_code_preserves_public_type_semantics },
        { "filter_stale_as_path_type_code_preserves_public_type_semantics", filter_stale_as_path_type_code_preserves_public_type_semantics },
        { "filter_route6_duplicate_community_attrs_preserve_linear_scan_semantics", filter_route6_duplicate_community_attrs_preserve_linear_scan_semantics },
        { "filter_malformed_public_attr_structs_fail_closed", filter_malformed_public_attr_structs_fail_closed },
        { "filter_route6_default_decision_for_null_inputs", filter_route6_default_decision_for_null_inputs },
        { "filter_invalid_match_types_fail_closed_for_route4_and_route6", filter_invalid_match_types_fail_closed_for_route4_and_route6 },
        { "filter_route6_path_and_community_negative_matchers", filter_route6_path_and_community_negative_matchers },
        { "filter_route6_malformed_public_attr_structs_fail_closed", filter_route6_malformed_public_attr_structs_fail_closed },
        { "filter_as_path_origin_requires_sequence_with_asns", filter_as_path_origin_requires_sequence_with_asns },
        { "filter_init_reports_calloc_failure", filter_init_reports_calloc_failure },
        { "filter_attr_helpers_ignore_null_and_wrong_attr_types", filter_attr_helpers_ignore_null_and_wrong_attr_types },
        { "filter_as_path_origin_uses_last_sequence_segment", filter_as_path_origin_uses_last_sequence_segment },
        { "filter_prefix_specificity_rejects_non_included_routes", filter_prefix_specificity_rejects_non_included_routes },
        { "filter_rule_order_still_last_match_after_capacity_growth", filter_rule_order_still_last_match_after_capacity_growth },
        { "filter_clear_and_rule_count", filter_clear_and_rule_count },
        { "filter_operations_after_destroy_use_null_behavior", filter_operations_after_destroy_use_null_behavior },
        { "filter_add_rule_reports_realloc_failure_and_preserves_rules", filter_add_rule_reports_realloc_failure_and_preserves_rules },
        { "filter_clear_keeps_capacity_for_reuse_without_allocator", filter_clear_keeps_capacity_for_reuse_without_allocator },
        { "filter_route6_match_any_permits_non_null_route", filter_route6_match_any_permits_non_null_route },
        { "filter_as_path_not_origin_requires_origin_presence_rfc4271", filter_as_path_not_origin_requires_origin_presence_rfc4271 },
        { "filter_route6_as_path_not_origin_requires_origin_presence_rfc4271", filter_route6_as_path_not_origin_requires_origin_presence_rfc4271 },
        { "filter_route6_as4_origin_matches_when_as_path_absent_rfc6793", filter_route6_as4_origin_matches_when_as_path_absent_rfc6793 },
        { "filter_route6_community_not_contains_denies_when_present_rfc1997", filter_route6_community_not_contains_denies_when_present_rfc1997 },
        { "filter_as_path_contains_fails_closed_on_missing_segments_rfc4271", filter_as_path_contains_fails_closed_on_missing_segments_rfc4271 },
        { "filter_as_path_origin_fails_closed_on_missing_segment_asns_rfc4271", filter_as_path_origin_fails_closed_on_missing_segment_asns_rfc4271 },
        { "filter_duplicate_as_path_origin_ignores_as_set_tail_rfc4271", filter_duplicate_as_path_origin_ignores_as_set_tail_rfc4271 }
    };

    return libbgp_run_tests("filter", tests, LIBBGP_ARRAY_LEN(tests));
}
