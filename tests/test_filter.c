#include "test_main.h"

#include "libbgp/filter.h"

#include <stdint.h>

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

static libbgp_rib4_route_t route4(libbgp_prefix4_t prefix)
{
    libbgp_rib4_route_t route;

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

LIBBGP_TEST(filter_rule_order_first_match_wins)
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

    LIBBGP_ASSERT_EQ_I64(LIBBGP_FILTER_DENY,
        libbgp_filter_apply_route(&filter, &route, LIBBGP_FILTER_PERMIT));
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

int main(void)
{
    const libbgp_test_case_t tests[] = {
        { "filter_rule_order_first_match_wins", filter_rule_order_first_match_wins },
        { "filter_default_decision_for_no_match_and_null_inputs", filter_default_decision_for_no_match_and_null_inputs },
        { "filter_prefix_rule_matches_included_route_prefix", filter_prefix_rule_matches_included_route_prefix },
        { "filter_as_path_and_as4_path_contains_asn", filter_as_path_and_as4_path_contains_asn },
        { "filter_community_contains_exact_value", filter_community_contains_exact_value },
        { "filter_malformed_public_attr_structs_fail_closed", filter_malformed_public_attr_structs_fail_closed },
        { "filter_clear_and_rule_count", filter_clear_and_rule_count },
        { "filter_operations_after_destroy_use_null_behavior", filter_operations_after_destroy_use_null_behavior }
    };

    return libbgp_run_tests("filter", tests, LIBBGP_ARRAY_LEN(tests));
}
