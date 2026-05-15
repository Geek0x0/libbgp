#include <libbgp/libbgp.h>

#include <stdint.h>
#include <stdio.h>
#include <string.h>

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
    libbgp_prefix4_t prefix;

    prefix.addr = ip4(a, b, c, d) & libbgp_cidr_to_mask(len);
    prefix.len = len;
    return prefix;
}

static void print_ip4(uint32_t value)
{
    uint8_t bytes[4];

    memcpy(bytes, &value, sizeof(bytes));
    printf("%u.%u.%u.%u",
        (unsigned int)bytes[0],
        (unsigned int)bytes[1],
        (unsigned int)bytes[2],
        (unsigned int)bytes[3]);
}

static void print_prefix4(const libbgp_prefix4_t *prefix)
{
    print_ip4(prefix->addr);
    printf("/%u", (unsigned int)prefix->len);
}

static const char *decision_name(libbgp_filter_decision_t decision)
{
    return decision == LIBBGP_FILTER_PERMIT ? "permit" : "deny";
}

static libbgp_rib4_route_t learned_route(libbgp_prefix4_t prefix)
{
    libbgp_rib4_route_t route;

    memset(&route, 0, sizeof(route));
    route.prefix = prefix;
    route.source_router_id = ip4(192u, 0u, 2u, 10u);
    route.next_hop = ip4(198u, 51u, 100u, 1u);
    route.local_pref = 200u;
    route.origin = 0u;
    route.origin_as = 64512u;
    route.as_path_len = 2u;
    return route;
}

int main(void)
{
    libbgp_rib4_t rib;
    libbgp_filter_t filter;
    libbgp_filter_rule_t deny_more_specific;
    const libbgp_rib4_route_t *found = NULL;
    libbgp_prefix4_t aggregate = p4(203u, 0u, 113u, 0u, 24u);
    libbgp_prefix4_t customer = p4(203u, 0u, 113u, 128u, 25u);
    libbgp_rib4_route_t learned = learned_route(customer);
    libbgp_err_t err;

    err = libbgp_rib4_init(&rib);
    if (err != LIBBGP_OK) {
        fprintf(stderr, "rib init failed: %s\n", libbgp_strerror(err));
        return 1;
    }
    err = libbgp_filter_init(&filter);
    if (err != LIBBGP_OK) {
        fprintf(stderr, "filter init failed: %s\n", libbgp_strerror(err));
        libbgp_rib4_destroy(&rib);
        return 1;
    }

    err = libbgp_rib4_insert_local(&rib, &aggregate, ip4(192u, 0u, 2u, 1u), 100);
    if (err == LIBBGP_OK) {
        err = libbgp_rib4_insert(&rib, &learned);
    }
    if (err != LIBBGP_OK) {
        fprintf(stderr, "rib insert failed: %s\n", libbgp_strerror(err));
        libbgp_filter_destroy(&filter);
        libbgp_rib4_destroy(&rib);
        return 1;
    }

    memset(&deny_more_specific, 0, sizeof(deny_more_specific));
    deny_more_specific.match_type = LIBBGP_FILTER_MATCH_PREFIX4_MORE_SPECIFIC;
    deny_more_specific.decision = LIBBGP_FILTER_DENY;
    deny_more_specific.match.prefix4 = aggregate;
    err = libbgp_filter_add_rule(&filter, &deny_more_specific);
    if (err != LIBBGP_OK) {
        fprintf(stderr, "filter rule failed: %s\n", libbgp_strerror(err));
        libbgp_filter_destroy(&filter);
        libbgp_rib4_destroy(&rib);
        return 1;
    }

    err = libbgp_rib4_lookup(&rib, ip4(203u, 0u, 113u, 200u), &found);
    if (err != LIBBGP_OK || found == NULL) {
        fprintf(stderr, "lookup failed: %s\n", libbgp_strerror(err));
        libbgp_filter_destroy(&filter);
        libbgp_rib4_destroy(&rib);
        return 1;
    }

    printf("best route for 203.0.113.200 is ");
    print_prefix4(&found->prefix);
    printf(" via ");
    print_ip4(found->next_hop);
    printf("\n");
    printf("filter decision: %s\n",
        decision_name(libbgp_filter_apply_route(&filter, found, LIBBGP_FILTER_PERMIT)));
    printf("rib route count: %zu\n", libbgp_rib4_route_count(&rib));

    libbgp_filter_destroy(&filter);
    libbgp_rib4_destroy(&rib);
    return 0;
}
