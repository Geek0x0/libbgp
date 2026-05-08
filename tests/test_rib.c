#include "test_main.h"

#include "libbgp/pattr.h"
#include "libbgp/rib4.h"
#include "libbgp/rib6.h"

#include <stdbool.h>
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

static libbgp_rib4_route_t route4(libbgp_prefix4_t prefix, uint32_t src)
{
    libbgp_rib4_route_t route;

    memset(&route, 0, sizeof(route));
    route.prefix = prefix;
    route.source_router_id = src;
    route.next_hop = ip4(192u, 0u, 2u, (uint8_t)src);
    route.local_pref = 100u;
    route.origin = 0u;
    return route;
}

static void assert_rib4_best_source(const libbgp_rib4_t *rib, uint32_t dest, uint32_t src)
{
    const libbgp_rib4_route_t *found = NULL;

    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_rib4_lookup(rib, dest, &found));
    LIBBGP_ASSERT(found != NULL);
    LIBBGP_ASSERT_EQ_U64(src, found->source_router_id);
}

LIBBGP_TEST(rib4_insert_local_and_lookup_longest_prefix)
{
    libbgp_rib4_t rib;
    libbgp_prefix4_t p8 = p4(10u, 0u, 0u, 0u, 8u);
    libbgp_prefix4_t p24 = p4(10u, 1u, 2u, 0u, 24u);
    const libbgp_rib4_route_t *found = NULL;

    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_rib4_init(&rib));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_rib4_insert_local(&rib, &p8, ip4(192u, 0u, 2u, 1u), 11));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_rib4_insert_local(&rib, &p24, ip4(192u, 0u, 2u, 2u), 22));
    LIBBGP_ASSERT_EQ_U64(2u, libbgp_rib4_route_count(&rib));

    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_rib4_lookup(&rib, ip4(10u, 1u, 2u, 99u), &found));
    LIBBGP_ASSERT(libbgp_prefix4_eq(&p24, &found->prefix));
    LIBBGP_ASSERT_EQ_U64(ip4(192u, 0u, 2u, 2u), found->next_hop);
    LIBBGP_ASSERT_EQ_I64(22, found->weight);
    LIBBGP_ASSERT_EQ_U64(100u, found->local_pref);
    LIBBGP_ASSERT(!found->is_ibgp);

    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_rib4_lookup(&rib, ip4(10u, 9u, 0u, 1u), &found));
    LIBBGP_ASSERT(libbgp_prefix4_eq(&p8, &found->prefix));

    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_NOT_FOUND, libbgp_rib4_lookup(&rib, ip4(11u, 0u, 0u, 1u), &found));
    libbgp_rib4_destroy(&rib);
}

LIBBGP_TEST(rib4_best_route_ordering_for_same_prefix)
{
    libbgp_rib4_t rib;
    libbgp_prefix4_t prefix = p4(203u, 0u, 113u, 0u, 24u);
    libbgp_rib4_route_t base = route4(prefix, 1u);
    libbgp_rib4_route_t challenger;
    uint32_t dest = ip4(203u, 0u, 113u, 44u);

    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_rib4_init(&rib));
    base.update_id = 10u;
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_rib4_insert(&rib, &base));

    challenger = route4(prefix, 2u);
    challenger.is_ibgp = true;
    challenger.weight = 1000;
    challenger.local_pref = 1000u;
    challenger.update_id = 20u;
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_rib4_insert(&rib, &challenger));
    assert_rib4_best_source(&rib, dest, 1u);

    challenger = route4(prefix, 3u);
    challenger.weight = 5;
    challenger.update_id = 30u;
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_rib4_insert(&rib, &challenger));
    assert_rib4_best_source(&rib, dest, 3u);

    challenger = route4(prefix, 4u);
    challenger.weight = 5;
    challenger.local_pref = 200u;
    challenger.as_path_len = 2u;
    challenger.update_id = 40u;
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_rib4_insert(&rib, &challenger));
    assert_rib4_best_source(&rib, dest, 4u);

    challenger = route4(prefix, 5u);
    challenger.weight = 5;
    challenger.local_pref = 200u;
    challenger.as_path_len = 1u;
    challenger.update_id = 50u;
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_rib4_insert(&rib, &challenger));
    assert_rib4_best_source(&rib, dest, 5u);

    challenger = route4(prefix, 6u);
    challenger.weight = 5;
    challenger.local_pref = 200u;
    challenger.as_path_len = 1u;
    challenger.origin = 1u;
    challenger.update_id = 60u;
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_rib4_insert(&rib, &challenger));
    assert_rib4_best_source(&rib, dest, 5u);

    challenger = route4(prefix, 7u);
    challenger.weight = 5;
    challenger.local_pref = 200u;
    challenger.as_path_len = 1u;
    challenger.med = 10u;
    challenger.origin_as = 65000u;
    challenger.update_id = 70u;
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_rib4_insert(&rib, &challenger));

    challenger = route4(prefix, 8u);
    challenger.weight = 5;
    challenger.local_pref = 200u;
    challenger.as_path_len = 1u;
    challenger.med = 5u;
    challenger.origin_as = 65000u;
    challenger.update_id = 80u;
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_rib4_insert(&rib, &challenger));
    assert_rib4_best_source(&rib, dest, 8u);

    challenger = route4(prefix, 9u);
    challenger.weight = 5;
    challenger.local_pref = 200u;
    challenger.as_path_len = 1u;
    challenger.med = 1000u;
    challenger.origin_as = 65001u;
    challenger.update_id = 90u;
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_rib4_insert(&rib, &challenger));
    assert_rib4_best_source(&rib, dest, 9u);

    challenger = route4(prefix, 10u);
    challenger.weight = 5;
    challenger.local_pref = 200u;
    challenger.as_path_len = 1u;
    challenger.med = 1000u;
    challenger.origin_as = 65001u;
    challenger.update_id = 90u;
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_rib4_insert(&rib, &challenger));
    assert_rib4_best_source(&rib, dest, 9u);

    libbgp_rib4_destroy(&rib);
}

LIBBGP_TEST(rib_best_route_compares_router_ids_as_network_order)
{
    libbgp_rib4_t rib4;
    libbgp_rib6_t rib6;
    libbgp_prefix4_t prefix4 = p4(203u, 0u, 113u, 0u, 24u);
    const uint8_t prefix6_addr[16] = { 0x20u, 0x01u, 0x0du, 0xb8u, 0u, 2u };
    const uint8_t dest6[16] = { 0x20u, 0x01u, 0x0du, 0xb8u, 0u, 2u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 1u };
    const uint8_t nh6[16] = { 0x20u, 0x01u, 0x0du, 0xb8u, 0xffu };
    libbgp_prefix6_t prefix6 = p6(prefix6_addr, 48u);
    libbgp_rib4_route_t route4_low = route4(prefix4, ip4(1u, 1u, 1u, 2u));
    libbgp_rib4_route_t route4_high = route4(prefix4, ip4(2u, 1u, 1u, 1u));
    libbgp_rib6_route_t route6_low;
    libbgp_rib6_route_t route6_high;
    const libbgp_rib4_route_t *found4 = NULL;
    const libbgp_rib6_route_t *found6 = NULL;

    route4_low.update_id = 100u;
    route4_high.update_id = 100u;

    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_rib4_init(&rib4));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_rib4_insert(&rib4, &route4_low));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_rib4_insert(&rib4, &route4_high));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_rib4_lookup(&rib4, ip4(203u, 0u, 113u, 9u), &found4));
    LIBBGP_ASSERT(found4 != NULL);
    LIBBGP_ASSERT_EQ_U64(ip4(1u, 1u, 1u, 2u), found4->source_router_id);
    libbgp_rib4_destroy(&rib4);

    memset(&route6_low, 0, sizeof(route6_low));
    route6_low.prefix = prefix6;
    route6_low.source_router_id = ip4(1u, 1u, 1u, 2u);
    memcpy(route6_low.next_hop, nh6, sizeof(route6_low.next_hop));
    route6_low.local_pref = 100u;
    route6_low.update_id = 100u;
    route6_high = route6_low;
    route6_high.source_router_id = ip4(2u, 1u, 1u, 1u);

    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_rib6_init(&rib6));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_rib6_insert(&rib6, &route6_low));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_rib6_insert(&rib6, &route6_high));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_rib6_lookup(&rib6, dest6, &found6));
    LIBBGP_ASSERT(found6 != NULL);
    LIBBGP_ASSERT_EQ_U64(ip4(1u, 1u, 1u, 2u), found6->source_router_id);
    libbgp_rib6_destroy(&rib6);
}

LIBBGP_TEST(rib4_replace_withdraw_discard_and_scoped_lookup)
{
    libbgp_rib4_t rib;
    libbgp_prefix4_t p16 = p4(172u, 16u, 0u, 0u, 16u);
    libbgp_prefix4_t p24 = p4(172u, 16u, 9u, 0u, 24u);
    libbgp_rib4_route_t route = route4(p16, 42u);
    const libbgp_rib4_route_t *found = NULL;

    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_rib4_init(&rib));
    route.weight = 10;
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_rib4_insert(&rib, &route));
    route.weight = 99;
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_rib4_insert(&rib, &route));
    LIBBGP_ASSERT_EQ_U64(1u, libbgp_rib4_route_count(&rib));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_rib4_lookup_scoped(&rib, 42u, ip4(172u, 16u, 1u, 1u), &found));
    LIBBGP_ASSERT_EQ_I64(99, found->weight);

    route = route4(p24, 43u);
    route.weight = 5;
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_rib4_insert(&rib, &route));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_rib4_lookup(&rib, ip4(172u, 16u, 9u, 8u), &found));
    LIBBGP_ASSERT_EQ_U64(43u, found->source_router_id);
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_rib4_lookup_scoped(&rib, 42u, ip4(172u, 16u, 9u, 8u), &found));
    LIBBGP_ASSERT(libbgp_prefix4_eq(&p16, &found->prefix));

    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_NOT_FOUND, libbgp_rib4_withdraw(&rib, 99u, &p24));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_rib4_withdraw(&rib, 43u, &p24));
    LIBBGP_ASSERT_EQ_U64(1u, libbgp_rib4_route_count(&rib));

    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_rib4_discard(&rib, 42u));
    LIBBGP_ASSERT_EQ_U64(0u, libbgp_rib4_route_count(&rib));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_rib4_discard(&rib, 42u));

    libbgp_rib4_destroy(&rib);
}

LIBBGP_TEST(rib4_lookup_returns_borrowed_pointer_replaced_by_mutation)
{
    libbgp_rib4_t rib;
    libbgp_prefix4_t prefix = p4(192u, 0u, 2u, 0u, 24u);
    libbgp_rib4_route_t route = route4(prefix, 55u);
    const libbgp_rib4_route_t *before = NULL;
    const libbgp_rib4_route_t *after = NULL;

    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_rib4_init(&rib));
    route.weight = 1;
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_rib4_insert(&rib, &route));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_rib4_lookup(&rib, ip4(192u, 0u, 2u, 9u), &before));
    LIBBGP_ASSERT(before != NULL);
    LIBBGP_ASSERT_EQ_I64(1, before->weight);

    route.weight = 2;
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_rib4_insert(&rib, &route));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_rib4_lookup(&rib, ip4(192u, 0u, 2u, 9u), &after));
    LIBBGP_ASSERT(after != NULL);
    LIBBGP_ASSERT(after != before);
    LIBBGP_ASSERT_EQ_I64(2, after->weight);

    libbgp_rib4_destroy(&rib);
}

LIBBGP_TEST(rib4_insert_refs_attrs_and_destroy_unrefs)
{
    libbgp_rib4_t rib;
    libbgp_prefix4_t prefix = p4(198u, 51u, 100u, 0u, 24u);
    libbgp_pattr_t *attr = libbgp_pattr_new(LIBBGP_PATTR_ORIGIN);
    libbgp_pattr_t *attrs[1];
    libbgp_rib4_route_t route = route4(prefix, 77u);

    LIBBGP_ASSERT(attr != NULL);
    attrs[0] = attr;
    route.attrs = attrs;
    route.attr_count = 1u;

    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_rib4_init(&rib));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_rib4_insert(&rib, &route));
    LIBBGP_ASSERT_EQ_U64(2u, attr->refcount);

    route.weight = 5;
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_rib4_insert(&rib, &route));
    LIBBGP_ASSERT_EQ_U64(2u, attr->refcount);

    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_rib4_withdraw(&rib, 77u, &prefix));
    LIBBGP_ASSERT_EQ_U64(1u, attr->refcount);
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_rib4_insert(&rib, &route));
    LIBBGP_ASSERT_EQ_U64(2u, attr->refcount);

    libbgp_rib4_destroy(&rib);
    LIBBGP_ASSERT_EQ_U64(1u, attr->refcount);
    libbgp_pattr_unref(attr);
}

LIBBGP_TEST(rib6_insert_lookup_withdraw_discard_and_scoped)
{
    libbgp_rib6_t rib;
    const uint8_t base_addr[16] = { 0x20u, 0x01u, 0x0du, 0xb8u };
    const uint8_t specific_addr[16] = { 0x20u, 0x01u, 0x0du, 0xb8u, 0u, 1u };
    const uint8_t dest[16] = { 0x20u, 0x01u, 0x0du, 0xb8u, 0u, 1u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 9u };
    const uint8_t next_hop[16] = { 0x20u, 0x01u, 0x0du, 0xb8u, 0xffu };
    libbgp_prefix6_t p32 = p6(base_addr, 32u);
    libbgp_prefix6_t p48 = p6(specific_addr, 48u);
    libbgp_rib6_route_t route;
    const libbgp_rib6_route_t *found = NULL;

    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_rib6_init(&rib));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_rib6_insert_local(&rib, &p32, next_hop, 1));

    memset(&route, 0, sizeof(route));
    route.prefix = p48;
    route.source_router_id = 12u;
    memcpy(route.next_hop, next_hop, 16u);
    route.local_pref = 100u;
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_rib6_insert(&rib, &route));
    LIBBGP_ASSERT_EQ_U64(2u, libbgp_rib6_route_count(&rib));

    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_rib6_lookup(&rib, dest, &found));
    LIBBGP_ASSERT(found != NULL);
    LIBBGP_ASSERT(libbgp_prefix6_eq(&p48, &found->prefix));
    LIBBGP_ASSERT_EQ_U64(12u, found->source_router_id);
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_rib6_lookup_scoped(&rib, 0u, dest, &found));
    LIBBGP_ASSERT(libbgp_prefix6_eq(&p32, &found->prefix));

    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_NOT_FOUND, libbgp_rib6_withdraw(&rib, 99u, &p48));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_rib6_withdraw(&rib, 12u, &p48));
    LIBBGP_ASSERT_EQ_U64(1u, libbgp_rib6_route_count(&rib));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_rib6_discard(&rib, 0u));
    LIBBGP_ASSERT_EQ_U64(0u, libbgp_rib6_route_count(&rib));

    libbgp_rib6_destroy(&rib);
}

int main(void)
{
    const libbgp_test_case_t tests[] = {
        { "rib4_insert_local_and_lookup_longest_prefix", rib4_insert_local_and_lookup_longest_prefix },
        { "rib4_best_route_ordering_for_same_prefix", rib4_best_route_ordering_for_same_prefix },
        { "rib_best_route_compares_router_ids_as_network_order", rib_best_route_compares_router_ids_as_network_order },
        { "rib4_replace_withdraw_discard_and_scoped_lookup", rib4_replace_withdraw_discard_and_scoped_lookup },
        { "rib4_lookup_returns_borrowed_pointer_replaced_by_mutation", rib4_lookup_returns_borrowed_pointer_replaced_by_mutation },
        { "rib4_insert_refs_attrs_and_destroy_unrefs", rib4_insert_refs_attrs_and_destroy_unrefs },
        { "rib6_insert_lookup_withdraw_discard_and_scoped", rib6_insert_lookup_withdraw_discard_and_scoped }
    };

    return libbgp_run_tests("rib", tests, LIBBGP_ARRAY_LEN(tests));
}
