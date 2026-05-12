#include "test_main.h"

#include "libbgp/pattr.h"
#include "libbgp/rib4.h"
#include "libbgp/rib6.h"
#include "../src/rib_internal.h"

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

static libbgp_rib6_route_t route6(
    libbgp_prefix6_t prefix,
    uint32_t src,
    const uint8_t next_hop[16])
{
    libbgp_rib6_route_t route;

    memset(&route, 0, sizeof(route));
    route.prefix = prefix;
    route.source_router_id = src;
    memcpy(route.next_hop, next_hop, sizeof(route.next_hop));
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

static void assert_rib6_best_source(const libbgp_rib6_t *rib, const uint8_t dest[16], uint32_t src)
{
    const libbgp_rib6_route_t *found = NULL;

    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_rib6_lookup(rib, dest, &found));
    LIBBGP_ASSERT(found != NULL);
    LIBBGP_ASSERT_EQ_U64(src, found->source_router_id);
}

typedef struct rib4_iter_count_ctx {
    size_t count;
    size_t limit;
    uint32_t sources[8];
} rib4_iter_count_ctx_t;

typedef struct rib6_iter_count_ctx {
    size_t count;
    size_t limit;
    uint32_t sources[8];
} rib6_iter_count_ctx_t;

static bool record_rib4_source(const libbgp_rib4_route_t *route, void *ctx)
{
    rib4_iter_count_ctx_t *record = (rib4_iter_count_ctx_t *)ctx;

    LIBBGP_ASSERT(route != NULL);
    LIBBGP_ASSERT(record->count < LIBBGP_ARRAY_LEN(record->sources));
    record->sources[record->count++] = route->source_router_id;
    return record->limit == 0u || record->count < record->limit;
}

static bool record_rib6_source(const libbgp_rib6_route_t *route, void *ctx)
{
    rib6_iter_count_ctx_t *record = (rib6_iter_count_ctx_t *)ctx;

    LIBBGP_ASSERT(route != NULL);
    LIBBGP_ASSERT(record->count < LIBBGP_ARRAY_LEN(record->sources));
    record->sources[record->count++] = route->source_router_id;
    return record->limit == 0u || record->count < record->limit;
}

static bool rib4_sources_contain(const rib4_iter_count_ctx_t *ctx, uint32_t source)
{
    size_t i;

    for (i = 0u; i < ctx->count; i++) {
        if (ctx->sources[i] == source) {
            return true;
        }
    }
    return false;
}

static bool rib6_sources_contain(const rib6_iter_count_ctx_t *ctx, uint32_t source)
{
    size_t i;

    for (i = 0u; i < ctx->count; i++) {
        if (ctx->sources[i] == source) {
            return true;
        }
    }
    return false;
}

static libbgp_pattr_t *test_as_path_attr(uint32_t first_asn, uint32_t origin_asn)
{
    libbgp_pattr_t *attr = libbgp_pattr_new(LIBBGP_PATTR_AS_PATH);
    libbgp_as_path_segment_t *segment;
    uint32_t *asns;

    LIBBGP_ASSERT(attr != NULL);
    segment = (libbgp_as_path_segment_t *)calloc(1u, sizeof(*segment));
    asns = (uint32_t *)calloc(2u, sizeof(*asns));
    LIBBGP_ASSERT(segment != NULL);
    LIBBGP_ASSERT(asns != NULL);
    asns[0] = first_asn;
    asns[1] = origin_asn;
    segment->type = 2u;
    segment->asn_count = 2u;
    segment->asns = asns;
    attr->data.as_path.segments = segment;
    attr->data.as_path.segment_count = 1u;
    attr->data.as_path.is_4b = true;
    return attr;
}

static libbgp_pattr_t *route4_find_attr(const libbgp_rib4_route_t *route, libbgp_pattr_type_t type)
{
    size_t i;

    if (route == NULL) {
        return NULL;
    }
    for (i = 0u; i < route->attr_count; i++) {
        if (route->attrs[i] != NULL && route->attrs[i]->type == type) {
            return route->attrs[i];
        }
    }
    return NULL;
}

static libbgp_pattr_t *route6_find_attr(const libbgp_rib6_route_t *route, libbgp_pattr_type_t type)
{
    size_t i;

    if (route == NULL) {
        return NULL;
    }
    for (i = 0u; i < route->attr_count; i++) {
        if (route->attrs[i] != NULL && route->attrs[i]->type == type) {
            return route->attrs[i];
        }
    }
    return NULL;
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

LIBBGP_TEST(rib4_insert_local_creates_legacy_path_attributes)
{
    libbgp_rib4_t rib;
    libbgp_prefix4_t prefix = p4(10u, 10u, 0u, 0u, 16u);
    const libbgp_rib4_route_t *found = NULL;
    libbgp_pattr_t *origin;
    libbgp_pattr_t *path;
    libbgp_pattr_t *next_hop;

    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_rib4_init(&rib));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK,
        libbgp_rib4_insert_local(&rib, &prefix, ip4(192u, 0u, 2u, 254u), 11));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_rib4_lookup(&rib, ip4(10u, 10u, 99u, 1u), &found));
    LIBBGP_ASSERT(found != NULL);

    origin = route4_find_attr(found, LIBBGP_PATTR_ORIGIN);
    path = route4_find_attr(found, LIBBGP_PATTR_AS_PATH);
    next_hop = route4_find_attr(found, LIBBGP_PATTR_NEXT_HOP);
    LIBBGP_ASSERT(origin != NULL);
    LIBBGP_ASSERT(path != NULL);
    LIBBGP_ASSERT(next_hop != NULL);
    LIBBGP_ASSERT_EQ_U64(0u, origin->data.origin.origin);
    LIBBGP_ASSERT_EQ_U64(0u, path->data.as_path.segment_count);
    LIBBGP_ASSERT(path->data.as_path.is_4b);
    LIBBGP_ASSERT_EQ_U64(ip4(192u, 0u, 2u, 254u), next_hop->data.next_hop.next_hop);
    libbgp_rib4_destroy(&rib);
}

LIBBGP_TEST(rib4_insert_local_rejects_duplicate_prefix)
{
    libbgp_rib4_t rib;
    libbgp_prefix4_t prefix = p4(10u, 2u, 0u, 0u, 16u);
    const libbgp_rib4_route_t *found = NULL;

    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_rib4_init(&rib));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK,
        libbgp_rib4_insert_local(&rib, &prefix, ip4(192u, 0u, 2u, 1u), 11));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_EXISTS,
        libbgp_rib4_insert_local(&rib, &prefix, ip4(192u, 0u, 2u, 2u), 22));
    LIBBGP_ASSERT_EQ_U64(1u, libbgp_rib4_route_count(&rib));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_rib4_lookup(&rib, ip4(10u, 2u, 9u, 1u), &found));
    LIBBGP_ASSERT(found != NULL);
    LIBBGP_ASSERT_EQ_U64(ip4(192u, 0u, 2u, 1u), found->next_hop);
    LIBBGP_ASSERT_EQ_I64(11, found->weight);
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
    challenger.local_pref = 300u;
    challenger.as_path_len = 1u;
    challenger.med = 10u;
    challenger.origin_as = 65000u;
    challenger.update_id = 49u;
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_rib4_insert(&rib, &challenger));

    challenger = route4(prefix, 8u);
    challenger.weight = 5;
    challenger.local_pref = 300u;
    challenger.as_path_len = 1u;
    challenger.med = 5u;
    challenger.origin_as = 65000u;
    challenger.update_id = 48u;
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_rib4_insert(&rib, &challenger));
    assert_rib4_best_source(&rib, dest, 8u);

    challenger = route4(prefix, 9u);
    challenger.weight = 5;
    challenger.local_pref = 400u;
    challenger.as_path_len = 1u;
    challenger.med = 1000u;
    challenger.origin_as = 65001u;
    challenger.update_id = 47u;
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_rib4_insert(&rib, &challenger));
    assert_rib4_best_source(&rib, dest, 9u);

    challenger = route4(prefix, 10u);
    challenger.weight = 5;
    challenger.local_pref = 400u;
    challenger.as_path_len = 1u;
    challenger.med = 1000u;
    challenger.origin_as = 65001u;
    challenger.update_id = 47u;
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_rib4_insert(&rib, &challenger));
    assert_rib4_best_source(&rib, dest, 9u);

    libbgp_rib4_destroy(&rib);
}

LIBBGP_TEST(rib4_best_route_prefers_lower_update_id)
{
    libbgp_rib4_t rib;
    libbgp_prefix4_t prefix = p4(198u, 51u, 100u, 0u, 24u);
    uint32_t older_src = ip4(192u, 0u, 2u, 250u);
    uint32_t newer_src = ip4(192u, 0u, 2u, 1u);
    libbgp_rib4_route_t older = route4(prefix, older_src);
    libbgp_rib4_route_t newer = route4(prefix, newer_src);

    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_rib4_init(&rib));
    older.update_id = 10u;
    newer.update_id = 20u;
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_rib4_insert(&rib, &older));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_rib4_insert(&rib, &newer));
    assert_rib4_best_source(&rib, ip4(198u, 51u, 100u, 99u), older_src);
    libbgp_rib4_destroy(&rib);
}

LIBBGP_TEST(rib4_best_route_prefers_lower_update_id_as_final_tie_break)
{
    libbgp_rib4_t rib;
    libbgp_prefix4_t prefix = p4(192u, 0u, 2u, 0u, 24u);
    libbgp_rib4_route_t older = route4(prefix, 1u);
    libbgp_rib4_route_t newer = route4(prefix, 2u);

    older.update_id = 10u;
    newer.update_id = 20u;

    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_rib4_init(&rib));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_rib4_insert(&rib, &older));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_rib4_insert(&rib, &newer));
    assert_rib4_best_source(&rib, ip4(192u, 0u, 2u, 99u), 1u);
    libbgp_rib4_destroy(&rib);
}

LIBBGP_TEST(rib4_foreach_best_route_visits_one_route_per_prefix)
{
    libbgp_rib4_t rib;
    libbgp_prefix4_t first = p4(10u, 0u, 0u, 0u, 24u);
    libbgp_prefix4_t second = p4(10u, 0u, 1u, 0u, 24u);
    libbgp_rib4_route_t first_best = route4(first, 1u);
    libbgp_rib4_route_t first_backup = route4(first, 2u);
    libbgp_rib4_route_t second_best = route4(second, 3u);
    rib4_iter_count_ctx_t ctx;

    memset(&ctx, 0, sizeof(ctx));
    first_best.is_ibgp = true;
    first_best.local_pref = 200u;
    first_backup.local_pref = 100u;

    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_rib4_init(&rib));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_rib4_insert(&rib, &first_best));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_rib4_insert(&rib, &first_backup));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_rib4_insert(&rib, &second_best));

    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, bgp_rib4_foreach_best_route(&rib, record_rib4_source, &ctx));
    LIBBGP_ASSERT_EQ_U64(2u, ctx.count);
    LIBBGP_ASSERT(rib4_sources_contain(&ctx, 1u));
    LIBBGP_ASSERT(rib4_sources_contain(&ctx, 3u));

    libbgp_rib4_destroy(&rib);
}

LIBBGP_TEST(rib4_foreach_best_route_stops_stored_route_iteration_early)
{
    libbgp_rib4_t rib;
    libbgp_prefix4_t first = p4(10u, 20u, 0u, 0u, 24u);
    libbgp_prefix4_t second = p4(10u, 20u, 1u, 0u, 24u);
    libbgp_rib4_route_t first_best = route4(first, 1u);
    libbgp_rib4_route_t first_backup = route4(first, 2u);
    libbgp_rib4_route_t second_best = route4(second, 3u);
    libbgp_rib4_route_t second_backup = route4(second, 4u);
    rib4_iter_count_ctx_t ctx;

    memset(&ctx, 0, sizeof(ctx));
    ctx.limit = 1u;
    first_best.local_pref = 200u;
    first_backup.local_pref = 100u;
    second_best.local_pref = 200u;
    second_backup.local_pref = 100u;

    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_rib4_init(&rib));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_rib4_insert(&rib, &first_best));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_rib4_insert(&rib, &first_backup));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_rib4_insert(&rib, &second_best));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_rib4_insert(&rib, &second_backup));

    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, bgp_rib4_foreach_best_route(&rib, record_rib4_source, &ctx));
    LIBBGP_ASSERT_EQ_U64(1u, ctx.count);
    LIBBGP_ASSERT(ctx.sources[0] == 1u || ctx.sources[0] == 3u);

    libbgp_rib4_destroy(&rib);
}

LIBBGP_TEST(rib4_med_comparison_uses_neighbor_as_from_as_path)
{
    libbgp_rib4_t rib;
    libbgp_prefix4_t prefix = p4(203u, 0u, 114u, 0u, 24u);
    libbgp_rib4_route_t high_med = route4(prefix, 1u);
    libbgp_rib4_route_t low_med = route4(prefix, 2u);
    libbgp_pattr_t *high_path = test_as_path_attr(65000u, 65100u);
    libbgp_pattr_t *low_path = test_as_path_attr(65000u, 65200u);
    libbgp_pattr_t *high_attrs[1];
    libbgp_pattr_t *low_attrs[1];

    high_attrs[0] = high_path;
    low_attrs[0] = low_path;
    high_med.attrs = high_attrs;
    high_med.attr_count = 1u;
    high_med.as_path_len = 2u;
    high_med.origin_as = 65100u;
    high_med.med = 100u;
    high_med.update_id = 10u;
    low_med.attrs = low_attrs;
    low_med.attr_count = 1u;
    low_med.as_path_len = 2u;
    low_med.origin_as = 65200u;
    low_med.med = 10u;
    low_med.update_id = 20u;

    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_rib4_init(&rib));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_rib4_insert(&rib, &high_med));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_rib4_insert(&rib, &low_med));
    assert_rib4_best_source(&rib, ip4(203u, 0u, 114u, 1u), 2u);

    libbgp_rib4_destroy(&rib);
    libbgp_pattr_unref(high_path);
    libbgp_pattr_unref(low_path);
}

LIBBGP_TEST(rib4_med_not_compared_without_neighbor_as)
{
    libbgp_rib4_t rib;
    libbgp_prefix4_t prefix = p4(203u, 0u, 115u, 0u, 24u);
    libbgp_rib4_route_t lower_med = route4(prefix, 1u);
    libbgp_rib4_route_t older = route4(prefix, 2u);

    lower_med.origin_as = 65000u;
    lower_med.med = 10u;
    lower_med.update_id = 20u;
    older.origin_as = 65000u;
    older.med = 100u;
    older.update_id = 10u;

    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_rib4_init(&rib));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_rib4_insert(&rib, &lower_med));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_rib4_insert(&rib, &older));
    assert_rib4_best_source(&rib, ip4(203u, 0u, 115u, 1u), 2u);

    libbgp_rib4_destroy(&rib);
}

LIBBGP_TEST(rib4_insert_reports_only_best_path_changes)
{
    libbgp_rib4_t rib;
    libbgp_prefix4_t prefix = p4(198u, 51u, 100u, 0u, 24u);
    libbgp_rib4_route_t best = route4(prefix, 1u);
    libbgp_rib4_route_t worse = route4(prefix, 2u);
    bgp_rib4_change_t change;
    uint64_t update_id = 0u;

    best.local_pref = 200u;
    worse.local_pref = 100u;

    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_rib4_init(&rib));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, bgp_rib4_insert_track_best(&rib, &best, &change, &update_id));
    LIBBGP_ASSERT_EQ_I64(BGP_RIB_CHANGE_NEW_BEST, change.kind);
    LIBBGP_ASSERT(change.best != NULL);
    LIBBGP_ASSERT_EQ_U64(1u, change.best->source_router_id);

    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, bgp_rib4_insert_track_best(&rib, &worse, &change, &update_id));
    LIBBGP_ASSERT_EQ_I64(BGP_RIB_CHANGE_NO_BEST_CHANGE, change.kind);
    LIBBGP_ASSERT(change.best != NULL);
    LIBBGP_ASSERT_EQ_U64(1u, change.best->source_router_id);

    libbgp_rib4_destroy(&rib);
}

LIBBGP_TEST(rib4_insert_reports_replacement_best_when_better_route_wins)
{
    libbgp_rib4_t rib;
    libbgp_prefix4_t prefix = p4(203u, 0u, 113u, 0u, 24u);
    libbgp_rib4_route_t initial = route4(prefix, 1u);
    libbgp_rib4_route_t better = route4(prefix, 2u);
    bgp_rib4_change_t change;
    uint64_t update_id = 0u;

    initial.local_pref = 100u;
    better.local_pref = 200u;

    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_rib4_init(&rib));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, bgp_rib4_insert_track_best(&rib, &initial, &change, &update_id));
    LIBBGP_ASSERT_EQ_I64(BGP_RIB_CHANGE_NEW_BEST, change.kind);

    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, bgp_rib4_insert_track_best(&rib, &better, &change, &update_id));
    LIBBGP_ASSERT_EQ_I64(BGP_RIB_CHANGE_REPLACEMENT_BEST, change.kind);
    LIBBGP_ASSERT(change.best != NULL);
    LIBBGP_ASSERT_EQ_U64(2u, change.best->source_router_id);

    libbgp_rib4_destroy(&rib);
}

LIBBGP_TEST(rib4_insert_reports_same_update_id_best_replacement)
{
    libbgp_rib4_t rib;
    libbgp_prefix4_t prefix = p4(203u, 0u, 113u, 0u, 24u);
    libbgp_rib4_route_t initial = route4(prefix, 1u);
    libbgp_rib4_route_t replacement = route4(prefix, 1u);
    bgp_rib4_change_t change;
    uint64_t update_id = 42u;

    initial.update_id = 42u;
    replacement.update_id = 42u;
    initial.local_pref = 100u;
    replacement.local_pref = 200u;

    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_rib4_init(&rib));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, bgp_rib4_insert_track_best(&rib, &initial, &change, &update_id));
    LIBBGP_ASSERT_EQ_I64(BGP_RIB_CHANGE_NEW_BEST, change.kind);

    update_id = 42u;
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, bgp_rib4_insert_track_best(&rib, &replacement, &change, &update_id));
    LIBBGP_ASSERT_EQ_I64(BGP_RIB_CHANGE_REPLACEMENT_BEST, change.kind);
    LIBBGP_ASSERT(change.best != NULL);
    LIBBGP_ASSERT_EQ_U64(1u, change.best->source_router_id);
    LIBBGP_ASSERT_EQ_U64(42u, change.best->update_id);
    LIBBGP_ASSERT_EQ_U64(200u, change.best->local_pref);

    libbgp_rib4_destroy(&rib);
}

LIBBGP_TEST(rib4_withdraw_reports_replacement_vs_unreachable)
{
    libbgp_rib4_t rib;
    libbgp_prefix4_t prefix = p4(203u, 0u, 113u, 0u, 24u);
    libbgp_rib4_route_t primary = route4(prefix, 1u);
    libbgp_rib4_route_t backup = route4(prefix, 2u);
    bgp_rib4_change_t change;
    uint64_t update_id = 0u;

    primary.local_pref = 200u;
    backup.local_pref = 100u;

    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_rib4_init(&rib));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, bgp_rib4_insert_track_best(&rib, &primary, &change, &update_id));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, bgp_rib4_insert_track_best(&rib, &backup, &change, &update_id));

    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, bgp_rib4_withdraw_track_best(&rib, 1u, &prefix, &change));
    LIBBGP_ASSERT_EQ_I64(BGP_RIB_CHANGE_REPLACEMENT_BEST, change.kind);
    LIBBGP_ASSERT(change.best != NULL);
    LIBBGP_ASSERT_EQ_U64(2u, change.best->source_router_id);

    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, bgp_rib4_withdraw_track_best(&rib, 2u, &prefix, &change));
    LIBBGP_ASSERT_EQ_I64(BGP_RIB_CHANGE_UNREACHABLE, change.kind);
    LIBBGP_ASSERT(change.best == NULL);

    libbgp_rib4_destroy(&rib);
}

LIBBGP_TEST(rib6_best_route_ordering_for_same_prefix)
{
    libbgp_rib6_t rib;
    const uint8_t prefix_addr[16] = { 0x20u, 0x01u, 0x0du, 0xb8u, 0u, 0x10u };
    const uint8_t dest[16] = { 0x20u, 0x01u, 0x0du, 0xb8u, 0u, 0x10u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 44u };
    const uint8_t next_hop[16] = { 0x20u, 0x01u, 0x0du, 0xb8u, 0xffu, 0x10u };
    libbgp_prefix6_t prefix = p6(prefix_addr, 48u);
    libbgp_rib6_route_t base = route6(prefix, 1u, next_hop);
    libbgp_rib6_route_t challenger;
    libbgp_pattr_t *path7 = test_as_path_attr(65000u, 65100u);
    libbgp_pattr_t *path8 = test_as_path_attr(65000u, 65200u);
    libbgp_pattr_t *attrs7[1];
    libbgp_pattr_t *attrs8[1];

    attrs7[0] = path7;
    attrs8[0] = path8;

    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_rib6_init(&rib));
    base.update_id = 10u;
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_rib6_insert(&rib, &base));

    challenger = route6(prefix, 2u, next_hop);
    challenger.is_ibgp = true;
    challenger.update_id = 5u;
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_rib6_insert(&rib, &challenger));
    assert_rib6_best_source(&rib, dest, 1u);

    challenger = route6(prefix, 3u, next_hop);
    challenger.weight = 5;
    challenger.update_id = 30u;
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_rib6_insert(&rib, &challenger));
    assert_rib6_best_source(&rib, dest, 3u);

    challenger = route6(prefix, 4u, next_hop);
    challenger.weight = 5;
    challenger.local_pref = 200u;
    challenger.as_path_len = 2u;
    challenger.update_id = 40u;
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_rib6_insert(&rib, &challenger));
    assert_rib6_best_source(&rib, dest, 4u);

    challenger = route6(prefix, 5u, next_hop);
    challenger.weight = 5;
    challenger.local_pref = 200u;
    challenger.as_path_len = 1u;
    challenger.update_id = 50u;
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_rib6_insert(&rib, &challenger));
    assert_rib6_best_source(&rib, dest, 5u);

    challenger = route6(prefix, 6u, next_hop);
    challenger.weight = 5;
    challenger.local_pref = 200u;
    challenger.as_path_len = 1u;
    challenger.origin = 1u;
    challenger.update_id = 40u;
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_rib6_insert(&rib, &challenger));
    assert_rib6_best_source(&rib, dest, 5u);

    challenger = route6(prefix, 7u, next_hop);
    challenger.weight = 5;
    challenger.local_pref = 300u;
    challenger.as_path_len = 1u;
    challenger.med = 10u;
    challenger.origin_as = 65000u;
    challenger.attrs = attrs7;
    challenger.attr_count = 1u;
    challenger.update_id = 40u;
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_rib6_insert(&rib, &challenger));

    challenger = route6(prefix, 8u, next_hop);
    challenger.weight = 5;
    challenger.local_pref = 300u;
    challenger.as_path_len = 1u;
    challenger.med = 5u;
    challenger.origin_as = 65200u;
    challenger.attrs = attrs8;
    challenger.attr_count = 1u;
    challenger.update_id = 50u;
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_rib6_insert(&rib, &challenger));
    assert_rib6_best_source(&rib, dest, 8u);

    challenger = route6(prefix, 9u, next_hop);
    challenger.weight = 5;
    challenger.local_pref = 400u;
    challenger.as_path_len = 1u;
    challenger.med = 1000u;
    challenger.origin_as = 65001u;
    challenger.update_id = 47u;
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_rib6_insert(&rib, &challenger));
    assert_rib6_best_source(&rib, dest, 9u);

    challenger = route6(prefix, ip4(1u, 1u, 1u, 2u), next_hop);
    challenger.weight = 5;
    challenger.local_pref = 400u;
    challenger.as_path_len = 1u;
    challenger.med = 1000u;
    challenger.origin_as = 65001u;
    challenger.update_id = 47u;
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_rib6_insert(&rib, &challenger));
    assert_rib6_best_source(&rib, dest, ip4(1u, 1u, 1u, 2u));

    challenger = route6(prefix, ip4(2u, 1u, 1u, 1u), next_hop);
    challenger.weight = 5;
    challenger.local_pref = 400u;
    challenger.as_path_len = 1u;
    challenger.med = 1000u;
    challenger.origin_as = 65001u;
    challenger.update_id = 47u;
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_rib6_insert(&rib, &challenger));
    assert_rib6_best_source(&rib, dest, ip4(1u, 1u, 1u, 2u));

    libbgp_rib6_destroy(&rib);
    libbgp_pattr_unref(path7);
    libbgp_pattr_unref(path8);
}

LIBBGP_TEST(rib6_foreach_best_route_visits_one_route_per_prefix)
{
    libbgp_rib6_t rib;
    const uint8_t first_addr[16] = { 0x20u, 0x01u, 0x0du, 0xb8u, 0u, 0x11u };
    const uint8_t second_addr[16] = { 0x20u, 0x01u, 0x0du, 0xb8u, 0u, 0x12u };
    const uint8_t next_hop[16] = { 0x20u, 0x01u, 0x0du, 0xb8u, 0xffu, 0x11u };
    libbgp_prefix6_t first = p6(first_addr, 48u);
    libbgp_prefix6_t second = p6(second_addr, 48u);
    libbgp_rib6_route_t first_best = route6(first, 1u, next_hop);
    libbgp_rib6_route_t first_backup = route6(first, 2u, next_hop);
    libbgp_rib6_route_t second_best = route6(second, 3u, next_hop);
    rib6_iter_count_ctx_t ctx;

    memset(&ctx, 0, sizeof(ctx));
    first_best.is_ibgp = true;
    first_best.local_pref = 200u;
    first_backup.local_pref = 100u;

    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_rib6_init(&rib));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_rib6_insert(&rib, &first_best));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_rib6_insert(&rib, &first_backup));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_rib6_insert(&rib, &second_best));

    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, bgp_rib6_foreach_best_route(&rib, record_rib6_source, &ctx));
    LIBBGP_ASSERT_EQ_U64(2u, ctx.count);
    LIBBGP_ASSERT(rib6_sources_contain(&ctx, 1u));
    LIBBGP_ASSERT(rib6_sources_contain(&ctx, 3u));

    libbgp_rib6_destroy(&rib);
}

LIBBGP_TEST(rib6_med_not_compared_without_neighbor_as)
{
    libbgp_rib6_t rib;
    const uint8_t prefix_addr[16] = { 0x20u, 0x01u, 0x0du, 0xb8u, 0u, 0x13u };
    const uint8_t dest[16] = { 0x20u, 0x01u, 0x0du, 0xb8u, 0u, 0x13u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 1u };
    const uint8_t next_hop[16] = { 0x20u, 0x01u, 0x0du, 0xb8u, 0xffu, 0x13u };
    libbgp_prefix6_t prefix = p6(prefix_addr, 48u);
    libbgp_rib6_route_t lower_med = route6(prefix, 1u, next_hop);
    libbgp_rib6_route_t older = route6(prefix, 2u, next_hop);

    lower_med.origin_as = 65000u;
    lower_med.med = 10u;
    lower_med.update_id = 20u;
    older.origin_as = 65000u;
    older.med = 100u;
    older.update_id = 10u;

    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_rib6_init(&rib));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_rib6_insert(&rib, &lower_med));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_rib6_insert(&rib, &older));
    assert_rib6_best_source(&rib, dest, 2u);

    libbgp_rib6_destroy(&rib);
}

LIBBGP_TEST(rib6_insert_refs_attrs_and_destroy_unrefs)
{
    libbgp_rib6_t rib;
    const uint8_t prefix_addr[16] = { 0x20u, 0x01u, 0x0du, 0xb8u, 0u, 0x14u };
    const uint8_t next_hop[16] = { 0x20u, 0x01u, 0x0du, 0xb8u, 0xffu, 0x14u };
    libbgp_prefix6_t prefix = p6(prefix_addr, 48u);
    libbgp_pattr_t *attr = libbgp_pattr_new(LIBBGP_PATTR_ORIGIN);
    libbgp_pattr_t *attrs[1];
    libbgp_rib6_route_t route = route6(prefix, 77u, next_hop);

    LIBBGP_ASSERT(attr != NULL);
    attrs[0] = attr;
    route.attrs = attrs;
    route.attr_count = 1u;

    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_rib6_init(&rib));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_rib6_insert(&rib, &route));
    LIBBGP_ASSERT_EQ_U64(2u, attr->refcount);

    route.weight = 5;
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_rib6_insert(&rib, &route));
    LIBBGP_ASSERT_EQ_U64(2u, attr->refcount);

    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_rib6_withdraw(&rib, 77u, &prefix));
    LIBBGP_ASSERT_EQ_U64(1u, attr->refcount);
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_rib6_insert(&rib, &route));
    LIBBGP_ASSERT_EQ_U64(2u, attr->refcount);

    libbgp_rib6_destroy(&rib);
    LIBBGP_ASSERT_EQ_U64(1u, attr->refcount);
    libbgp_pattr_unref(attr);
}

LIBBGP_TEST(rib6_best_route_prefers_lower_update_id)
{
    libbgp_rib6_t rib;
    const uint8_t prefix_addr[16] = { 0x20u, 0x01u, 0x0du, 0xb8u, 0u, 4u };
    const uint8_t dest[16] = { 0x20u, 0x01u, 0x0du, 0xb8u, 0u, 4u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 99u };
    const uint8_t next_hop[16] = { 0x20u, 0x01u, 0x0du, 0xb8u, 0xffu, 4u };
    libbgp_prefix6_t prefix = p6(prefix_addr, 48u);
    uint32_t older_src = ip4(192u, 0u, 2u, 250u);
    uint32_t newer_src = ip4(192u, 0u, 2u, 1u);
    libbgp_rib6_route_t older = route6(prefix, older_src, next_hop);
    libbgp_rib6_route_t newer = route6(prefix, newer_src, next_hop);

    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_rib6_init(&rib));
    older.update_id = 10u;
    newer.update_id = 20u;
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_rib6_insert(&rib, &older));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_rib6_insert(&rib, &newer));
    assert_rib6_best_source(&rib, dest, older_src);
    libbgp_rib6_destroy(&rib);
}

LIBBGP_TEST(rib6_foreach_best_route_stops_stored_route_iteration_early)
{
    libbgp_rib6_t rib;
    const uint8_t first_addr[16] = { 0x20u, 0x01u, 0x0du, 0xb8u, 0u, 7u };
    const uint8_t second_addr[16] = { 0x20u, 0x01u, 0x0du, 0xb8u, 0u, 8u };
    const uint8_t next_hop[16] = { 0x20u, 0x01u, 0x0du, 0xb8u, 0xffu, 7u };
    libbgp_prefix6_t first = p6(first_addr, 48u);
    libbgp_prefix6_t second = p6(second_addr, 48u);
    libbgp_rib6_route_t first_best = route6(first, 1u, next_hop);
    libbgp_rib6_route_t first_backup = route6(first, 2u, next_hop);
    libbgp_rib6_route_t second_best = route6(second, 3u, next_hop);
    libbgp_rib6_route_t second_backup = route6(second, 4u, next_hop);
    rib6_iter_count_ctx_t ctx;

    memset(&ctx, 0, sizeof(ctx));
    ctx.limit = 1u;
    first_best.local_pref = 200u;
    first_backup.local_pref = 100u;
    second_best.local_pref = 200u;
    second_backup.local_pref = 100u;

    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_rib6_init(&rib));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_rib6_insert(&rib, &first_best));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_rib6_insert(&rib, &first_backup));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_rib6_insert(&rib, &second_best));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_rib6_insert(&rib, &second_backup));

    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, bgp_rib6_foreach_best_route(&rib, record_rib6_source, &ctx));
    LIBBGP_ASSERT_EQ_U64(1u, ctx.count);
    LIBBGP_ASSERT(ctx.sources[0] == 1u || ctx.sources[0] == 3u);

    libbgp_rib6_destroy(&rib);
}

LIBBGP_TEST(rib6_med_comparison_uses_neighbor_as_from_as_path)
{
    libbgp_rib6_t rib;
    const uint8_t prefix_addr[16] = { 0x20u, 0x01u, 0x0du, 0xb8u, 0u, 9u };
    const uint8_t dest[16] = { 0x20u, 0x01u, 0x0du, 0xb8u, 0u, 9u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 1u };
    const uint8_t next_hop[16] = { 0x20u, 0x01u, 0x0du, 0xb8u, 0xffu, 9u };
    libbgp_prefix6_t prefix = p6(prefix_addr, 48u);
    libbgp_rib6_route_t high_med = route6(prefix, 1u, next_hop);
    libbgp_rib6_route_t low_med = route6(prefix, 2u, next_hop);
    libbgp_pattr_t *high_path = test_as_path_attr(65000u, 65100u);
    libbgp_pattr_t *low_path = test_as_path_attr(65000u, 65200u);
    libbgp_pattr_t *high_attrs[1];
    libbgp_pattr_t *low_attrs[1];

    high_attrs[0] = high_path;
    low_attrs[0] = low_path;
    high_med.attrs = high_attrs;
    high_med.attr_count = 1u;
    high_med.as_path_len = 2u;
    high_med.origin_as = 65100u;
    high_med.med = 100u;
    high_med.update_id = 10u;
    low_med.attrs = low_attrs;
    low_med.attr_count = 1u;
    low_med.as_path_len = 2u;
    low_med.origin_as = 65200u;
    low_med.med = 10u;
    low_med.update_id = 20u;

    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_rib6_init(&rib));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_rib6_insert(&rib, &high_med));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_rib6_insert(&rib, &low_med));
    assert_rib6_best_source(&rib, dest, 2u);

    libbgp_rib6_destroy(&rib);
    libbgp_pattr_unref(high_path);
    libbgp_pattr_unref(low_path);
}

LIBBGP_TEST(rib6_insert_reports_same_update_id_best_replacement)
{
    libbgp_rib6_t rib;
    const uint8_t prefix_addr[16] = { 0x20u, 0x01u, 0x0du, 0xb8u, 0u, 6u };
    const uint8_t next_hop[16] = { 0x20u, 0x01u, 0x0du, 0xb8u, 0xffu, 6u };
    libbgp_prefix6_t prefix = p6(prefix_addr, 48u);
    libbgp_rib6_route_t initial = route6(prefix, 1u, next_hop);
    libbgp_rib6_route_t replacement = route6(prefix, 1u, next_hop);
    bgp_rib6_change_t change;
    uint64_t update_id = 42u;

    initial.update_id = 42u;
    replacement.update_id = 42u;
    initial.local_pref = 100u;
    replacement.local_pref = 200u;

    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_rib6_init(&rib));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, bgp_rib6_insert_track_best(&rib, &initial, &change, &update_id));
    LIBBGP_ASSERT_EQ_I64(BGP_RIB_CHANGE_NEW_BEST, change.kind);

    update_id = 42u;
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, bgp_rib6_insert_track_best(&rib, &replacement, &change, &update_id));
    LIBBGP_ASSERT_EQ_I64(BGP_RIB_CHANGE_REPLACEMENT_BEST, change.kind);
    LIBBGP_ASSERT(change.best != NULL);
    LIBBGP_ASSERT_EQ_U64(1u, change.best->source_router_id);
    LIBBGP_ASSERT_EQ_U64(42u, change.best->update_id);
    LIBBGP_ASSERT_EQ_U64(200u, change.best->local_pref);

    libbgp_rib6_destroy(&rib);
}

LIBBGP_TEST(rib6_insert_and_withdraw_track_best_changes)
{
    libbgp_rib6_t rib;
    const uint8_t prefix_addr[16] = { 0x20u, 0x01u, 0x0du, 0xb8u, 0u, 5u };
    const uint8_t next_hop[16] = { 0x20u, 0x01u, 0x0du, 0xb8u, 0xffu, 5u };
    libbgp_prefix6_t prefix = p6(prefix_addr, 48u);
    libbgp_rib6_route_t initial = route6(prefix, 1u, next_hop);
    libbgp_rib6_route_t better = route6(prefix, 2u, next_hop);
    libbgp_rib6_route_t worse = route6(prefix, 3u, next_hop);
    bgp_rib6_change_t change;
    uint64_t update_id = 0u;

    initial.local_pref = 100u;
    better.local_pref = 200u;
    worse.local_pref = 50u;

    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_rib6_init(&rib));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, bgp_rib6_insert_track_best(&rib, &initial, &change, &update_id));
    LIBBGP_ASSERT_EQ_I64(BGP_RIB_CHANGE_NEW_BEST, change.kind);

    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, bgp_rib6_insert_track_best(&rib, &better, &change, &update_id));
    LIBBGP_ASSERT_EQ_I64(BGP_RIB_CHANGE_REPLACEMENT_BEST, change.kind);
    LIBBGP_ASSERT(change.best != NULL);
    LIBBGP_ASSERT_EQ_U64(2u, change.best->source_router_id);

    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, bgp_rib6_insert_track_best(&rib, &worse, &change, &update_id));
    LIBBGP_ASSERT_EQ_I64(BGP_RIB_CHANGE_NO_BEST_CHANGE, change.kind);
    LIBBGP_ASSERT(change.best != NULL);
    LIBBGP_ASSERT_EQ_U64(2u, change.best->source_router_id);

    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, bgp_rib6_withdraw_track_best(&rib, 3u, &prefix, &change));
    LIBBGP_ASSERT_EQ_I64(BGP_RIB_CHANGE_NO_BEST_CHANGE, change.kind);
    LIBBGP_ASSERT(change.best != NULL);
    LIBBGP_ASSERT_EQ_U64(2u, change.best->source_router_id);

    libbgp_rib6_destroy(&rib);
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

LIBBGP_TEST(rib6_insert_local_creates_legacy_path_attributes)
{
    libbgp_rib6_t rib;
    static const uint8_t prefix_addr[16] = { 0x20u, 0x01u, 0x0du, 0xb8u, 0x80u };
    static const uint8_t dest[16] = { 0x20u, 0x01u, 0x0du, 0xb8u, 0x80u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 1u };
    static const uint8_t next_hop[16] = { 0x20u, 0x01u, 0x0du, 0xb8u, 0xffu, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 9u };
    libbgp_prefix6_t prefix = p6(prefix_addr, 40u);
    const libbgp_rib6_route_t *found = NULL;
    libbgp_pattr_t *origin;
    libbgp_pattr_t *as_path;

    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_rib6_init(&rib));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_rib6_insert_local(&rib, &prefix, next_hop, 11));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_rib6_lookup(&rib, dest, &found));
    LIBBGP_ASSERT(found != NULL);
    LIBBGP_ASSERT_EQ_U64(2u, found->attr_count);
    origin = route6_find_attr(found, LIBBGP_PATTR_ORIGIN);
    as_path = route6_find_attr(found, LIBBGP_PATTR_AS_PATH);
    LIBBGP_ASSERT(origin != NULL);
    LIBBGP_ASSERT(as_path != NULL);
    LIBBGP_ASSERT_EQ_U64(0u, origin->data.origin.origin);
    LIBBGP_ASSERT_EQ_U64(0u, as_path->data.as_path.segment_count);
    LIBBGP_ASSERT(as_path->data.as_path.is_4b);
    LIBBGP_ASSERT_EQ_I64(0, memcmp(next_hop, found->next_hop, sizeof(found->next_hop)));

    libbgp_rib6_destroy(&rib);
}

LIBBGP_TEST(rib6_insert_local_rejects_duplicate_prefix)
{
    libbgp_rib6_t rib;
    const uint8_t prefix_addr[16] = { 0x20u, 0x01u, 0x0du, 0xb8u, 0u, 3u };
    const uint8_t dest[16] = { 0x20u, 0x01u, 0x0du, 0xb8u, 0u, 3u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 9u };
    const uint8_t next_hop1[16] = { 0x20u, 0x01u, 0x0du, 0xb8u, 0xffu, 1u };
    const uint8_t next_hop2[16] = { 0x20u, 0x01u, 0x0du, 0xb8u, 0xffu, 2u };
    libbgp_prefix6_t prefix = p6(prefix_addr, 48u);
    const libbgp_rib6_route_t *found = NULL;

    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_rib6_init(&rib));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_rib6_insert_local(&rib, &prefix, next_hop1, 11));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_EXISTS, libbgp_rib6_insert_local(&rib, &prefix, next_hop2, 22));
    LIBBGP_ASSERT_EQ_U64(1u, libbgp_rib6_route_count(&rib));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_rib6_lookup(&rib, dest, &found));
    LIBBGP_ASSERT(found != NULL);
    LIBBGP_ASSERT_BYTES_EQ(next_hop1, found->next_hop, sizeof(next_hop1));
    LIBBGP_ASSERT_EQ_I64(11, found->weight);
    libbgp_rib6_destroy(&rib);
}

int main(void)
{
    const libbgp_test_case_t tests[] = {
        { "rib4_insert_local_and_lookup_longest_prefix", rib4_insert_local_and_lookup_longest_prefix },
        { "rib4_insert_local_creates_legacy_path_attributes", rib4_insert_local_creates_legacy_path_attributes },
        { "rib4_insert_local_rejects_duplicate_prefix", rib4_insert_local_rejects_duplicate_prefix },
        { "rib4_best_route_ordering_for_same_prefix", rib4_best_route_ordering_for_same_prefix },
        { "rib4_best_route_prefers_lower_update_id", rib4_best_route_prefers_lower_update_id },
        { "rib4_best_route_prefers_lower_update_id_as_final_tie_break", rib4_best_route_prefers_lower_update_id_as_final_tie_break },
        { "rib4_foreach_best_route_visits_one_route_per_prefix", rib4_foreach_best_route_visits_one_route_per_prefix },
        { "rib4_foreach_best_route_stops_stored_route_iteration_early", rib4_foreach_best_route_stops_stored_route_iteration_early },
        { "rib4_med_comparison_uses_neighbor_as_from_as_path", rib4_med_comparison_uses_neighbor_as_from_as_path },
        { "rib4_med_not_compared_without_neighbor_as", rib4_med_not_compared_without_neighbor_as },
        { "rib4_insert_reports_only_best_path_changes", rib4_insert_reports_only_best_path_changes },
        { "rib4_insert_reports_replacement_best_when_better_route_wins", rib4_insert_reports_replacement_best_when_better_route_wins },
        { "rib4_insert_reports_same_update_id_best_replacement", rib4_insert_reports_same_update_id_best_replacement },
        { "rib4_withdraw_reports_replacement_vs_unreachable", rib4_withdraw_reports_replacement_vs_unreachable },
        { "rib6_best_route_ordering_for_same_prefix", rib6_best_route_ordering_for_same_prefix },
        { "rib6_foreach_best_route_visits_one_route_per_prefix", rib6_foreach_best_route_visits_one_route_per_prefix },
        { "rib6_med_not_compared_without_neighbor_as", rib6_med_not_compared_without_neighbor_as },
        { "rib6_insert_refs_attrs_and_destroy_unrefs", rib6_insert_refs_attrs_and_destroy_unrefs },
        { "rib6_best_route_prefers_lower_update_id", rib6_best_route_prefers_lower_update_id },
        { "rib6_foreach_best_route_stops_stored_route_iteration_early", rib6_foreach_best_route_stops_stored_route_iteration_early },
        { "rib6_med_comparison_uses_neighbor_as_from_as_path", rib6_med_comparison_uses_neighbor_as_from_as_path },
        { "rib6_insert_reports_same_update_id_best_replacement", rib6_insert_reports_same_update_id_best_replacement },
        { "rib6_insert_and_withdraw_track_best_changes", rib6_insert_and_withdraw_track_best_changes },
        { "rib_best_route_compares_router_ids_as_network_order", rib_best_route_compares_router_ids_as_network_order },
        { "rib4_replace_withdraw_discard_and_scoped_lookup", rib4_replace_withdraw_discard_and_scoped_lookup },
        { "rib4_lookup_returns_borrowed_pointer_replaced_by_mutation", rib4_lookup_returns_borrowed_pointer_replaced_by_mutation },
        { "rib4_insert_refs_attrs_and_destroy_unrefs", rib4_insert_refs_attrs_and_destroy_unrefs },
        { "rib6_insert_lookup_withdraw_discard_and_scoped", rib6_insert_lookup_withdraw_discard_and_scoped },
        { "rib6_insert_local_creates_legacy_path_attributes", rib6_insert_local_creates_legacy_path_attributes },
        { "rib6_insert_local_rejects_duplicate_prefix", rib6_insert_local_rejects_duplicate_prefix }
    };

    return libbgp_run_tests("rib", tests, LIBBGP_ARRAY_LEN(tests));
}
