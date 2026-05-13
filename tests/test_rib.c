#include "test_main.h"

#include "libbgp/pattr.h"
#include "libbgp/rib4.h"
#include "libbgp/rib6.h"
#include "../src/internal.h"
#include "../src/hashmap.h"
#include "../src/rib_internal.h"
#include "fixtures/alloc_tracker.h"

#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

#include "libbgp/alloc.h"

typedef struct fail_after_alloc_ctx {
    size_t calls;
    size_t fail_at;
} fail_after_alloc_ctx_t;

static void *fail_after_malloc(size_t size, void *ctx)
{
    fail_after_alloc_ctx_t *fail_ctx = (fail_after_alloc_ctx_t *)ctx;

    fail_ctx->calls++;
    if (fail_ctx->calls == fail_ctx->fail_at) {
        return NULL;
    }
    return malloc(size);
}

static void *fail_after_calloc(size_t nmemb, size_t size, void *ctx)
{
    fail_after_alloc_ctx_t *fail_ctx = (fail_after_alloc_ctx_t *)ctx;

    fail_ctx->calls++;
    if (fail_ctx->calls == fail_ctx->fail_at) {
        return NULL;
    }
    return calloc(nmemb, size);
}

static void *fail_after_realloc(void *ptr, size_t size, void *ctx)
{
    fail_after_alloc_ctx_t *fail_ctx = (fail_after_alloc_ctx_t *)ctx;

    fail_ctx->calls++;
    if (fail_ctx->calls == fail_ctx->fail_at) {
        return NULL;
    }
    return realloc(ptr, size);
}

static void fail_after_free(void *ptr, void *ctx)
{
    (void)ctx;
    free(ptr);
}

static libbgp_alloc_t fail_after_alloc_make(fail_after_alloc_ctx_t *ctx)
{
    libbgp_alloc_t alloc;

    alloc.malloc = fail_after_malloc;
    alloc.calloc = fail_after_calloc;
    alloc.realloc = fail_after_realloc;
    alloc.free = fail_after_free;
    alloc.ctx = ctx;
    return alloc;
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
    segment = (libbgp_as_path_segment_t *)libbgp_calloc(1u, sizeof(*segment));
    asns = (uint32_t *)libbgp_calloc(2u, sizeof(*asns));
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

static libbgp_pattr_t *test_as_path_attr_with_segments(
    uint8_t first_type,
    uint32_t first_asn,
    uint8_t second_type,
    uint32_t second_asn)
{
    libbgp_pattr_t *attr = libbgp_pattr_new(LIBBGP_PATTR_AS_PATH);
    libbgp_as_path_segment_t *segments;
    uint32_t *first_asns;
    uint32_t *second_asns;

    LIBBGP_ASSERT(attr != NULL);
    segments = (libbgp_as_path_segment_t *)libbgp_calloc(2u, sizeof(*segments));
    first_asns = (uint32_t *)libbgp_calloc(1u, sizeof(*first_asns));
    second_asns = (uint32_t *)libbgp_calloc(1u, sizeof(*second_asns));
    LIBBGP_ASSERT(segments != NULL);
    LIBBGP_ASSERT(first_asns != NULL);
    LIBBGP_ASSERT(second_asns != NULL);
    first_asns[0] = first_asn;
    second_asns[0] = second_asn;
    segments[0].type = first_type;
    segments[0].asn_count = 1u;
    segments[0].asns = first_asns;
    segments[1].type = second_type;
    segments[1].asn_count = 1u;
    segments[1].asns = second_asns;
    attr->data.as_path.segments = segments;
    attr->data.as_path.segment_count = 2u;
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

LIBBGP_TEST(rib4_foreach_best_route_avoids_per_prefix_realloc)
{
    libbgp_rib4_t rib;
    libbgp_alloc_tracker_t tracker;
    libbgp_alloc_t alloc;
    rib4_iter_count_ctx_t ctx;
    size_t i;

    memset(&ctx, 0, sizeof(ctx));
    libbgp_alloc_tracker_init(&tracker);
    alloc = libbgp_alloc_tracker_make(&tracker);

    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_rib4_init(&rib));
    for (i = 0u; i < 8u; i++) {
        libbgp_prefix4_t prefix = p4(10u, 30u, (uint8_t)i, 0u, 24u);
        libbgp_rib4_route_t best = route4(prefix, (uint32_t)(i + 1u));
        libbgp_rib4_route_t backup = route4(prefix, (uint32_t)(i + 101u));

        best.local_pref = 200u;
        backup.local_pref = 100u;
        LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_rib4_insert(&rib, &best));
        LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_rib4_insert(&rib, &backup));
    }

    libbgp_set_alloc(&alloc);
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, bgp_rib4_foreach_best_route(&rib, record_rib4_source, &ctx));
    libbgp_set_alloc(NULL);

    LIBBGP_ASSERT_EQ_U64(8u, ctx.count);
    LIBBGP_ASSERT(tracker.realloc_calls <= 1u);
    libbgp_rib4_destroy(&rib);
}

LIBBGP_TEST(rib4_discard_collect_preserves_replacement_correctness)
{
    libbgp_rib4_t rib;
    bgp_rib4_discard_result_t result;
    libbgp_prefix4_t replaced_prefix = p4(10u, 31u, 0u, 0u, 24u);
    libbgp_prefix4_t withdrawn_prefix = p4(10u, 31u, 1u, 0u, 24u);
    libbgp_rib4_route_t peer_best = route4(replaced_prefix, 1u);
    libbgp_rib4_route_t replacement = route4(replaced_prefix, 2u);
    libbgp_rib4_route_t peer_only = route4(withdrawn_prefix, 1u);
    const libbgp_rib4_route_t *found = NULL;

    peer_best.local_pref = 200u;
    replacement.local_pref = 100u;
    peer_only.local_pref = 200u;

    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_rib4_init(&rib));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_rib4_insert(&rib, &peer_best));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_rib4_insert(&rib, &replacement));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_rib4_insert(&rib, &peer_only));

    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, bgp_rib4_discard_collect(&rib, 1u, &result));
    LIBBGP_ASSERT_EQ_U64(1u, result.withdrawn_count);
    LIBBGP_ASSERT(libbgp_prefix4_eq(&withdrawn_prefix, &result.withdrawn[0]));
    LIBBGP_ASSERT_EQ_U64(1u, result.replacement_count);
    LIBBGP_ASSERT(libbgp_prefix4_eq(&replaced_prefix, &result.replacements[0].prefix));
    LIBBGP_ASSERT_EQ_U64(2u, result.replacements[0].source_router_id);
    LIBBGP_ASSERT_EQ_U64(1u, libbgp_rib4_route_count(&rib));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_rib4_lookup(&rib, ip4(10u, 31u, 0u, 1u), &found));
    LIBBGP_ASSERT_EQ_U64(2u, found->source_router_id);
    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_NOT_FOUND, libbgp_rib4_lookup(&rib, ip4(10u, 31u, 1u, 1u), &found));

    bgp_rib4_discard_result_destroy(&result);
    libbgp_rib4_destroy(&rib);
}

LIBBGP_TEST(rib4_discard_large)
{
    libbgp_rib4_t rib;
    size_t i;

    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_rib4_init(&rib));
    for (i = 0u; i < 500u; i++) {
        libbgp_prefix4_t prefix = p4(10u, (uint8_t)(i >> 8), (uint8_t)i, 0u, 24u);
        libbgp_rib4_route_t route = route4(prefix, 1u);

        route.local_pref = 100u;
        LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_rib4_insert(&rib, &route));
        route.source_router_id = 2u;
        route.local_pref = 200u;
        LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_rib4_insert(&rib, &route));
    }
    LIBBGP_ASSERT_EQ_U64(1000u, libbgp_rib4_route_count(&rib));

    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_rib4_discard(&rib, 1u));
    LIBBGP_ASSERT_EQ_U64(500u, libbgp_rib4_route_count(&rib));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_rib4_discard(&rib, 2u));
    LIBBGP_ASSERT_EQ_U64(0u, libbgp_rib4_route_count(&rib));

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

LIBBGP_TEST(rib4_med_ignores_missing_wrong_type_and_different_neighbor_as)
{
    libbgp_rib4_t rib;
    libbgp_prefix4_t missing_prefix = p4(203u, 0u, 116u, 0u, 24u);
    libbgp_prefix4_t wrong_type_prefix = p4(203u, 0u, 117u, 0u, 24u);
    libbgp_prefix4_t different_as_prefix = p4(203u, 0u, 118u, 0u, 24u);
    libbgp_rib4_route_t missing_low_med = route4(missing_prefix, 1u);
    libbgp_rib4_route_t missing_older = route4(missing_prefix, 2u);
    libbgp_rib4_route_t wrong_type_low_med = route4(wrong_type_prefix, 3u);
    libbgp_rib4_route_t wrong_type_older = route4(wrong_type_prefix, 4u);
    libbgp_rib4_route_t different_as_low_med = route4(different_as_prefix, 5u);
    libbgp_rib4_route_t different_as_older = route4(different_as_prefix, 6u);
    libbgp_pattr_t *wrong_type = libbgp_pattr_new(LIBBGP_PATTR_ORIGIN);
    libbgp_pattr_t *low_path = test_as_path_attr(65010u, 65100u);
    libbgp_pattr_t *older_path = test_as_path_attr(65020u, 65200u);
    libbgp_pattr_t *wrong_attrs[1];
    libbgp_pattr_t *low_attrs[1];
    libbgp_pattr_t *older_attrs[1];

    LIBBGP_ASSERT(wrong_type != NULL);
    wrong_attrs[0] = wrong_type;
    low_attrs[0] = low_path;
    older_attrs[0] = older_path;
    missing_low_med.med = 10u;
    missing_low_med.update_id = 20u;
    missing_older.med = 100u;
    missing_older.update_id = 10u;
    wrong_type_low_med.med = 10u;
    wrong_type_low_med.update_id = 20u;
    wrong_type_low_med.attrs = wrong_attrs;
    wrong_type_low_med.attr_count = 1u;
    wrong_type_older.med = 100u;
    wrong_type_older.update_id = 10u;
    wrong_type_older.attrs = wrong_attrs;
    wrong_type_older.attr_count = 1u;
    different_as_low_med.med = 10u;
    different_as_low_med.update_id = 20u;
    different_as_low_med.attrs = low_attrs;
    different_as_low_med.attr_count = 1u;
    different_as_older.med = 100u;
    different_as_older.update_id = 10u;
    different_as_older.attrs = older_attrs;
    different_as_older.attr_count = 1u;

    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_rib4_init(&rib));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_rib4_insert(&rib, &missing_low_med));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_rib4_insert(&rib, &missing_older));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_rib4_insert(&rib, &wrong_type_low_med));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_rib4_insert(&rib, &wrong_type_older));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_rib4_insert(&rib, &different_as_low_med));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_rib4_insert(&rib, &different_as_older));
    assert_rib4_best_source(&rib, ip4(203u, 0u, 116u, 1u), 2u);
    assert_rib4_best_source(&rib, ip4(203u, 0u, 117u, 1u), 4u);
    assert_rib4_best_source(&rib, ip4(203u, 0u, 118u, 1u), 6u);

    libbgp_rib4_destroy(&rib);
    libbgp_pattr_unref(wrong_type);
    libbgp_pattr_unref(low_path);
    libbgp_pattr_unref(older_path);
}

LIBBGP_TEST(rib4_neighbor_as_uses_first_as_sequence_segment)
{
    libbgp_rib4_t rib;
    libbgp_prefix4_t prefix = p4(203u, 0u, 119u, 0u, 24u);
    libbgp_rib4_route_t high_med = route4(prefix, 1u);
    libbgp_rib4_route_t low_med = route4(prefix, 2u);
    libbgp_pattr_t *high_path = test_as_path_attr_with_segments(1u, 65099u, 2u, 65030u);
    libbgp_pattr_t *low_path = test_as_path_attr_with_segments(1u, 65098u, 2u, 65030u);
    libbgp_pattr_t *high_attrs[1];
    libbgp_pattr_t *low_attrs[1];

    high_attrs[0] = high_path;
    low_attrs[0] = low_path;
    high_med.med = 100u;
    high_med.update_id = 10u;
    high_med.attrs = high_attrs;
    high_med.attr_count = 1u;
    low_med.med = 10u;
    low_med.update_id = 20u;
    low_med.attrs = low_attrs;
    low_med.attr_count = 1u;

    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_rib4_init(&rib));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_rib4_insert(&rib, &high_med));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_rib4_insert(&rib, &low_med));
    assert_rib4_best_source(&rib, ip4(203u, 0u, 119u, 1u), 2u);

    libbgp_rib4_destroy(&rib);
    libbgp_pattr_unref(high_path);
    libbgp_pattr_unref(low_path);
}

LIBBGP_TEST(rib4_neighbor_as_skips_null_attrs_and_rejects_malformed_path)
{
    libbgp_rib4_t rib;
    libbgp_prefix4_t null_prefix = p4(203u, 0u, 120u, 0u, 24u);
    libbgp_prefix4_t malformed_prefix = p4(203u, 0u, 121u, 0u, 24u);
    libbgp_rib4_route_t null_high = route4(null_prefix, 1u);
    libbgp_rib4_route_t null_low = route4(null_prefix, 2u);
    libbgp_rib4_route_t malformed_low = route4(malformed_prefix, 3u);
    libbgp_rib4_route_t malformed_old = route4(malformed_prefix, 4u);
    libbgp_pattr_t *high_path = test_as_path_attr(65040u, 65100u);
    libbgp_pattr_t *low_path = test_as_path_attr(65040u, 65200u);
    libbgp_pattr_t *malformed_path = libbgp_pattr_new(LIBBGP_PATTR_AS_PATH);
    libbgp_pattr_t *high_attrs[2];
    libbgp_pattr_t *low_attrs[2];
    libbgp_pattr_t *malformed_attrs[1];

    LIBBGP_ASSERT(malformed_path != NULL);
    malformed_path->data.as_path.segment_count = 1u;
    malformed_path->data.as_path.segments = NULL;
    high_attrs[0] = NULL;
    high_attrs[1] = high_path;
    low_attrs[0] = NULL;
    low_attrs[1] = low_path;
    malformed_attrs[0] = malformed_path;

    null_high.med = 100u;
    null_high.update_id = 10u;
    null_high.attrs = high_attrs;
    null_high.attr_count = 2u;
    null_low.med = 10u;
    null_low.update_id = 20u;
    null_low.attrs = low_attrs;
    null_low.attr_count = 2u;
    malformed_low.med = 10u;
    malformed_low.update_id = 20u;
    malformed_low.attrs = malformed_attrs;
    malformed_low.attr_count = 1u;
    malformed_old.med = 100u;
    malformed_old.update_id = 10u;
    malformed_old.attrs = malformed_attrs;
    malformed_old.attr_count = 1u;

    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_rib4_init(&rib));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_rib4_insert(&rib, &null_high));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_rib4_insert(&rib, &null_low));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_rib4_insert(&rib, &malformed_low));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_rib4_insert(&rib, &malformed_old));
    assert_rib4_best_source(&rib, ip4(203u, 0u, 120u, 1u), 2u);
    assert_rib4_best_source(&rib, ip4(203u, 0u, 121u, 1u), 4u);

    libbgp_rib4_destroy(&rib);
    libbgp_pattr_unref(high_path);
    libbgp_pattr_unref(low_path);
    libbgp_pattr_unref(malformed_path);
}

LIBBGP_TEST(rib6_neighbor_as_skips_null_attrs_and_rejects_malformed_path)
{
    libbgp_rib6_t rib;
    const uint8_t null_addr[16] = { 0x20u, 0x01u, 0x0du, 0xb8u, 0u, 0x20u };
    const uint8_t null_dest[16] = { 0x20u, 0x01u, 0x0du, 0xb8u, 0u, 0x20u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 1u };
    const uint8_t malformed_addr[16] = { 0x20u, 0x01u, 0x0du, 0xb8u, 0u, 0x21u };
    const uint8_t malformed_dest[16] = { 0x20u, 0x01u, 0x0du, 0xb8u, 0u, 0x21u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 1u };
    const uint8_t next_hop[16] = { 0x20u, 0x01u, 0x0du, 0xb8u, 0xffu, 0x20u };
    libbgp_rib6_route_t null_high = route6(p6(null_addr, 48u), 1u, next_hop);
    libbgp_rib6_route_t null_low = route6(p6(null_addr, 48u), 2u, next_hop);
    libbgp_rib6_route_t malformed_low = route6(p6(malformed_addr, 48u), 3u, next_hop);
    libbgp_rib6_route_t malformed_old = route6(p6(malformed_addr, 48u), 4u, next_hop);
    libbgp_pattr_t *high_path = test_as_path_attr(65040u, 65100u);
    libbgp_pattr_t *low_path = test_as_path_attr(65040u, 65200u);
    libbgp_pattr_t *malformed_path = libbgp_pattr_new(LIBBGP_PATTR_AS_PATH);
    libbgp_pattr_t *high_attrs[2];
    libbgp_pattr_t *low_attrs[2];
    libbgp_pattr_t *malformed_attrs[1];
    libbgp_err_t err;

    LIBBGP_ASSERT(malformed_path != NULL);
    malformed_path->data.as_path.segment_count = 1u;
    malformed_path->data.as_path.segments = NULL;
    high_attrs[0] = NULL;
    high_attrs[1] = high_path;
    low_attrs[0] = NULL;
    low_attrs[1] = low_path;
    malformed_attrs[0] = malformed_path;

    null_high.med = 100u;
    null_high.update_id = 10u;
    null_high.attrs = high_attrs;
    null_high.attr_count = 2u;
    null_low.med = 10u;
    null_low.update_id = 20u;
    null_low.attrs = low_attrs;
    null_low.attr_count = 2u;
    malformed_low.med = 10u;
    malformed_low.update_id = 20u;
    malformed_low.attrs = malformed_attrs;
    malformed_low.attr_count = 1u;
    malformed_old.med = 100u;
    malformed_old.update_id = 10u;
    malformed_old.attrs = malformed_attrs;
    malformed_old.attr_count = 1u;

    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_rib6_init(&rib));
    err = libbgp_rib6_insert(&rib, &null_high);
    if (err == LIBBGP_ERR_INVALID) {
        LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_INVALID, libbgp_rib6_insert(&rib, &null_low));
        LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_rib6_insert(&rib, &malformed_low));
        LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_rib6_insert(&rib, &malformed_old));
        assert_rib6_best_source(&rib, malformed_dest, 4u);
        libbgp_rib6_destroy(&rib);
        libbgp_pattr_unref(high_path);
        libbgp_pattr_unref(low_path);
        libbgp_pattr_unref(malformed_path);
        return;
    }
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, err);
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_rib6_insert(&rib, &null_low));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_rib6_insert(&rib, &malformed_low));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_rib6_insert(&rib, &malformed_old));
    assert_rib6_best_source(&rib, null_dest, 2u);
    assert_rib6_best_source(&rib, malformed_dest, 4u);

    libbgp_rib6_destroy(&rib);
    libbgp_pattr_unref(high_path);
    libbgp_pattr_unref(low_path);
    libbgp_pattr_unref(malformed_path);
}

LIBBGP_TEST(rib4_saved_route_withdraw_restore_and_conflict_paths)
{
    libbgp_rib4_t rib;
    libbgp_prefix4_t prefix = p4(10u, 71u, 0u, 0u, 24u);
    libbgp_rib4_route_t original = route4(prefix, 71u);
    libbgp_rib4_route_t conflict = route4(prefix, 71u);
    bgp_rib4_saved_route_t saved;
    bool had_route = true;
    uint64_t update_id = 0u;
    const libbgp_rib4_route_t *found = NULL;

    memset(&saved, 0, sizeof(saved));
    original.local_pref = 150u;
    conflict.local_pref = 250u;

    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_rib4_init(&rib));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_rib4_insert(&rib, &original));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, bgp_rib4_withdraw_exact_save(&rib, 99u, &prefix, &saved, &had_route));
    LIBBGP_ASSERT(!had_route);
    LIBBGP_ASSERT(saved.entry == NULL);

    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, bgp_rib4_withdraw_exact_save(&rib, 71u, &prefix, &saved, &had_route));
    LIBBGP_ASSERT(had_route);
    LIBBGP_ASSERT(saved.entry != NULL);
    LIBBGP_ASSERT_EQ_U64(0u, libbgp_rib4_route_count(&rib));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, bgp_rib4_saved_route_update_id(&saved, &update_id));
    LIBBGP_ASSERT(update_id != 0u);

    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_rib4_insert(&rib, &conflict));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, bgp_rib4_restore_saved_if_absent(&rib, 71u, &saved));
    LIBBGP_ASSERT(saved.entry != NULL);
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_rib4_lookup(&rib, ip4(10u, 71u, 0u, 1u), &found));
    LIBBGP_ASSERT_EQ_U64(250u, found->local_pref);

    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_rib4_withdraw(&rib, 71u, &prefix));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, bgp_rib4_restore_saved_if_absent(&rib, 71u, &saved));
    LIBBGP_ASSERT(saved.entry == NULL);
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_rib4_lookup(&rib, ip4(10u, 71u, 0u, 1u), &found));
    LIBBGP_ASSERT_EQ_U64(150u, found->local_pref);

    bgp_rib4_saved_route_destroy(&saved);
    libbgp_rib4_destroy(&rib);
}

LIBBGP_TEST(rib4_discard_collect_reports_allocator_failures)
{
    libbgp_rib4_t rib;
    libbgp_prefix4_t withdrawn_prefix = p4(10u, 72u, 0u, 0u, 24u);
    libbgp_prefix4_t replaced_prefix = p4(10u, 72u, 1u, 0u, 24u);
    libbgp_rib4_route_t peer_only = route4(withdrawn_prefix, 72u);
    libbgp_rib4_route_t peer_best = route4(replaced_prefix, 72u);
    libbgp_rib4_route_t replacement = route4(replaced_prefix, 73u);
    bgp_rib4_discard_result_t result;
    fail_after_alloc_ctx_t fail_ctx;
    libbgp_alloc_t alloc;
    libbgp_err_t err;

    peer_only.local_pref = 200u;
    peer_best.local_pref = 200u;
    replacement.local_pref = 100u;

    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_rib4_init(&rib));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_rib4_insert(&rib, &peer_only));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_rib4_insert(&rib, &peer_best));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_rib4_insert(&rib, &replacement));

    fail_ctx.calls = 0u;
    fail_ctx.fail_at = 1u;
    alloc = fail_after_alloc_make(&fail_ctx);
    libbgp_set_alloc(&alloc);
    err = bgp_rib4_discard_collect(&rib, 72u, &result);
    libbgp_set_alloc(NULL);
    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_NOMEM, err);
    LIBBGP_ASSERT_EQ_U64(0u, result.withdrawn_count);
    LIBBGP_ASSERT_EQ_U64(0u, result.replacement_count);

    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_rib4_insert(&rib, &peer_only));
    fail_ctx.calls = 0u;
    fail_ctx.fail_at = 3u;
    libbgp_set_alloc(&alloc);
    err = bgp_rib4_discard_collect(&rib, 72u, &result);
    libbgp_set_alloc(NULL);
    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_NOMEM, err);
    LIBBGP_ASSERT_EQ_U64(0u, result.withdrawn_count);
    LIBBGP_ASSERT_EQ_U64(0u, result.replacement_count);

    libbgp_rib4_destroy(&rib);
}

LIBBGP_TEST(rib4_insert_defaults_local_pref_and_update_id)
{
    libbgp_rib4_t rib;
    libbgp_prefix4_t prefix = p4(198u, 51u, 101u, 0u, 24u);
    libbgp_rib4_route_t route = route4(prefix, 101u);
    const libbgp_rib4_route_t *found = NULL;
    uint64_t update_id = 0u;

    route.local_pref = 0u;
    route.update_id = 0u;

    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_rib4_init(&rib));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, bgp_rib4_insert_save_replaced(&rib, &route, NULL, NULL, &update_id));
    LIBBGP_ASSERT(update_id != 0u);
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_rib4_lookup(&rib, ip4(198u, 51u, 101u, 1u), &found));
    LIBBGP_ASSERT(found != NULL);
    LIBBGP_ASSERT_EQ_U64(100u, found->local_pref);
    LIBBGP_ASSERT_EQ_U64(update_id, found->update_id);

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

LIBBGP_TEST(rib6_foreach_best_route_avoids_per_prefix_realloc)
{
    libbgp_rib6_t rib;
    libbgp_alloc_tracker_t tracker;
    libbgp_alloc_t alloc;
    rib6_iter_count_ctx_t ctx;
    const uint8_t next_hop[16] = { 0x20u, 0x01u, 0x0du, 0xb8u, 0xffu, 0x31u };
    size_t i;

    memset(&ctx, 0, sizeof(ctx));
    libbgp_alloc_tracker_init(&tracker);
    alloc = libbgp_alloc_tracker_make(&tracker);

    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_rib6_init(&rib));
    for (i = 0u; i < 8u; i++) {
        uint8_t addr[16] = { 0x20u, 0x01u, 0x0du, 0xb8u, 0u, 0x31u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, (uint8_t)i, 0u };
        libbgp_prefix6_t prefix = p6(addr, 120u);
        libbgp_rib6_route_t best = route6(prefix, (uint32_t)(i + 1u), next_hop);
        libbgp_rib6_route_t backup = route6(prefix, (uint32_t)(i + 101u), next_hop);

        best.local_pref = 200u;
        backup.local_pref = 100u;
        LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_rib6_insert(&rib, &best));
        LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_rib6_insert(&rib, &backup));
    }

    libbgp_set_alloc(&alloc);
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, bgp_rib6_foreach_best_route(&rib, record_rib6_source, &ctx));
    libbgp_set_alloc(NULL);

    LIBBGP_ASSERT_EQ_U64(8u, ctx.count);
    LIBBGP_ASSERT(tracker.realloc_calls <= 1u);
    libbgp_rib6_destroy(&rib);
}

LIBBGP_TEST(rib6_discard_collect_preserves_replacement_correctness)
{
    libbgp_rib6_t rib;
    bgp_rib6_discard_result_t result;
    const uint8_t replaced_addr[16] = { 0x20u, 0x01u, 0x0du, 0xb8u, 0u, 0x32u };
    const uint8_t withdrawn_addr[16] = { 0x20u, 0x01u, 0x0du, 0xb8u, 0u, 0x33u };
    const uint8_t replaced_dest[16] = { 0x20u, 0x01u, 0x0du, 0xb8u, 0u, 0x32u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 1u };
    const uint8_t withdrawn_dest[16] = { 0x20u, 0x01u, 0x0du, 0xb8u, 0u, 0x33u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 1u };
    const uint8_t next_hop[16] = { 0x20u, 0x01u, 0x0du, 0xb8u, 0xffu, 0x32u };
    libbgp_prefix6_t replaced_prefix = p6(replaced_addr, 48u);
    libbgp_prefix6_t withdrawn_prefix = p6(withdrawn_addr, 48u);
    libbgp_rib6_route_t peer_best = route6(replaced_prefix, 1u, next_hop);
    libbgp_rib6_route_t replacement = route6(replaced_prefix, 2u, next_hop);
    libbgp_rib6_route_t peer_only = route6(withdrawn_prefix, 1u, next_hop);
    const libbgp_rib6_route_t *found = NULL;

    peer_best.local_pref = 200u;
    replacement.local_pref = 100u;
    peer_only.local_pref = 200u;

    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_rib6_init(&rib));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_rib6_insert(&rib, &peer_best));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_rib6_insert(&rib, &replacement));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_rib6_insert(&rib, &peer_only));

    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, bgp_rib6_discard_collect(&rib, 1u, &result));
    LIBBGP_ASSERT_EQ_U64(1u, result.withdrawn_count);
    LIBBGP_ASSERT(libbgp_prefix6_eq(&withdrawn_prefix, &result.withdrawn[0]));
    LIBBGP_ASSERT_EQ_U64(1u, result.replacement_count);
    LIBBGP_ASSERT(libbgp_prefix6_eq(&replaced_prefix, &result.replacements[0].prefix));
    LIBBGP_ASSERT_EQ_U64(2u, result.replacements[0].source_router_id);
    LIBBGP_ASSERT_EQ_U64(1u, libbgp_rib6_route_count(&rib));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_rib6_lookup(&rib, replaced_dest, &found));
    LIBBGP_ASSERT_EQ_U64(2u, found->source_router_id);
    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_NOT_FOUND, libbgp_rib6_lookup(&rib, withdrawn_dest, &found));

    bgp_rib6_discard_result_destroy(&result);
    libbgp_rib6_destroy(&rib);
}

LIBBGP_TEST(rib6_discard_large)
{
    libbgp_rib6_t rib;
    static const uint8_t next_hop[16] = { 0x20u, 0x01u, 0x0du, 0xb8u, 0xffu, 0x55u };
    size_t i;

    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_rib6_init(&rib));
    for (i = 0u; i < 500u; i++) {
        uint8_t addr[16] = { 0x20u, 0x01u, 0x0du, 0xb8u };
        libbgp_prefix6_t prefix;
        libbgp_rib6_route_t route;

        addr[6] = (uint8_t)(i >> 8);
        addr[7] = (uint8_t)i;
        prefix = p6(addr, 64u);
        route = route6(prefix, 1u, next_hop);
        route.local_pref = 100u;
        LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_rib6_insert(&rib, &route));
        route.source_router_id = 2u;
        route.local_pref = 200u;
        LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_rib6_insert(&rib, &route));
    }
    LIBBGP_ASSERT_EQ_U64(1000u, libbgp_rib6_route_count(&rib));

    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_rib6_discard(&rib, 1u));
    LIBBGP_ASSERT_EQ_U64(500u, libbgp_rib6_route_count(&rib));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_rib6_discard(&rib, 2u));
    LIBBGP_ASSERT_EQ_U64(0u, libbgp_rib6_route_count(&rib));

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

LIBBGP_TEST(rib6_med_ignores_missing_wrong_type_and_different_neighbor_as)
{
    libbgp_rib6_t rib;
    const uint8_t next_hop[16] = { 0x20u, 0x01u, 0x0du, 0xb8u, 0xffu, 0x16u };
    const uint8_t missing_addr[16] = { 0x20u, 0x01u, 0x0du, 0xb8u, 0u, 0x16u };
    const uint8_t wrong_type_addr[16] = { 0x20u, 0x01u, 0x0du, 0xb8u, 0u, 0x17u };
    const uint8_t different_as_addr[16] = { 0x20u, 0x01u, 0x0du, 0xb8u, 0u, 0x18u };
    const uint8_t missing_dest[16] = { 0x20u, 0x01u, 0x0du, 0xb8u, 0u, 0x16u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 1u };
    const uint8_t wrong_type_dest[16] = { 0x20u, 0x01u, 0x0du, 0xb8u, 0u, 0x17u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 1u };
    const uint8_t different_as_dest[16] = { 0x20u, 0x01u, 0x0du, 0xb8u, 0u, 0x18u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 1u };
    libbgp_rib6_route_t missing_low_med = route6(p6(missing_addr, 48u), 1u, next_hop);
    libbgp_rib6_route_t missing_older = route6(p6(missing_addr, 48u), 2u, next_hop);
    libbgp_rib6_route_t wrong_type_low_med = route6(p6(wrong_type_addr, 48u), 3u, next_hop);
    libbgp_rib6_route_t wrong_type_older = route6(p6(wrong_type_addr, 48u), 4u, next_hop);
    libbgp_rib6_route_t different_as_low_med = route6(p6(different_as_addr, 48u), 5u, next_hop);
    libbgp_rib6_route_t different_as_older = route6(p6(different_as_addr, 48u), 6u, next_hop);
    libbgp_pattr_t *wrong_type = libbgp_pattr_new(LIBBGP_PATTR_ORIGIN);
    libbgp_pattr_t *low_path = test_as_path_attr(65010u, 65100u);
    libbgp_pattr_t *older_path = test_as_path_attr(65020u, 65200u);
    libbgp_pattr_t *wrong_attrs[1];
    libbgp_pattr_t *low_attrs[1];
    libbgp_pattr_t *older_attrs[1];

    LIBBGP_ASSERT(wrong_type != NULL);
    wrong_attrs[0] = wrong_type;
    low_attrs[0] = low_path;
    older_attrs[0] = older_path;
    missing_low_med.med = 10u;
    missing_low_med.update_id = 20u;
    missing_older.med = 100u;
    missing_older.update_id = 10u;
    wrong_type_low_med.med = 10u;
    wrong_type_low_med.update_id = 20u;
    wrong_type_low_med.attrs = wrong_attrs;
    wrong_type_low_med.attr_count = 1u;
    wrong_type_older.med = 100u;
    wrong_type_older.update_id = 10u;
    wrong_type_older.attrs = wrong_attrs;
    wrong_type_older.attr_count = 1u;
    different_as_low_med.med = 10u;
    different_as_low_med.update_id = 20u;
    different_as_low_med.attrs = low_attrs;
    different_as_low_med.attr_count = 1u;
    different_as_older.med = 100u;
    different_as_older.update_id = 10u;
    different_as_older.attrs = older_attrs;
    different_as_older.attr_count = 1u;

    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_rib6_init(&rib));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_rib6_insert(&rib, &missing_low_med));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_rib6_insert(&rib, &missing_older));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_rib6_insert(&rib, &wrong_type_low_med));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_rib6_insert(&rib, &wrong_type_older));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_rib6_insert(&rib, &different_as_low_med));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_rib6_insert(&rib, &different_as_older));
    assert_rib6_best_source(&rib, missing_dest, 2u);
    assert_rib6_best_source(&rib, wrong_type_dest, 4u);
    assert_rib6_best_source(&rib, different_as_dest, 6u);

    libbgp_rib6_destroy(&rib);
    libbgp_pattr_unref(wrong_type);
    libbgp_pattr_unref(low_path);
    libbgp_pattr_unref(older_path);
}

LIBBGP_TEST(rib6_neighbor_as_uses_first_as_sequence_segment)
{
    libbgp_rib6_t rib;
    const uint8_t prefix_addr[16] = { 0x20u, 0x01u, 0x0du, 0xb8u, 0u, 0x19u };
    const uint8_t dest[16] = { 0x20u, 0x01u, 0x0du, 0xb8u, 0u, 0x19u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 1u };
    const uint8_t next_hop[16] = { 0x20u, 0x01u, 0x0du, 0xb8u, 0xffu, 0x19u };
    libbgp_prefix6_t prefix = p6(prefix_addr, 48u);
    libbgp_rib6_route_t high_med = route6(prefix, 1u, next_hop);
    libbgp_rib6_route_t low_med = route6(prefix, 2u, next_hop);
    libbgp_pattr_t *high_path = test_as_path_attr_with_segments(1u, 65099u, 2u, 65030u);
    libbgp_pattr_t *low_path = test_as_path_attr_with_segments(1u, 65098u, 2u, 65030u);
    libbgp_pattr_t *high_attrs[1];
    libbgp_pattr_t *low_attrs[1];

    high_attrs[0] = high_path;
    low_attrs[0] = low_path;
    high_med.med = 100u;
    high_med.update_id = 10u;
    high_med.attrs = high_attrs;
    high_med.attr_count = 1u;
    low_med.med = 10u;
    low_med.update_id = 20u;
    low_med.attrs = low_attrs;
    low_med.attr_count = 1u;

    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_rib6_init(&rib));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_rib6_insert(&rib, &high_med));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_rib6_insert(&rib, &low_med));
    assert_rib6_best_source(&rib, dest, 2u);

    libbgp_rib6_destroy(&rib);
    libbgp_pattr_unref(high_path);
    libbgp_pattr_unref(low_path);
}

LIBBGP_TEST(rib6_insert_defaults_local_pref_and_update_id)
{
    libbgp_rib6_t rib;
    const uint8_t prefix_addr[16] = { 0x20u, 0x01u, 0x0du, 0xb8u, 0u, 0x1au };
    const uint8_t dest[16] = { 0x20u, 0x01u, 0x0du, 0xb8u, 0u, 0x1au, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 1u };
    const uint8_t next_hop[16] = { 0x20u, 0x01u, 0x0du, 0xb8u, 0xffu, 0x1au };
    libbgp_rib6_route_t route = route6(p6(prefix_addr, 48u), 101u, next_hop);
    const libbgp_rib6_route_t *found = NULL;
    uint64_t update_id = 0u;

    route.local_pref = 0u;
    route.update_id = 0u;

    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_rib6_init(&rib));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, bgp_rib6_insert_save_replaced(&rib, &route, NULL, NULL, &update_id));
    LIBBGP_ASSERT(update_id != 0u);
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_rib6_lookup(&rib, dest, &found));
    LIBBGP_ASSERT(found != NULL);
    LIBBGP_ASSERT_EQ_U64(100u, found->local_pref);
    LIBBGP_ASSERT_EQ_U64(update_id, found->update_id);

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

LIBBGP_TEST(rib4_and_rib6_change_kind_values_match)
{
    LIBBGP_ASSERT_EQ_I64(0, BGP_RIB_CHANGE_NO_BEST_CHANGE);
    LIBBGP_ASSERT_EQ_I64(BGP_RIB_CHANGE_NO_BEST_CHANGE + 1, BGP_RIB_CHANGE_NEW_BEST);
    LIBBGP_ASSERT_EQ_I64(BGP_RIB_CHANGE_NEW_BEST + 1, BGP_RIB_CHANGE_REPLACEMENT_BEST);
    LIBBGP_ASSERT_EQ_I64(BGP_RIB_CHANGE_REPLACEMENT_BEST + 1, BGP_RIB_CHANGE_UNREACHABLE);
}

LIBBGP_TEST(rib4_and_rib6_best_path_parity_for_core_tie_breakers)
{
    libbgp_rib4_t rib4;
    libbgp_rib6_t rib6;
    libbgp_prefix4_t pref4 = p4(198u, 51u, 120u, 0u, 24u);
    const uint8_t pref6_addr[16] = { 0x20u, 0x01u, 0x0du, 0xb8u, 0u, 0x70u };
    const uint8_t dest6[16] = { 0x20u, 0x01u, 0x0du, 0xb8u, 0u, 0x70u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 1u };
    const uint8_t next_hop6[16] = { 0x20u, 0x01u, 0x0du, 0xb8u, 0xffu, 0x70u };
    libbgp_prefix6_t pref6 = p6(pref6_addr, 48u);
    libbgp_rib4_route_t old_med4 = route4(pref4, 1u);
    libbgp_rib4_route_t low_med4 = route4(pref4, 2u);
    libbgp_rib4_route_t better_pref4 = route4(pref4, 3u);
    libbgp_rib4_route_t better_origin4 = route4(pref4, 4u);
    libbgp_rib6_route_t old_med6 = route6(pref6, 1u, next_hop6);
    libbgp_rib6_route_t low_med6 = route6(pref6, 2u, next_hop6);
    libbgp_rib6_route_t better_pref6 = route6(pref6, 3u, next_hop6);
    libbgp_rib6_route_t better_origin6 = route6(pref6, 4u, next_hop6);
    libbgp_pattr_t *old_path = test_as_path_attr(65070u, 65100u);
    libbgp_pattr_t *low_path = test_as_path_attr(65070u, 65200u);
    libbgp_pattr_t *old_attrs[1];
    libbgp_pattr_t *low_attrs[1];

    old_attrs[0] = old_path;
    low_attrs[0] = low_path;

    old_med4.local_pref = 200u;
    old_med4.origin = 1u;
    old_med4.med = 100u;
    old_med4.attrs = old_attrs;
    old_med4.attr_count = 1u;
    low_med4.local_pref = 200u;
    low_med4.origin = 1u;
    low_med4.med = 10u;
    low_med4.attrs = low_attrs;
    low_med4.attr_count = 1u;
    better_pref4.local_pref = 250u;
    better_pref4.origin = 2u;
    better_origin4.local_pref = 250u;
    better_origin4.origin = 0u;

    old_med6.local_pref = old_med4.local_pref;
    old_med6.origin = old_med4.origin;
    old_med6.med = old_med4.med;
    old_med6.attrs = old_attrs;
    old_med6.attr_count = 1u;
    low_med6.local_pref = low_med4.local_pref;
    low_med6.origin = low_med4.origin;
    low_med6.med = low_med4.med;
    low_med6.attrs = low_attrs;
    low_med6.attr_count = 1u;
    better_pref6.local_pref = better_pref4.local_pref;
    better_pref6.origin = better_pref4.origin;
    better_origin6.local_pref = better_origin4.local_pref;
    better_origin6.origin = better_origin4.origin;

    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_rib4_init(&rib4));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_rib6_init(&rib6));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_rib4_insert(&rib4, &old_med4));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_rib4_insert(&rib4, &low_med4));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_rib6_insert(&rib6, &old_med6));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_rib6_insert(&rib6, &low_med6));
    assert_rib4_best_source(&rib4, ip4(198u, 51u, 120u, 1u), 2u);
    assert_rib6_best_source(&rib6, dest6, 2u);

    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_rib4_insert(&rib4, &better_pref4));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_rib6_insert(&rib6, &better_pref6));
    assert_rib4_best_source(&rib4, ip4(198u, 51u, 120u, 1u), 3u);
    assert_rib6_best_source(&rib6, dest6, 3u);

    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_rib4_insert(&rib4, &better_origin4));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_rib6_insert(&rib6, &better_origin6));
    assert_rib4_best_source(&rib4, ip4(198u, 51u, 120u, 1u), 4u);
    assert_rib6_best_source(&rib6, dest6, 4u);

    libbgp_rib4_destroy(&rib4);
    libbgp_rib6_destroy(&rib6);
    libbgp_pattr_unref(old_path);
    libbgp_pattr_unref(low_path);
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

LIBBGP_TEST(rib4_insert_allocation_failures_preserve_existing_routes)
{
    libbgp_rib4_t rib;
    libbgp_prefix4_t first_prefix = p4(10u, 50u, 0u, 0u, 24u);
    libbgp_prefix4_t second_prefix = p4(10u, 50u, 1u, 0u, 24u);
    libbgp_rib4_route_t first = route4(first_prefix, 51u);
    libbgp_rib4_route_t second = route4(second_prefix, 52u);
    libbgp_pattr_t *attr = libbgp_pattr_new(LIBBGP_PATTR_ORIGIN);
    libbgp_pattr_t *attrs[1];
    const libbgp_rib4_route_t *found = NULL;
    fail_after_alloc_ctx_t fail_ctx;
    libbgp_alloc_t fail_alloc;
    int rc;

    LIBBGP_ASSERT(attr != NULL);
    attrs[0] = attr;
    second.attrs = attrs;
    second.attr_count = 1u;

    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_rib4_init(&rib));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_rib4_insert(&rib, &first));

    fail_ctx.calls = 0u;
    fail_ctx.fail_at = 1u;
    fail_alloc = fail_after_alloc_make(&fail_ctx);
    libbgp_set_alloc(&fail_alloc);
    rc = libbgp_rib4_insert(&rib, &second);
    libbgp_set_alloc(NULL);
    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_NOMEM, rc);
    LIBBGP_ASSERT_EQ_U64(1u, fail_ctx.calls);
    LIBBGP_ASSERT_EQ_U64(1u, libbgp_rib4_route_count(&rib));
    LIBBGP_ASSERT_EQ_U64(1u, attr->refcount);

    fail_ctx.calls = 0u;
    fail_ctx.fail_at = 2u;
    fail_alloc = fail_after_alloc_make(&fail_ctx);
    libbgp_set_alloc(&fail_alloc);
    rc = libbgp_rib4_insert(&rib, &second);
    libbgp_set_alloc(NULL);
    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_NOMEM, rc);
    LIBBGP_ASSERT_EQ_U64(2u, fail_ctx.calls);
    LIBBGP_ASSERT_EQ_U64(1u, libbgp_rib4_route_count(&rib));
    LIBBGP_ASSERT_EQ_U64(1u, attr->refcount);

    fail_ctx.calls = 0u;
    fail_ctx.fail_at = 3u;
    fail_alloc = fail_after_alloc_make(&fail_ctx);
    libbgp_set_alloc(&fail_alloc);
    rc = libbgp_rib4_insert(&rib, &second);
    libbgp_set_alloc(NULL);
    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_NOMEM, rc);
    LIBBGP_ASSERT_EQ_U64(3u, fail_ctx.calls);
    LIBBGP_ASSERT_EQ_U64(1u, libbgp_rib4_route_count(&rib));
    LIBBGP_ASSERT_EQ_U64(1u, attr->refcount);

    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_rib4_lookup(&rib, ip4(10u, 50u, 0u, 1u), &found));
    LIBBGP_ASSERT(found != NULL);
    LIBBGP_ASSERT_EQ_U64(51u, found->source_router_id);
    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_NOT_FOUND, libbgp_rib4_lookup(&rib, ip4(10u, 50u, 1u, 1u), &found));

    libbgp_rib4_destroy(&rib);
    libbgp_pattr_unref(attr);
}

LIBBGP_TEST(rib4_snapshot_clone_rejects_invalid_and_clears_on_alloc_failure)
{
    libbgp_rib4_route_t src = route4(p4(10u, 51u, 0u, 0u, 24u), 51u);
    libbgp_rib4_route_t dst;
    libbgp_pattr_t *attr = libbgp_pattr_new(LIBBGP_PATTR_ORIGIN);
    libbgp_pattr_t *attrs[1];
    fail_after_alloc_ctx_t fail_ctx = { 0u, 1u };
    libbgp_alloc_t fail_alloc = fail_after_alloc_make(&fail_ctx);
    int rc;

    LIBBGP_ASSERT(attr != NULL);
    attrs[0] = attr;
    src.attrs = attrs;
    src.attr_count = 1u;
    memset(&dst, 0xff, sizeof(dst));

    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_INVALID, bgp_rib4_route_snapshot_clone(NULL, &dst));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_INVALID, bgp_rib4_route_snapshot_clone(&src, NULL));
    src.attrs = NULL;
    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_INVALID, bgp_rib4_route_snapshot_clone(&src, &dst));
    src.attrs = attrs;

    libbgp_set_alloc(&fail_alloc);
    rc = bgp_rib4_route_snapshot_clone(&src, &dst);
    libbgp_set_alloc(NULL);
    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_NOMEM, rc);
    LIBBGP_ASSERT_EQ_U64(1u, fail_ctx.calls);
    LIBBGP_ASSERT_EQ_U64(0u, dst.attr_count);
    LIBBGP_ASSERT(dst.attrs == NULL);
    LIBBGP_ASSERT_EQ_U64(1u, attr->refcount);

    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, bgp_rib4_route_snapshot_clone(&src, &dst));
    LIBBGP_ASSERT_EQ_U64(1u, dst.attr_count);
    LIBBGP_ASSERT_EQ_U64(2u, attr->refcount);
    bgp_rib4_route_snapshot_destroy(&dst);
    LIBBGP_ASSERT_EQ_U64(1u, attr->refcount);
    bgp_rib4_route_snapshot_destroy(NULL);
    libbgp_pattr_unref(attr);
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

LIBBGP_TEST(rib6_insert_allocation_failures_preserve_existing_routes)
{
    libbgp_rib6_t rib;
    const uint8_t first_addr[16] = { 0x20u, 0x01u, 0x0du, 0xb8u, 0u, 0x50u };
    const uint8_t second_addr[16] = { 0x20u, 0x01u, 0x0du, 0xb8u, 0u, 0x51u };
    const uint8_t first_dest[16] = { 0x20u, 0x01u, 0x0du, 0xb8u, 0u, 0x50u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 1u };
    const uint8_t second_dest[16] = { 0x20u, 0x01u, 0x0du, 0xb8u, 0u, 0x51u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 1u };
    const uint8_t next_hop[16] = { 0x20u, 0x01u, 0x0du, 0xb8u, 0xffu, 0x50u };
    libbgp_rib6_route_t first = route6(p6(first_addr, 48u), 51u, next_hop);
    libbgp_rib6_route_t second = route6(p6(second_addr, 48u), 52u, next_hop);
    libbgp_pattr_t *attr = libbgp_pattr_new(LIBBGP_PATTR_ORIGIN);
    libbgp_pattr_t *attrs[1];
    const libbgp_rib6_route_t *found = NULL;
    fail_after_alloc_ctx_t fail_ctx;
    libbgp_alloc_t fail_alloc;
    int rc;

    LIBBGP_ASSERT(attr != NULL);
    attrs[0] = attr;
    second.attrs = attrs;
    second.attr_count = 1u;

    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_rib6_init(&rib));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_rib6_insert(&rib, &first));

    fail_ctx.calls = 0u;
    fail_ctx.fail_at = 1u;
    fail_alloc = fail_after_alloc_make(&fail_ctx);
    libbgp_set_alloc(&fail_alloc);
    rc = libbgp_rib6_insert(&rib, &second);
    libbgp_set_alloc(NULL);
    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_NOMEM, rc);
    LIBBGP_ASSERT_EQ_U64(1u, fail_ctx.calls);
    LIBBGP_ASSERT_EQ_U64(1u, libbgp_rib6_route_count(&rib));
    LIBBGP_ASSERT_EQ_U64(1u, attr->refcount);

    fail_ctx.calls = 0u;
    fail_ctx.fail_at = 2u;
    fail_alloc = fail_after_alloc_make(&fail_ctx);
    libbgp_set_alloc(&fail_alloc);
    rc = libbgp_rib6_insert(&rib, &second);
    libbgp_set_alloc(NULL);
    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_NOMEM, rc);
    LIBBGP_ASSERT_EQ_U64(2u, fail_ctx.calls);
    LIBBGP_ASSERT_EQ_U64(1u, libbgp_rib6_route_count(&rib));
    LIBBGP_ASSERT_EQ_U64(1u, attr->refcount);

    fail_ctx.calls = 0u;
    fail_ctx.fail_at = 3u;
    fail_alloc = fail_after_alloc_make(&fail_ctx);
    libbgp_set_alloc(&fail_alloc);
    rc = libbgp_rib6_insert(&rib, &second);
    libbgp_set_alloc(NULL);
    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_NOMEM, rc);
    LIBBGP_ASSERT_EQ_U64(3u, fail_ctx.calls);
    LIBBGP_ASSERT_EQ_U64(1u, libbgp_rib6_route_count(&rib));
    LIBBGP_ASSERT_EQ_U64(1u, attr->refcount);

    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_rib6_lookup(&rib, first_dest, &found));
    LIBBGP_ASSERT(found != NULL);
    LIBBGP_ASSERT_EQ_U64(51u, found->source_router_id);
    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_NOT_FOUND, libbgp_rib6_lookup(&rib, second_dest, &found));

    libbgp_rib6_destroy(&rib);
    libbgp_pattr_unref(attr);
}

LIBBGP_TEST(rib6_snapshot_clone_rejects_invalid_and_clears_on_alloc_failure)
{
    const uint8_t prefix_addr[16] = { 0x20u, 0x01u, 0x0du, 0xb8u, 0u, 0x52u };
    const uint8_t next_hop[16] = { 0x20u, 0x01u, 0x0du, 0xb8u, 0xffu, 0x52u };
    libbgp_rib6_route_t src = route6(p6(prefix_addr, 48u), 52u, next_hop);
    libbgp_rib6_route_t dst;
    libbgp_pattr_t *attr = libbgp_pattr_new(LIBBGP_PATTR_ORIGIN);
    libbgp_pattr_t *attrs[1];
    fail_after_alloc_ctx_t fail_ctx = { 0u, 1u };
    libbgp_alloc_t fail_alloc = fail_after_alloc_make(&fail_ctx);
    int rc;

    LIBBGP_ASSERT(attr != NULL);
    attrs[0] = attr;
    src.attrs = attrs;
    src.attr_count = 1u;
    memset(&dst, 0xff, sizeof(dst));

    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_INVALID, bgp_rib6_route_snapshot_clone(NULL, &dst));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_INVALID, bgp_rib6_route_snapshot_clone(&src, NULL));
    src.attrs = NULL;
    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_INVALID, bgp_rib6_route_snapshot_clone(&src, &dst));
    src.attrs = attrs;

    libbgp_set_alloc(&fail_alloc);
    rc = bgp_rib6_route_snapshot_clone(&src, &dst);
    libbgp_set_alloc(NULL);
    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_NOMEM, rc);
    LIBBGP_ASSERT_EQ_U64(1u, fail_ctx.calls);
    LIBBGP_ASSERT_EQ_U64(0u, dst.attr_count);
    LIBBGP_ASSERT(dst.attrs == NULL);
    LIBBGP_ASSERT_EQ_U64(1u, attr->refcount);

    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, bgp_rib6_route_snapshot_clone(&src, &dst));
    LIBBGP_ASSERT_EQ_U64(1u, dst.attr_count);
    LIBBGP_ASSERT_EQ_U64(2u, attr->refcount);
    bgp_rib6_route_snapshot_destroy(&dst);
    LIBBGP_ASSERT_EQ_U64(1u, attr->refcount);
    bgp_rib6_route_snapshot_destroy(NULL);
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

LIBBGP_TEST(rib4_rejects_invalid_args_and_stops_foreach_route)
{
    libbgp_rib4_t rib;
    libbgp_rib4_t empty;
    libbgp_prefix4_t prefix = p4(10u, 40u, 0u, 0u, 24u);
    libbgp_rib4_route_t route = route4(prefix, 11u);
    libbgp_rib4_route_t invalid = route4(prefix, 12u);
    const libbgp_rib4_route_t *found = NULL;
    rib4_iter_count_ctx_t ctx;
    bool exact_found = true;
    libbgp_rib4_route_t snapshot;

    memset(&empty, 0, sizeof(empty));
    memset(&ctx, 0, sizeof(ctx));
    memset(&snapshot, 0xff, sizeof(snapshot));
    ctx.limit = 1u;
    invalid.attr_count = 1u;
    invalid.attrs = NULL;

    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_INVALID, libbgp_rib4_init(NULL));
    libbgp_rib4_destroy(NULL);
    LIBBGP_ASSERT_EQ_U64(0u, libbgp_rib4_route_count(NULL));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_INVALID, libbgp_rib4_insert(NULL, &route));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_INVALID, libbgp_rib4_insert(&empty, &route));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_INVALID, libbgp_rib4_lookup(NULL, ip4(10u, 40u, 0u, 1u), &found));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_INVALID, libbgp_rib4_lookup(&empty, ip4(10u, 40u, 0u, 1u), NULL));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_INVALID, libbgp_rib4_withdraw(&empty, 11u, NULL));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_INVALID, libbgp_rib4_discard(&empty, 11u));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_INVALID, bgp_rib4_foreach_route(&empty, record_rib4_source, &ctx));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_INVALID, bgp_rib4_foreach_best_route(&empty, record_rib4_source, &ctx));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_INVALID, bgp_rib4_best_exact_clone(&empty, &prefix, &snapshot, &exact_found));
    LIBBGP_ASSERT(!exact_found);
    LIBBGP_ASSERT_EQ_U64(0u, snapshot.attr_count);

    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_rib4_init(&rib));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_INVALID, libbgp_rib4_insert_local(&rib, NULL, 0u, 0));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_INVALID, libbgp_rib4_insert(&rib, NULL));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_INVALID, libbgp_rib4_insert(&rib, &invalid));
    invalid = route4(prefix, 12u);
    invalid.prefix.len = 33u;
    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_INVALID, libbgp_rib4_insert(&rib, &invalid));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_NOT_FOUND, libbgp_rib4_withdraw(&rib, 11u, &prefix));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_INVALID, bgp_rib4_foreach_route(&rib, NULL, &ctx));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_INVALID, bgp_rib4_foreach_best_route(&rib, NULL, &ctx));

    invalid.prefix = prefix;
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_rib4_insert(&rib, &invalid));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_rib4_lookup(&rib, ip4(10u, 40u, 0u, 1u), &found));
    ((libbgp_rib4_route_t *)found)->prefix.len = 33u;
    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_NOT_FOUND, libbgp_rib4_lookup(&rib, ip4(10u, 40u, 0u, 1u), &found));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_rib4_withdraw(&rib, 12u, &invalid.prefix));

    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_rib4_insert(&rib, &route));
    route = route4(p4(10u, 40u, 1u, 0u, 24u), 12u);
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_rib4_insert(&rib, &route));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, bgp_rib4_foreach_route(&rib, record_rib4_source, &ctx));
    LIBBGP_ASSERT_EQ_U64(1u, ctx.count);

    libbgp_rib4_destroy(&rib);
}

LIBBGP_TEST(rib6_rejects_invalid_args_and_stops_foreach_route)
{
    libbgp_rib6_t rib;
    libbgp_rib6_t empty;
    const uint8_t prefix_addr[16] = { 0x20u, 0x01u, 0x0du, 0xb8u, 0u, 0x40u };
    const uint8_t dest[16] = { 0x20u, 0x01u, 0x0du, 0xb8u, 0u, 0x40u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 1u };
    const uint8_t next_hop[16] = { 0x20u, 0x01u, 0x0du, 0xb8u, 0xffu, 0x40u };
    libbgp_prefix6_t prefix = p6(prefix_addr, 48u);
    libbgp_rib6_route_t route = route6(prefix, 11u, next_hop);
    libbgp_rib6_route_t invalid = route6(prefix, 12u, next_hop);
    const libbgp_rib6_route_t *found = NULL;
    rib6_iter_count_ctx_t ctx;
    bool exact_found = true;
    libbgp_rib6_route_t snapshot;

    memset(&empty, 0, sizeof(empty));
    memset(&ctx, 0, sizeof(ctx));
    memset(&snapshot, 0xff, sizeof(snapshot));
    ctx.limit = 1u;
    invalid.attr_count = 1u;
    invalid.attrs = NULL;

    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_INVALID, libbgp_rib6_init(NULL));
    libbgp_rib6_destroy(NULL);
    LIBBGP_ASSERT_EQ_U64(0u, libbgp_rib6_route_count(NULL));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_INVALID, libbgp_rib6_insert(NULL, &route));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_INVALID, libbgp_rib6_insert(&empty, &route));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_INVALID, libbgp_rib6_lookup(NULL, dest, &found));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_INVALID, libbgp_rib6_lookup(&empty, NULL, &found));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_INVALID, libbgp_rib6_lookup(&empty, dest, NULL));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_INVALID, libbgp_rib6_withdraw(&empty, 11u, NULL));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_INVALID, libbgp_rib6_discard(&empty, 11u));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_INVALID, bgp_rib6_foreach_route(&empty, record_rib6_source, &ctx));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_INVALID, bgp_rib6_foreach_best_route(&empty, record_rib6_source, &ctx));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_INVALID, bgp_rib6_best_exact_clone(&empty, &prefix, &snapshot, &exact_found));
    LIBBGP_ASSERT(!exact_found);
    LIBBGP_ASSERT_EQ_U64(0u, snapshot.attr_count);

    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_rib6_init(&rib));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_INVALID, libbgp_rib6_insert_local(&rib, NULL, next_hop, 0));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_INVALID, libbgp_rib6_insert_local(&rib, &prefix, NULL, 0));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_INVALID, libbgp_rib6_insert(&rib, NULL));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_INVALID, libbgp_rib6_insert(&rib, &invalid));
    invalid = route6(prefix, 12u, next_hop);
    invalid.prefix.len = 129u;
    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_INVALID, libbgp_rib6_insert(&rib, &invalid));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_NOT_FOUND, libbgp_rib6_withdraw(&rib, 11u, &prefix));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_INVALID, bgp_rib6_foreach_route(&rib, NULL, &ctx));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_INVALID, bgp_rib6_foreach_best_route(&rib, NULL, &ctx));

    invalid.prefix = prefix;
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_rib6_insert(&rib, &invalid));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_rib6_lookup(&rib, dest, &found));
    ((libbgp_rib6_route_t *)found)->prefix.len = 129u;
    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_NOT_FOUND, libbgp_rib6_lookup(&rib, dest, &found));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_rib6_withdraw(&rib, 12u, &invalid.prefix));

    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_rib6_insert(&rib, &route));
    route = route6(p6(dest, 120u), 12u, next_hop);
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_rib6_insert(&rib, &route));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, bgp_rib6_foreach_route(&rib, record_rib6_source, &ctx));
    LIBBGP_ASSERT_EQ_U64(1u, ctx.count);

    libbgp_rib6_destroy(&rib);
}

LIBBGP_TEST(rib4_rejects_invalid_prefixes_on_local_clone_lookup_and_withdraw)
{
    libbgp_rib4_t rib;
    libbgp_prefix4_t invalid_prefix = p4(10u, 61u, 0u, 0u, 24u);
    libbgp_prefix4_t valid_prefix = p4(10u, 61u, 1u, 0u, 24u);
    libbgp_rib4_route_t route = route4(valid_prefix, 61u);
    const libbgp_rib4_route_t *found = NULL;
    libbgp_rib4_route_t snapshot;
    bool exact_found = true;

    invalid_prefix.len = 33u;
    memset(&snapshot, 0xff, sizeof(snapshot));

    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_rib4_init(&rib));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_INVALID, libbgp_rib4_insert_local(&rib, &invalid_prefix, ip4(192u, 0u, 2u, 61u), 1));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_NOT_FOUND, libbgp_rib4_lookup(&rib, ip4(10u, 61u, 0u, 1u), &found));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_NOT_FOUND, libbgp_rib4_withdraw(&rib, 61u, &invalid_prefix));
    exact_found = true;
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, bgp_rib4_best_exact_clone(&rib, &invalid_prefix, &snapshot, &exact_found));
    LIBBGP_ASSERT(!exact_found);

    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_rib4_insert(&rib, &route));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_INVALID, bgp_rib4_best_exact_clone(NULL, &valid_prefix, &snapshot, &exact_found));
    LIBBGP_ASSERT(!exact_found);
    LIBBGP_ASSERT_EQ_U64(0u, snapshot.attr_count);
    exact_found = true;
    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_INVALID, bgp_rib4_best_exact_clone(&rib, NULL, &snapshot, &exact_found));
    LIBBGP_ASSERT(!exact_found);
    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_INVALID, bgp_rib4_best_exact_clone(&rib, &valid_prefix, NULL, &exact_found));
    LIBBGP_ASSERT(!exact_found);
    exact_found = false;
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, bgp_rib4_best_exact_clone(&rib, &valid_prefix, &snapshot, &exact_found));
    LIBBGP_ASSERT(exact_found);
    LIBBGP_ASSERT_EQ_U64(61u, snapshot.source_router_id);
    bgp_rib4_route_snapshot_destroy(&snapshot);
    libbgp_rib4_destroy(&rib);
}

LIBBGP_TEST(rib6_rejects_invalid_prefixes_on_local_clone_lookup_and_withdraw)
{
    libbgp_rib6_t rib;
    const uint8_t addr[16] = { 0x20u, 0x01u, 0x0du, 0xb8u, 0u, 0x62u };
    const uint8_t valid_addr[16] = { 0x20u, 0x01u, 0x0du, 0xb8u, 0u, 0x63u };
    const uint8_t dest[16] = { 0x20u, 0x01u, 0x0du, 0xb8u, 0u, 0x62u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 1u };
    const uint8_t next_hop[16] = { 0x20u, 0x01u, 0x0du, 0xb8u, 0xffu, 0x62u };
    libbgp_prefix6_t invalid_prefix = p6(addr, 48u);
    libbgp_prefix6_t valid_prefix = p6(valid_addr, 48u);
    libbgp_rib6_route_t route = route6(valid_prefix, 63u, next_hop);
    const libbgp_rib6_route_t *found = NULL;
    libbgp_rib6_route_t snapshot;
    bool exact_found = true;

    invalid_prefix.len = 129u;
    memset(&snapshot, 0xff, sizeof(snapshot));

    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_rib6_init(&rib));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_INVALID, libbgp_rib6_insert_local(&rib, &invalid_prefix, next_hop, 1));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_NOT_FOUND, libbgp_rib6_lookup(&rib, dest, &found));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_NOT_FOUND, libbgp_rib6_withdraw(&rib, 62u, &invalid_prefix));
    exact_found = true;
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, bgp_rib6_best_exact_clone(&rib, &invalid_prefix, &snapshot, &exact_found));
    LIBBGP_ASSERT(!exact_found);

    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_rib6_insert(&rib, &route));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_INVALID, bgp_rib6_best_exact_clone(NULL, &valid_prefix, &snapshot, &exact_found));
    LIBBGP_ASSERT(!exact_found);
    LIBBGP_ASSERT_EQ_U64(0u, snapshot.attr_count);
    exact_found = true;
    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_INVALID, bgp_rib6_best_exact_clone(&rib, NULL, &snapshot, &exact_found));
    LIBBGP_ASSERT(!exact_found);
    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_INVALID, bgp_rib6_best_exact_clone(&rib, &valid_prefix, NULL, &exact_found));
    LIBBGP_ASSERT(!exact_found);
    exact_found = false;
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, bgp_rib6_best_exact_clone(&rib, &valid_prefix, &snapshot, &exact_found));
    LIBBGP_ASSERT(exact_found);
    LIBBGP_ASSERT_EQ_U64(63u, snapshot.source_router_id);
    bgp_rib6_route_snapshot_destroy(&snapshot);
    libbgp_rib6_destroy(&rib);
}

LIBBGP_TEST(rib4_foreach_empty_tables_accept_valid_callback)
{
    libbgp_rib4_t rib;
    rib4_iter_count_ctx_t ctx;

    memset(&ctx, 0, sizeof(ctx));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_rib4_init(&rib));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, bgp_rib4_foreach_route(&rib, record_rib4_source, &ctx));
    LIBBGP_ASSERT_EQ_U64(0u, ctx.count);
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, bgp_rib4_foreach_best_route(&rib, record_rib4_source, &ctx));
    LIBBGP_ASSERT_EQ_U64(0u, ctx.count);
    libbgp_rib4_destroy(&rib);
}

LIBBGP_TEST(rib6_foreach_empty_tables_accept_valid_callback)
{
    libbgp_rib6_t rib;
    rib6_iter_count_ctx_t ctx;

    memset(&ctx, 0, sizeof(ctx));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_rib6_init(&rib));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, bgp_rib6_foreach_route(&rib, record_rib6_source, &ctx));
    LIBBGP_ASSERT_EQ_U64(0u, ctx.count);
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, bgp_rib6_foreach_best_route(&rib, record_rib6_source, &ctx));
    LIBBGP_ASSERT_EQ_U64(0u, ctx.count);
    libbgp_rib6_destroy(&rib);
}

LIBBGP_TEST(rib4_saved_route_update_restore_and_conditional_withdraw)
{
    libbgp_rib4_t rib;
    libbgp_prefix4_t prefix = p4(10u, 41u, 0u, 0u, 24u);
    libbgp_rib4_route_t original = route4(prefix, 41u);
    libbgp_rib4_route_t replacement = route4(prefix, 41u);
    bgp_rib4_saved_route_t saved;
    bool had_route = true;
    uint64_t inserted_id = 0u;
    uint64_t saved_id = 0u;
    uint64_t exact_id = 0u;
    const libbgp_rib4_route_t *found = NULL;

    memset(&saved, 0, sizeof(saved));
    original.weight = 10;
    replacement.weight = 99;
    replacement.update_id = 100u;

    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_INVALID, bgp_rib4_saved_route_update_id(NULL, &saved_id));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_INVALID, bgp_rib4_saved_route_update_id(&saved, NULL));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_NOT_FOUND, bgp_rib4_saved_route_update_id(&saved, &saved_id));
    LIBBGP_ASSERT_EQ_U64(0u, saved_id);

    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_rib4_init(&rib));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, bgp_rib4_insert_save_replaced(&rib, &original, NULL, NULL, &inserted_id));
    LIBBGP_ASSERT(inserted_id != 0u);
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, bgp_rib4_exact_update_id(&rib, 41u, &prefix, &exact_id));
    LIBBGP_ASSERT_EQ_U64(inserted_id, exact_id);
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, bgp_rib4_exact_update_id(&rib, 41u, &prefix, NULL));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_NOT_FOUND, bgp_rib4_exact_update_id(&rib, 99u, &prefix, &exact_id));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_INVALID, bgp_rib4_withdraw_exact_if_update_id(&rib, 41u, &prefix, 0u));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, bgp_rib4_withdraw_exact_if_update_id(&rib, 41u, &prefix, inserted_id + 1u));
    LIBBGP_ASSERT_EQ_U64(1u, libbgp_rib4_route_count(&rib));

    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, bgp_rib4_withdraw_exact_save(&rib, 99u, &prefix, &saved, &had_route));
    LIBBGP_ASSERT(!had_route);
    LIBBGP_ASSERT(saved.entry == NULL);
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, bgp_rib4_withdraw_exact_save(&rib, 41u, &prefix, &saved, &had_route));
    LIBBGP_ASSERT(had_route);
    LIBBGP_ASSERT(saved.entry != NULL);
    LIBBGP_ASSERT_EQ_U64(0u, libbgp_rib4_route_count(&rib));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, bgp_rib4_saved_route_update_id(&saved, &saved_id));
    LIBBGP_ASSERT_EQ_U64(inserted_id, saved_id);

    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, bgp_rib4_restore_saved_if_absent(&rib, 41u, &saved));
    LIBBGP_ASSERT(saved.entry == NULL);
    LIBBGP_ASSERT_EQ_U64(1u, libbgp_rib4_route_count(&rib));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_NOT_FOUND, bgp_rib4_saved_route_update_id(&saved, &saved_id));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, bgp_rib4_withdraw_exact_save(&rib, 41u, &prefix, &saved, &had_route));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_rib4_insert(&rib, &replacement));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, bgp_rib4_restore_saved_if_absent(&rib, 41u, &saved));
    LIBBGP_ASSERT(saved.entry != NULL);
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_rib4_lookup(&rib, ip4(10u, 41u, 0u, 1u), &found));
    LIBBGP_ASSERT_EQ_I64(99, found->weight);
    bgp_rib4_saved_route_destroy(&saved);

    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, bgp_rib4_withdraw_exact_if_update_id(&rib, 41u, &prefix, inserted_id));
    LIBBGP_ASSERT_EQ_U64(1u, libbgp_rib4_route_count(&rib));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, bgp_rib4_exact_update_id(&rib, 41u, &prefix, &exact_id));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, bgp_rib4_withdraw_exact_if_update_id(&rib, 41u, &prefix, exact_id));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_NOT_FOUND, bgp_rib4_withdraw_exact_if_update_id(&rib, 41u, &prefix, exact_id));
    libbgp_rib4_destroy(&rib);
}

LIBBGP_TEST(rib6_withdraw_track_reports_unreachable_and_rejects_invalid_args)
{
    libbgp_rib6_t rib;
    const uint8_t prefix_addr[16] = { 0x20u, 0x01u, 0x0du, 0xb8u, 0u, 0x42u };
    const uint8_t next_hop[16] = { 0x20u, 0x01u, 0x0du, 0xb8u, 0xffu, 0x42u };
    libbgp_prefix6_t prefix = p6(prefix_addr, 48u);
    libbgp_rib6_route_t route = route6(prefix, 42u, next_hop);
    bgp_rib6_change_t change;

    change.kind = BGP_RIB_CHANGE_REPLACEMENT_BEST;
    change.best = &route;
    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_INVALID, bgp_rib6_withdraw_track_best(NULL, 42u, &prefix, &change));
    LIBBGP_ASSERT_EQ_I64(BGP_RIB_CHANGE_NO_BEST_CHANGE, change.kind);
    LIBBGP_ASSERT(change.best == NULL);

    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_rib6_init(&rib));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_INVALID, bgp_rib6_withdraw_track_best(&rib, 42u, NULL, &change));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_INVALID, bgp_rib6_withdraw_track_best(&rib, 42u, &prefix, NULL));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_rib6_insert(&rib, &route));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, bgp_rib6_withdraw_track_best(&rib, 42u, &prefix, &change));
    LIBBGP_ASSERT_EQ_I64(BGP_RIB_CHANGE_UNREACHABLE, change.kind);
    LIBBGP_ASSERT(change.best == NULL);
    LIBBGP_ASSERT_EQ_U64(0u, libbgp_rib6_route_count(&rib));
    libbgp_rib6_destroy(&rib);
}

LIBBGP_TEST(rib4_lookup_covers_default_exact_and_boundary_prefixes)
{
    libbgp_rib4_t rib;
    libbgp_prefix4_t default_prefix = p4(0u, 0u, 0u, 0u, 0u);
    libbgp_prefix4_t exact_prefix = p4(203u, 0u, 113u, 255u, 32u);
    libbgp_rib4_route_t default_route = route4(default_prefix, 80u);
    libbgp_rib4_route_t exact_route = route4(exact_prefix, 81u);
    const libbgp_rib4_route_t *found = NULL;

    default_route.local_pref = 50u;
    exact_route.local_pref = 200u;

    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_rib4_init(&rib));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_rib4_insert(&rib, &default_route));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_rib4_insert(&rib, &exact_route));

    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_rib4_lookup(&rib, ip4(198u, 51u, 100u, 9u), &found));
    LIBBGP_ASSERT(found != NULL);
    LIBBGP_ASSERT(libbgp_prefix4_eq(&default_prefix, &found->prefix));
    LIBBGP_ASSERT_EQ_U64(80u, found->source_router_id);

    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_rib4_lookup(&rib, ip4(203u, 0u, 113u, 255u), &found));
    LIBBGP_ASSERT(found != NULL);
    LIBBGP_ASSERT(libbgp_prefix4_eq(&exact_prefix, &found->prefix));
    LIBBGP_ASSERT_EQ_U64(81u, found->source_router_id);

    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_NOT_FOUND, libbgp_rib4_lookup_scoped(&rib, 99u, ip4(203u, 0u, 113u, 255u), &found));

    libbgp_rib4_destroy(&rib);
}

LIBBGP_TEST(rib6_lookup_covers_default_exact_and_boundary_prefixes)
{
    libbgp_rib6_t rib;
    static const uint8_t zero[16] = { 0u };
    static const uint8_t exact_addr[16] = { 0x20u, 0x01u, 0x0du, 0xb8u, 0xffu, 0xffu, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0xffu };
    static const uint8_t fallback_dest[16] = { 0x20u, 0x01u, 0x0du, 0xb9u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 1u };
    static const uint8_t next_hop[16] = { 0x20u, 0x01u, 0x0du, 0xb8u, 0xffu, 0xffu };
    libbgp_prefix6_t default_prefix = p6(zero, 0u);
    libbgp_prefix6_t exact_prefix = p6(exact_addr, 128u);
    libbgp_rib6_route_t default_route = route6(default_prefix, 82u, next_hop);
    libbgp_rib6_route_t exact_route = route6(exact_prefix, 83u, next_hop);
    const libbgp_rib6_route_t *found = NULL;

    default_route.local_pref = 50u;
    exact_route.local_pref = 200u;

    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_rib6_init(&rib));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_rib6_insert(&rib, &default_route));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_rib6_insert(&rib, &exact_route));

    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_rib6_lookup(&rib, fallback_dest, &found));
    LIBBGP_ASSERT(found != NULL);
    LIBBGP_ASSERT(libbgp_prefix6_eq(&default_prefix, &found->prefix));
    LIBBGP_ASSERT_EQ_U64(82u, found->source_router_id);

    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_rib6_lookup(&rib, exact_addr, &found));
    LIBBGP_ASSERT(found != NULL);
    LIBBGP_ASSERT(libbgp_prefix6_eq(&exact_prefix, &found->prefix));
    LIBBGP_ASSERT_EQ_U64(83u, found->source_router_id);

    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_NOT_FOUND, libbgp_rib6_lookup_scoped(&rib, 99u, exact_addr, &found));

    libbgp_rib6_destroy(&rib);
}

LIBBGP_TEST(rib4_lookup_radix_updates_after_withdraw_restore_and_discard)
{
    libbgp_rib4_t rib;
    libbgp_prefix4_t default_prefix = p4(0u, 0u, 0u, 0u, 0u);
    libbgp_prefix4_t broad_prefix = p4(10u, 91u, 0u, 0u, 16u);
    libbgp_prefix4_t exact_prefix = p4(10u, 91u, 2u, 3u, 32u);
    libbgp_rib4_route_t default_route = route4(default_prefix, 90u);
    libbgp_rib4_route_t broad_route = route4(broad_prefix, 91u);
    libbgp_rib4_route_t exact_route = route4(exact_prefix, 92u);
    bgp_rib4_saved_route_t saved;
    bool had_route = false;
    const libbgp_rib4_route_t *found = NULL;
    uint32_t dest = ip4(10u, 91u, 2u, 3u);

    memset(&saved, 0, sizeof(saved));

    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_rib4_init(&rib));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_rib4_insert(&rib, &default_route));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_rib4_insert(&rib, &broad_route));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_rib4_insert(&rib, &exact_route));

    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_rib4_lookup(&rib, dest, &found));
    LIBBGP_ASSERT_EQ_U64(92u, found->source_router_id);

    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, bgp_rib4_withdraw_exact_save(&rib, 92u, &exact_prefix, &saved, &had_route));
    LIBBGP_ASSERT(had_route);
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_rib4_lookup(&rib, dest, &found));
    LIBBGP_ASSERT_EQ_U64(91u, found->source_router_id);

    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, bgp_rib4_restore_saved_if_absent(&rib, 92u, &saved));
    LIBBGP_ASSERT(saved.entry == NULL);
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_rib4_lookup(&rib, dest, &found));
    LIBBGP_ASSERT_EQ_U64(92u, found->source_router_id);

    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_rib4_withdraw(&rib, 92u, &exact_prefix));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_rib4_lookup(&rib, dest, &found));
    LIBBGP_ASSERT_EQ_U64(91u, found->source_router_id);

    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_rib4_discard(&rib, 91u));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_rib4_lookup(&rib, dest, &found));
    LIBBGP_ASSERT_EQ_U64(90u, found->source_router_id);

    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_rib4_discard(&rib, 90u));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_NOT_FOUND, libbgp_rib4_lookup(&rib, dest, &found));

    bgp_rib4_saved_route_destroy(&saved);
    libbgp_rib4_destroy(&rib);
}

LIBBGP_TEST(rib6_lookup_radix_updates_partial_prefix_after_withdraw_and_discard)
{
    libbgp_rib6_t rib;
    static const uint8_t zero[16] = { 0u };
    static const uint8_t broad_addr[16] = { 0x20u, 0x01u, 0x0du, 0xb8u, 0u, 0x91u };
    static const uint8_t partial_addr[16] = { 0x20u, 0x01u, 0x0du, 0xb8u, 0u, 0x91u, 0u, 0u, 0x80u };
    static const uint8_t dest[16] = { 0x20u, 0x01u, 0x0du, 0xb8u, 0u, 0x91u, 0u, 0u, 0x80u, 0u, 0u, 0u, 0u, 0u, 0u, 1u };
    static const uint8_t next_hop[16] = { 0x20u, 0x01u, 0x0du, 0xb8u, 0xffu, 0x91u };
    libbgp_prefix6_t default_prefix = p6(zero, 0u);
    libbgp_prefix6_t broad_prefix = p6(broad_addr, 48u);
    libbgp_prefix6_t partial_prefix = p6(partial_addr, 65u);
    libbgp_rib6_route_t default_route = route6(default_prefix, 93u, next_hop);
    libbgp_rib6_route_t broad_route = route6(broad_prefix, 94u, next_hop);
    libbgp_rib6_route_t partial_route = route6(partial_prefix, 95u, next_hop);
    const libbgp_rib6_route_t *found = NULL;

    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_rib6_init(&rib));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_rib6_insert(&rib, &default_route));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_rib6_insert(&rib, &broad_route));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_rib6_insert(&rib, &partial_route));

    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_rib6_lookup(&rib, dest, &found));
    LIBBGP_ASSERT_EQ_U64(95u, found->source_router_id);

    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_rib6_withdraw(&rib, 95u, &partial_prefix));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_rib6_lookup(&rib, dest, &found));
    LIBBGP_ASSERT_EQ_U64(94u, found->source_router_id);

    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_rib6_discard(&rib, 94u));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_rib6_lookup(&rib, dest, &found));
    LIBBGP_ASSERT_EQ_U64(93u, found->source_router_id);

    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_rib6_discard(&rib, 93u));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_NOT_FOUND, libbgp_rib6_lookup(&rib, dest, &found));

    libbgp_rib6_destroy(&rib);
}

LIBBGP_TEST(rib4_insert_save_replaced_reports_replaced_route)
{
    libbgp_rib4_t rib;
    libbgp_prefix4_t prefix = p4(10u, 82u, 0u, 0u, 24u);
    libbgp_rib4_route_t old_route = route4(prefix, 82u);
    libbgp_rib4_route_t new_route = route4(prefix, 82u);
    bgp_rib4_saved_route_t replaced;
    bool had_replaced = true;
    uint64_t update_id = 0u;
    const libbgp_rib4_route_t *found = NULL;

    memset(&replaced, 0, sizeof(replaced));
    old_route.weight = 10;
    new_route.weight = 20;

    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_rib4_init(&rib));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, bgp_rib4_insert_save_replaced(&rib, &old_route, &replaced, &had_replaced, &update_id));
    LIBBGP_ASSERT(!had_replaced);
    LIBBGP_ASSERT(replaced.entry == NULL);

    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, bgp_rib4_insert_save_replaced(&rib, &new_route, &replaced, &had_replaced, &update_id));
    LIBBGP_ASSERT(had_replaced);
    LIBBGP_ASSERT(replaced.entry != NULL);
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_rib4_lookup(&rib, ip4(10u, 82u, 0u, 1u), &found));
    LIBBGP_ASSERT(found != NULL);
    LIBBGP_ASSERT_EQ_I64(20, found->weight);

    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_rib4_withdraw(&rib, 82u, &prefix));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, bgp_rib4_restore_saved_if_absent(&rib, 82u, &replaced));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_rib4_lookup(&rib, ip4(10u, 82u, 0u, 1u), &found));
    LIBBGP_ASSERT(found != NULL);
    LIBBGP_ASSERT_EQ_I64(10, found->weight);

    bgp_rib4_saved_route_destroy(&replaced);
    libbgp_rib4_destroy(&rib);
}

LIBBGP_TEST(rib6_insert_save_replaced_reports_replaced_route)
{
    libbgp_rib6_t rib;
    static const uint8_t prefix_addr[16] = { 0x20u, 0x01u, 0x0du, 0xb8u, 0u, 0x82u };
    static const uint8_t dest[16] = { 0x20u, 0x01u, 0x0du, 0xb8u, 0u, 0x82u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 1u };
    static const uint8_t next_hop[16] = { 0x20u, 0x01u, 0x0du, 0xb8u, 0xffu, 0x82u };
    libbgp_prefix6_t prefix = p6(prefix_addr, 48u);
    libbgp_rib6_route_t old_route = route6(prefix, 82u, next_hop);
    libbgp_rib6_route_t new_route = route6(prefix, 82u, next_hop);
    bgp_rib6_saved_route_t replaced;
    bool had_replaced = true;
    uint64_t update_id = 0u;
    const libbgp_rib6_route_t *found = NULL;

    memset(&replaced, 0, sizeof(replaced));
    old_route.weight = 10;
    new_route.weight = 20;

    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_rib6_init(&rib));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, bgp_rib6_insert_save_replaced(&rib, &old_route, &replaced, &had_replaced, &update_id));
    LIBBGP_ASSERT(!had_replaced);
    LIBBGP_ASSERT(replaced.entry == NULL);

    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, bgp_rib6_insert_save_replaced(&rib, &new_route, &replaced, &had_replaced, &update_id));
    LIBBGP_ASSERT(had_replaced);
    LIBBGP_ASSERT(replaced.entry != NULL);
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_rib6_lookup(&rib, dest, &found));
    LIBBGP_ASSERT(found != NULL);
    LIBBGP_ASSERT_EQ_I64(20, found->weight);

    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_rib6_withdraw(&rib, 82u, &prefix));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, bgp_rib6_restore_saved_if_absent(&rib, 82u, &replaced));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_rib6_lookup(&rib, dest, &found));
    LIBBGP_ASSERT(found != NULL);
    LIBBGP_ASSERT_EQ_I64(10, found->weight);

    bgp_rib6_saved_route_destroy(&replaced);
    libbgp_rib6_destroy(&rib);
}

LIBBGP_TEST(rib4_withdraw_track_reports_no_change_and_rejects_invalid_args)
{
    libbgp_rib4_t rib;
    libbgp_prefix4_t prefix = p4(10u, 83u, 0u, 0u, 24u);
    libbgp_rib4_route_t best = route4(prefix, 83u);
    libbgp_rib4_route_t backup = route4(prefix, 84u);
    bgp_rib4_change_t change;
    uint64_t update_id = 0u;

    best.local_pref = 200u;
    backup.local_pref = 100u;
    change.kind = BGP_RIB_CHANGE_REPLACEMENT_BEST;
    change.best = &best;
    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_INVALID, bgp_rib4_withdraw_track_best(NULL, 83u, &prefix, &change));
    LIBBGP_ASSERT_EQ_I64(BGP_RIB_CHANGE_NO_BEST_CHANGE, change.kind);
    LIBBGP_ASSERT(change.best == NULL);

    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_rib4_init(&rib));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_INVALID, bgp_rib4_withdraw_track_best(&rib, 83u, NULL, &change));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_INVALID, bgp_rib4_withdraw_track_best(&rib, 83u, &prefix, NULL));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, bgp_rib4_insert_track_best(&rib, &best, &change, &update_id));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, bgp_rib4_insert_track_best(&rib, &backup, &change, &update_id));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, bgp_rib4_withdraw_track_best(&rib, 84u, &prefix, &change));
    LIBBGP_ASSERT_EQ_I64(BGP_RIB_CHANGE_NO_BEST_CHANGE, change.kind);
    LIBBGP_ASSERT(change.best != NULL);
    LIBBGP_ASSERT_EQ_U64(83u, change.best->source_router_id);
    LIBBGP_ASSERT_EQ_U64(1u, libbgp_rib4_route_count(&rib));

    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_NOT_FOUND, bgp_rib4_withdraw_track_best(&rib, 99u, &prefix, &change));
    LIBBGP_ASSERT_EQ_I64(BGP_RIB_CHANGE_NO_BEST_CHANGE, change.kind);
    LIBBGP_ASSERT(change.best == NULL);
    LIBBGP_ASSERT_EQ_U64(1u, libbgp_rib4_route_count(&rib));
    libbgp_rib4_destroy(&rib);
}

LIBBGP_TEST(rib6_discard_empty_and_withdraw_missing_preserve_routes)
{
    libbgp_rib6_t rib;
    static const uint8_t prefix_addr[16] = { 0x20u, 0x01u, 0x0du, 0xb8u, 0u, 0x83u };
    static const uint8_t dest[16] = { 0x20u, 0x01u, 0x0du, 0xb8u, 0u, 0x83u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 1u };
    static const uint8_t next_hop[16] = { 0x20u, 0x01u, 0x0du, 0xb8u, 0xffu, 0x83u };
    libbgp_prefix6_t prefix = p6(prefix_addr, 48u);
    libbgp_rib6_route_t route = route6(prefix, 83u, next_hop);
    const libbgp_rib6_route_t *found = NULL;

    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_rib6_init(&rib));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_rib6_discard(&rib, 83u));
    LIBBGP_ASSERT_EQ_U64(0u, libbgp_rib6_route_count(&rib));

    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_rib6_insert(&rib, &route));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_NOT_FOUND, libbgp_rib6_withdraw(&rib, 84u, &prefix));
    LIBBGP_ASSERT_EQ_U64(1u, libbgp_rib6_route_count(&rib));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_rib6_lookup(&rib, dest, &found));
    LIBBGP_ASSERT(found != NULL);
    LIBBGP_ASSERT_EQ_U64(83u, found->source_router_id);

    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_rib6_discard(&rib, 84u));
    LIBBGP_ASSERT_EQ_U64(1u, libbgp_rib6_route_count(&rib));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_rib6_discard(&rib, 83u));
    LIBBGP_ASSERT_EQ_U64(0u, libbgp_rib6_route_count(&rib));
    libbgp_rib6_destroy(&rib);
}

LIBBGP_TEST(rib4_discard_empty_and_withdraw_missing_preserve_routes)
{
    /*
     * RFC basis: RFC 4271 §9.1.3 (route withdrawals apply to existing routes only).
     * Covered branches: rib4_withdraw_locked not-found path; libbgp_rib4_discard no-op path.
     * Expected result: withdrawing a missing route keeps existing best route unchanged.
     */
    libbgp_rib4_t rib;
    libbgp_prefix4_t prefix = p4(10u, 84u, 0u, 0u, 24u);
    libbgp_rib4_route_t route = route4(prefix, 84u);
    const libbgp_rib4_route_t *found = NULL;

    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_rib4_init(&rib));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_rib4_discard(&rib, 84u));
    LIBBGP_ASSERT_EQ_U64(0u, libbgp_rib4_route_count(&rib));

    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_rib4_insert(&rib, &route));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_NOT_FOUND, libbgp_rib4_withdraw(&rib, 85u, &prefix));
    LIBBGP_ASSERT_EQ_U64(1u, libbgp_rib4_route_count(&rib));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_rib4_lookup(&rib, ip4(10u, 84u, 0u, 1u), &found));
    LIBBGP_ASSERT(found != NULL);
    LIBBGP_ASSERT_EQ_U64(84u, found->source_router_id);

    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_rib4_discard(&rib, 85u));
    LIBBGP_ASSERT_EQ_U64(1u, libbgp_rib4_route_count(&rib));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_rib4_discard(&rib, 84u));
    LIBBGP_ASSERT_EQ_U64(0u, libbgp_rib4_route_count(&rib));
    libbgp_rib4_destroy(&rib);
}

LIBBGP_TEST(rib4_med_ignores_as_path_without_as_sequence)
{
    /*
     * RFC basis: RFC 4271 §9.1.2.2 (MED only compared for paths from same neighboring AS).
     * Covered branches: rib4_neighbor_as path with AS_PATH present but no AS_SEQUENCE segment.
     * Expected result: MED ignored, final tie-break falls back to older update_id.
     */
    libbgp_rib4_t rib;
    libbgp_prefix4_t prefix = p4(203u, 0u, 122u, 0u, 24u);
    libbgp_rib4_route_t high_med_older = route4(prefix, 1u);
    libbgp_rib4_route_t low_med_newer = route4(prefix, 2u);
    libbgp_pattr_t *set_only_path = libbgp_pattr_new(LIBBGP_PATTR_AS_PATH);
    libbgp_as_path_segment_t *segments;
    uint32_t *set_asns;
    libbgp_pattr_t *attrs[1];

    LIBBGP_ASSERT(set_only_path != NULL);
    segments = (libbgp_as_path_segment_t *)libbgp_calloc(1u, sizeof(*segments));
    set_asns = (uint32_t *)libbgp_calloc(1u, sizeof(*set_asns));
    LIBBGP_ASSERT(segments != NULL);
    LIBBGP_ASSERT(set_asns != NULL);
    set_asns[0] = 65050u;
    segments[0].type = 1u;
    segments[0].asn_count = 1u;
    segments[0].asns = set_asns;
    set_only_path->data.as_path.segments = segments;
    set_only_path->data.as_path.segment_count = 1u;
    set_only_path->data.as_path.is_4b = true;
    attrs[0] = set_only_path;

    high_med_older.attrs = attrs;
    high_med_older.attr_count = 1u;
    high_med_older.med = 100u;
    high_med_older.update_id = 10u;
    low_med_newer.attrs = attrs;
    low_med_newer.attr_count = 1u;
    low_med_newer.med = 10u;
    low_med_newer.update_id = 20u;

    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_rib4_init(&rib));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_rib4_insert(&rib, &high_med_older));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_rib4_insert(&rib, &low_med_newer));
    assert_rib4_best_source(&rib, ip4(203u, 0u, 122u, 1u), 1u);

    libbgp_rib4_destroy(&rib);
    libbgp_pattr_unref(set_only_path);
}

LIBBGP_TEST(rib6_med_ignores_as_path_without_as_sequence)
{
    /*
     * RFC basis: RFC 4271 §9.1.2.2 (MED only compared for paths from same neighboring AS).
     * Covered branches: rib6_neighbor_as path with AS_PATH present but no AS_SEQUENCE segment.
     * Expected result: MED ignored, final tie-break falls back to older update_id.
     */
    libbgp_rib6_t rib;
    const uint8_t prefix_addr[16] = { 0x20u, 0x01u, 0x0du, 0xb8u, 0u, 0x22u };
    const uint8_t dest[16] = { 0x20u, 0x01u, 0x0du, 0xb8u, 0u, 0x22u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 1u };
    const uint8_t next_hop[16] = { 0x20u, 0x01u, 0x0du, 0xb8u, 0xffu, 0x22u };
    libbgp_prefix6_t prefix = p6(prefix_addr, 48u);
    libbgp_rib6_route_t high_med_older = route6(prefix, 1u, next_hop);
    libbgp_rib6_route_t low_med_newer = route6(prefix, 2u, next_hop);
    libbgp_pattr_t *set_only_path = libbgp_pattr_new(LIBBGP_PATTR_AS_PATH);
    libbgp_as_path_segment_t *segments;
    uint32_t *set_asns;
    libbgp_pattr_t *attrs[1];

    LIBBGP_ASSERT(set_only_path != NULL);
    segments = (libbgp_as_path_segment_t *)libbgp_calloc(1u, sizeof(*segments));
    set_asns = (uint32_t *)libbgp_calloc(1u, sizeof(*set_asns));
    LIBBGP_ASSERT(segments != NULL);
    LIBBGP_ASSERT(set_asns != NULL);
    set_asns[0] = 65050u;
    segments[0].type = 1u;
    segments[0].asn_count = 1u;
    segments[0].asns = set_asns;
    set_only_path->data.as_path.segments = segments;
    set_only_path->data.as_path.segment_count = 1u;
    set_only_path->data.as_path.is_4b = true;
    attrs[0] = set_only_path;

    high_med_older.attrs = attrs;
    high_med_older.attr_count = 1u;
    high_med_older.med = 100u;
    high_med_older.update_id = 10u;
    low_med_newer.attrs = attrs;
    low_med_newer.attr_count = 1u;
    low_med_newer.med = 10u;
    low_med_newer.update_id = 20u;

    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_rib6_init(&rib));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_rib6_insert(&rib, &high_med_older));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_rib6_insert(&rib, &low_med_newer));
    assert_rib6_best_source(&rib, dest, 1u);

    libbgp_rib6_destroy(&rib);
    libbgp_pattr_unref(set_only_path);
}

LIBBGP_TEST(rib6_discard_collect_reports_allocator_failures)
{
    /*
     * RFC basis: RFC 7606 §2 (error handling should be robust and avoid state corruption).
     * Covered branches: rib6_prefix_array_push/rib6_result_add_replacement allocation-failure paths.
     * Expected result: returns LIBBGP_ERR_NOMEM and reports no withdrawn/replacement output.
     */
    libbgp_rib6_t rib;
    const uint8_t withdrawn_addr[16] = { 0x20u, 0x01u, 0x0du, 0xb8u, 0u, 0x72u };
    const uint8_t replaced_addr[16] = { 0x20u, 0x01u, 0x0du, 0xb8u, 0u, 0x73u };
    const uint8_t next_hop[16] = { 0x20u, 0x01u, 0x0du, 0xb8u, 0xffu, 0x72u };
    libbgp_prefix6_t withdrawn_prefix = p6(withdrawn_addr, 48u);
    libbgp_prefix6_t replaced_prefix = p6(replaced_addr, 48u);
    libbgp_rib6_route_t peer_only = route6(withdrawn_prefix, 72u, next_hop);
    libbgp_rib6_route_t peer_best = route6(replaced_prefix, 72u, next_hop);
    libbgp_rib6_route_t replacement = route6(replaced_prefix, 73u, next_hop);
    bgp_rib6_discard_result_t result;
    fail_after_alloc_ctx_t fail_ctx;
    libbgp_alloc_t alloc;
    libbgp_err_t err;

    peer_only.local_pref = 200u;
    peer_best.local_pref = 200u;
    replacement.local_pref = 100u;

    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_rib6_init(&rib));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_rib6_insert(&rib, &peer_only));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_rib6_insert(&rib, &peer_best));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_rib6_insert(&rib, &replacement));

    fail_ctx.calls = 0u;
    fail_ctx.fail_at = 1u;
    alloc = fail_after_alloc_make(&fail_ctx);
    libbgp_set_alloc(&alloc);
    err = bgp_rib6_discard_collect(&rib, 72u, &result);
    libbgp_set_alloc(NULL);
    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_NOMEM, err);
    LIBBGP_ASSERT_EQ_U64(0u, result.withdrawn_count);
    LIBBGP_ASSERT_EQ_U64(0u, result.replacement_count);

    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_rib6_insert(&rib, &peer_only));
    fail_ctx.calls = 0u;
    fail_ctx.fail_at = 3u;
    libbgp_set_alloc(&alloc);
    err = bgp_rib6_discard_collect(&rib, 72u, &result);
    libbgp_set_alloc(NULL);
    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_NOMEM, err);
    LIBBGP_ASSERT_EQ_U64(0u, result.withdrawn_count);
    LIBBGP_ASSERT_EQ_U64(0u, result.replacement_count);

    libbgp_rib6_destroy(&rib);
}

LIBBGP_TEST(rib6_saved_route_update_restore_and_conditional_withdraw)
{
    libbgp_rib6_t rib;
    const uint8_t prefix_addr[16] = { 0x20u, 0x01u, 0x0du, 0xb8u, 0u, 0x41u };
    const uint8_t dest[16] = { 0x20u, 0x01u, 0x0du, 0xb8u, 0u, 0x41u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 1u };
    const uint8_t next_hop[16] = { 0x20u, 0x01u, 0x0du, 0xb8u, 0xffu, 0x41u };
    libbgp_prefix6_t prefix = p6(prefix_addr, 48u);
    libbgp_rib6_route_t original = route6(prefix, 41u, next_hop);
    libbgp_rib6_route_t replacement = route6(prefix, 41u, next_hop);
    bgp_rib6_saved_route_t saved;
    bool had_route = true;
    uint64_t inserted_id = 0u;
    uint64_t saved_id = 0u;
    uint64_t exact_id = 0u;
    const libbgp_rib6_route_t *found = NULL;

    memset(&saved, 0, sizeof(saved));
    original.weight = 10;
    replacement.weight = 99;
    replacement.update_id = 100u;

    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_INVALID, bgp_rib6_saved_route_update_id(NULL, &saved_id));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_INVALID, bgp_rib6_saved_route_update_id(&saved, NULL));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_NOT_FOUND, bgp_rib6_saved_route_update_id(&saved, &saved_id));
    LIBBGP_ASSERT_EQ_U64(0u, saved_id);

    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_rib6_init(&rib));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, bgp_rib6_insert_save_replaced(&rib, &original, NULL, NULL, &inserted_id));
    LIBBGP_ASSERT(inserted_id != 0u);
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, bgp_rib6_exact_update_id(&rib, 41u, &prefix, &exact_id));
    LIBBGP_ASSERT_EQ_U64(inserted_id, exact_id);
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, bgp_rib6_exact_update_id(&rib, 41u, &prefix, NULL));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_NOT_FOUND, bgp_rib6_exact_update_id(&rib, 99u, &prefix, &exact_id));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_INVALID, bgp_rib6_withdraw_exact_if_update_id(&rib, 41u, &prefix, 0u));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, bgp_rib6_withdraw_exact_if_update_id(&rib, 41u, &prefix, inserted_id + 1u));
    LIBBGP_ASSERT_EQ_U64(1u, libbgp_rib6_route_count(&rib));

    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, bgp_rib6_withdraw_exact_save(&rib, 99u, &prefix, &saved, &had_route));
    LIBBGP_ASSERT(!had_route);
    LIBBGP_ASSERT(saved.entry == NULL);
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, bgp_rib6_withdraw_exact_save(&rib, 41u, &prefix, &saved, &had_route));
    LIBBGP_ASSERT(had_route);
    LIBBGP_ASSERT(saved.entry != NULL);
    LIBBGP_ASSERT_EQ_U64(0u, libbgp_rib6_route_count(&rib));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, bgp_rib6_saved_route_update_id(&saved, &saved_id));
    LIBBGP_ASSERT_EQ_U64(inserted_id, saved_id);

    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, bgp_rib6_restore_saved_if_absent(&rib, 41u, &saved));
    LIBBGP_ASSERT(saved.entry == NULL);
    LIBBGP_ASSERT_EQ_U64(1u, libbgp_rib6_route_count(&rib));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_NOT_FOUND, bgp_rib6_saved_route_update_id(&saved, &saved_id));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, bgp_rib6_withdraw_exact_save(&rib, 41u, &prefix, &saved, &had_route));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_rib6_insert(&rib, &replacement));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, bgp_rib6_restore_saved_if_absent(&rib, 41u, &saved));
    LIBBGP_ASSERT(saved.entry != NULL);
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_rib6_lookup(&rib, dest, &found));
    LIBBGP_ASSERT_EQ_I64(99, found->weight);
    bgp_rib6_saved_route_destroy(&saved);

    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, bgp_rib6_withdraw_exact_if_update_id(&rib, 41u, &prefix, inserted_id));
    LIBBGP_ASSERT_EQ_U64(1u, libbgp_rib6_route_count(&rib));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, bgp_rib6_exact_update_id(&rib, 41u, &prefix, &exact_id));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, bgp_rib6_withdraw_exact_if_update_id(&rib, 41u, &prefix, exact_id));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_NOT_FOUND, bgp_rib6_withdraw_exact_if_update_id(&rib, 41u, &prefix, exact_id));
    libbgp_rib6_destroy(&rib);
}

LIBBGP_TEST(rib4_scoped_lookup_keeps_adj_rib_sources_separate)
{
    libbgp_rib4_t rib;
    libbgp_prefix4_t broad = p4(10u, 90u, 0u, 0u, 16u);
    libbgp_prefix4_t source_one_specific_prefix = p4(10u, 90u, 1u, 0u, 24u);
    libbgp_prefix4_t specific = p4(10u, 90u, 1u, 0u, 24u);
    libbgp_rib4_route_t source_one = route4(broad, 90u);
    libbgp_rib4_route_t source_one_specific = route4(source_one_specific_prefix, 90u);
    libbgp_rib4_route_t source_two = route4(specific, 91u);
    const libbgp_rib4_route_t *found = NULL;

    source_one.local_pref = 100u;
    source_one_specific.local_pref = 150u;
    source_two.local_pref = 200u;

    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_rib4_init(&rib));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_rib4_insert(&rib, &source_one));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_rib4_insert(&rib, &source_one_specific));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_rib4_insert(&rib, &source_two));

    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_rib4_lookup(&rib, ip4(10u, 90u, 1u, 7u), &found));
    LIBBGP_ASSERT(found != NULL);
    LIBBGP_ASSERT_EQ_U64(91u, found->source_router_id);
    LIBBGP_ASSERT(libbgp_prefix4_eq(&specific, &found->prefix));

    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_rib4_lookup_scoped(&rib, 90u, ip4(10u, 90u, 1u, 7u), &found));
    LIBBGP_ASSERT(found != NULL);
    LIBBGP_ASSERT_EQ_U64(90u, found->source_router_id);
    LIBBGP_ASSERT(libbgp_prefix4_eq(&source_one_specific_prefix, &found->prefix));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_NOT_FOUND, libbgp_rib4_lookup_scoped(&rib, 92u, ip4(10u, 90u, 1u, 7u), &found));

    libbgp_rib4_destroy(&rib);
}

LIBBGP_TEST(rib6_scoped_lookup_keeps_adj_rib_sources_separate)
{
    libbgp_rib6_t rib;
    static const uint8_t broad_addr[16] = { 0x20u, 0x01u, 0x0du, 0xb8u, 0x90u, 0u };
    static const uint8_t specific_addr[16] = { 0x20u, 0x01u, 0x0du, 0xb8u, 0x90u, 0x01u };
    static const uint8_t dest[16] = { 0x20u, 0x01u, 0x0du, 0xb8u, 0x90u, 0x01u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 7u };
    static const uint8_t next_hop[16] = { 0x20u, 0x01u, 0x0du, 0xb8u, 0xffu, 0x90u };
    libbgp_prefix6_t broad = p6(broad_addr, 40u);
    libbgp_prefix6_t source_one_specific_prefix = p6(specific_addr, 64u);
    libbgp_prefix6_t specific = p6(specific_addr, 64u);
    libbgp_rib6_route_t source_one = route6(broad, 90u, next_hop);
    libbgp_rib6_route_t source_one_specific = route6(source_one_specific_prefix, 90u, next_hop);
    libbgp_rib6_route_t source_two = route6(specific, 91u, next_hop);
    const libbgp_rib6_route_t *found = NULL;

    source_one.local_pref = 100u;
    source_one_specific.local_pref = 150u;
    source_two.local_pref = 200u;

    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_rib6_init(&rib));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_rib6_insert(&rib, &source_one));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_rib6_insert(&rib, &source_one_specific));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_rib6_insert(&rib, &source_two));

    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_rib6_lookup(&rib, dest, &found));
    LIBBGP_ASSERT(found != NULL);
    LIBBGP_ASSERT_EQ_U64(91u, found->source_router_id);
    LIBBGP_ASSERT(libbgp_prefix6_eq(&specific, &found->prefix));

    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_rib6_lookup_scoped(&rib, 90u, dest, &found));
    LIBBGP_ASSERT(found != NULL);
    LIBBGP_ASSERT_EQ_U64(90u, found->source_router_id);
    LIBBGP_ASSERT(libbgp_prefix6_eq(&source_one_specific_prefix, &found->prefix));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_NOT_FOUND, libbgp_rib6_lookup_scoped(&rib, 92u, dest, &found));

    libbgp_rib6_destroy(&rib);
}

LIBBGP_TEST(rib6_lookup_prefers_partial_byte_prefix_over_default)
{
    libbgp_rib6_t rib;
    static const uint8_t zero[16] = { 0u };
    static const uint8_t partial_addr[16] = { 0x20u, 0x01u, 0x0du, 0xb8u, 0xa0u, 0u };
    static const uint8_t inside[16] = { 0x20u, 0x01u, 0x0du, 0xb8u, 0xafu, 0x0fu, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 1u };
    static const uint8_t outside[16] = { 0x20u, 0x01u, 0x0du, 0xb8u, 0xb0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 1u };
    static const uint8_t next_hop[16] = { 0x20u, 0x01u, 0x0du, 0xb8u, 0xffu, 0x91u };
    libbgp_prefix6_t default_prefix = p6(zero, 0u);
    libbgp_prefix6_t partial = p6(partial_addr, 36u);
    libbgp_rib6_route_t default_route = route6(default_prefix, 92u, next_hop);
    libbgp_rib6_route_t partial_route = route6(partial, 93u, next_hop);
    const libbgp_rib6_route_t *found = NULL;

    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_rib6_init(&rib));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_rib6_insert(&rib, &default_route));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_rib6_insert(&rib, &partial_route));

    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_rib6_lookup(&rib, inside, &found));
    LIBBGP_ASSERT(found != NULL);
    LIBBGP_ASSERT_EQ_U64(93u, found->source_router_id);
    LIBBGP_ASSERT(libbgp_prefix6_eq(&partial, &found->prefix));

    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_rib6_lookup(&rib, outside, &found));
    LIBBGP_ASSERT(found != NULL);
    LIBBGP_ASSERT_EQ_U64(92u, found->source_router_id);
    LIBBGP_ASSERT(libbgp_prefix6_eq(&default_prefix, &found->prefix));

    libbgp_rib6_destroy(&rib);
}

/* ---- Branch coverage tests for rib4_better / rib6_better tie-breaking ---- */

LIBBGP_TEST(rib4_better_ties_through_router_id_and_ibgp_and_local_pref_zero)
{
    /* Exercise: local_pref==0 defaults to 100, is_ibgp tie-break,
       update_id tie-break falls through to router_id comparison. */
    libbgp_rib4_t rib;
    libbgp_prefix4_t prefix = p4(172u, 16u, 0u, 0u, 16u);
    uint32_t dest = ip4(172u, 16u, 0u, 1u);
    libbgp_rib4_route_t r;

    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_rib4_init(&rib));

    /* Route A: local_pref=0 (should default to 100), update_id=10 */
    r = route4(prefix, 1u);
    r.local_pref = 0u;
    r.update_id = 10u;
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_rib4_insert(&rib, &r));

    /* Route B: local_pref=0 (also defaults to 100), same weight, update_id=20.
       Since update_ids differ, prefers lower update_id -> route 1 wins. */
    r = route4(prefix, 2u);
    r.local_pref = 0u;
    r.update_id = 20u;
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_rib4_insert(&rib, &r));
    assert_rib4_best_source(&rib, dest, 1u);

    /* Route C: same weight, local_pref=0, update_id=10, same as route A.
       update_id tie, falls through to router_id.  Source 3 > Source 1
       in NBO comparison, so route 1 still wins (lower router_id). */
    r = route4(prefix, 3u);
    r.local_pref = 0u;
    r.update_id = 10u;
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_rib4_insert(&rib, &r));
    assert_rib4_best_source(&rib, dest, 1u);

    /* Route D: is_ibgp=true.  When weight/local_pref/as_path/origin are
       equal but is_ibgp differs, eBGP (is_ibgp=false) is preferred. */
    r = route4(prefix, 4u);
    r.local_pref = 0u;
    r.is_ibgp = true;
    r.update_id = 10u;
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_rib4_insert(&rib, &r));
    /* Best should still be source 1 (eBGP) */
    assert_rib4_best_source(&rib, dest, 1u);

    libbgp_rib4_destroy(&rib);
}

LIBBGP_TEST(rib6_better_ties_through_router_id_and_ibgp_and_local_pref_zero)
{
    libbgp_rib6_t rib;
    static const uint8_t prefix_addr[16] = { 0x20u, 0x01u, 0x0du, 0xb8u, 0xAAu, 0u };
    static const uint8_t dest[16] = { 0x20u, 0x01u, 0x0du, 0xb8u, 0xAAu, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 1u };
    static const uint8_t next_hop[16] = { 0x20u, 0x01u, 0x0du, 0xb8u, 0xFFu, 0xAAu };
    libbgp_prefix6_t prefix = p6(prefix_addr, 48u);
    libbgp_rib6_route_t r;

    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_rib6_init(&rib));

    r = route6(prefix, 1u, next_hop);
    r.local_pref = 0u;
    r.update_id = 10u;
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_rib6_insert(&rib, &r));

    r = route6(prefix, 2u, next_hop);
    r.local_pref = 0u;
    r.update_id = 20u;
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_rib6_insert(&rib, &r));
    assert_rib6_best_source(&rib, dest, 1u);

    r = route6(prefix, 3u, next_hop);
    r.local_pref = 0u;
    r.update_id = 10u;
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_rib6_insert(&rib, &r));
    assert_rib6_best_source(&rib, dest, 1u);

    r = route6(prefix, 4u, next_hop);
    r.local_pref = 0u;
    r.is_ibgp = true;
    r.update_id = 10u;
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_rib6_insert(&rib, &r));
    assert_rib6_best_source(&rib, dest, 1u);

    libbgp_rib6_destroy(&rib);
}

LIBBGP_TEST(rib4_scoped_lookup_tiebreaks_same_prefix_length_via_better)
{
    /* Two routes from the same source, same prefix length but different
       local_pref.  The scoped lookup should call rib4_better to pick
       the higher-local_pref route when prefix lengths tie. */
    libbgp_rib4_t rib;
    libbgp_prefix4_t prefix = p4(10u, 80u, 0u, 0u, 16u);
    libbgp_rib4_route_t low = route4(prefix, 80u);
    libbgp_rib4_route_t high = route4(prefix, 80u);
    const libbgp_rib4_route_t *found = NULL;
    uint32_t dest = ip4(10u, 80u, 5u, 1u);

    low.local_pref = 100u;
    low.update_id = 1u;
    high.local_pref = 200u;
    high.update_id = 2u;

    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_rib4_init(&rib));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_rib4_insert(&rib, &low));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_rib4_insert(&rib, &high));

    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_rib4_lookup_scoped(&rib, 80u, dest, &found));
    LIBBGP_ASSERT(found != NULL);
    LIBBGP_ASSERT_EQ_U64(200u, found->local_pref);

    libbgp_rib4_destroy(&rib);
}

LIBBGP_TEST(rib6_scoped_lookup_tiebreaks_same_prefix_length_via_better)
{
    libbgp_rib6_t rib;
    static const uint8_t prefix_addr[16] = { 0x20u, 0x01u, 0x0du, 0xb8u, 0xBBu, 0u };
    static const uint8_t dest[16] = { 0x20u, 0x01u, 0x0du, 0xb8u, 0xBBu, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 1u };
    static const uint8_t next_hop[16] = { 0x20u, 0x01u, 0x0du, 0xb8u, 0xFFu, 0xBBu };
    libbgp_prefix6_t prefix = p6(prefix_addr, 48u);
    libbgp_rib6_route_t low = route6(prefix, 81u, next_hop);
    libbgp_rib6_route_t high = route6(prefix, 81u, next_hop);
    const libbgp_rib6_route_t *found = NULL;

    low.local_pref = 100u;
    low.update_id = 1u;
    high.local_pref = 200u;
    high.update_id = 2u;

    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_rib6_init(&rib));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_rib6_insert(&rib, &low));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_rib6_insert(&rib, &high));

    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_rib6_lookup_scoped(&rib, 81u, dest, &found));
    LIBBGP_ASSERT(found != NULL);
    LIBBGP_ASSERT_EQ_U64(200u, found->local_pref);

    libbgp_rib6_destroy(&rib);
}

LIBBGP_TEST(rib6_withdraw_track_best_reports_replacement_best)
{
    /* Withdraw the best route; a backup route from another source should
       cause BGP_RIB_CHANGE_REPLACEMENT_BEST.  Exercises the uncovered
       branch at rib6.c line 779. */
    libbgp_rib6_t rib;
    static const uint8_t prefix_addr[16] = { 0x20u, 0x01u, 0x0du, 0xb8u, 0xCCu, 0u };
    static const uint8_t next_hop[16] = { 0x20u, 0x01u, 0x0du, 0xb8u, 0xFFu, 0xCCu };
    libbgp_prefix6_t prefix = p6(prefix_addr, 48u);
    libbgp_rib6_route_t best = route6(prefix, 100u, next_hop);
    libbgp_rib6_route_t backup = route6(prefix, 101u, next_hop);
    bgp_rib6_change_t change;
    uint64_t update_id = 0u;

    best.local_pref = 200u;
    backup.local_pref = 100u;

    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_rib6_init(&rib));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, bgp_rib6_insert_track_best(&rib, &best, &change, &update_id));
    LIBBGP_ASSERT_EQ_I64(BGP_RIB_CHANGE_NEW_BEST, change.kind);

    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, bgp_rib6_insert_track_best(&rib, &backup, &change, &update_id));
    LIBBGP_ASSERT_EQ_I64(BGP_RIB_CHANGE_NO_BEST_CHANGE, change.kind);

    /* Withdraw the best; backup should become best -> REPLACEMENT_BEST */
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, bgp_rib6_withdraw_track_best(&rib, 100u, &prefix, &change));
    LIBBGP_ASSERT_EQ_I64(BGP_RIB_CHANGE_REPLACEMENT_BEST, change.kind);
    LIBBGP_ASSERT(change.best != NULL);
    LIBBGP_ASSERT_EQ_U64(101u, change.best->source_router_id);

    libbgp_rib6_destroy(&rib);
}

LIBBGP_TEST(rib4_foreach_best_route_covers_initial_capacity_branch)
{
    /* Ensure route_capacity starts at 0, triggering the initial capacity
       branch (route_capacity == 0) in foreach_best_route.  Only need 1 route
       so that the first snapshot hits the capacity==0 path. */
    libbgp_rib4_t rib;
    libbgp_prefix4_t prefix = p4(10u, 91u, 0u, 0u, 24u);
    libbgp_rib4_route_t route = route4(prefix, 91u);
    rib4_iter_count_ctx_t ctx;

    memset(&ctx, 0, sizeof(ctx));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_rib4_init(&rib));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_rib4_insert(&rib, &route));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, bgp_rib4_foreach_best_route(&rib, record_rib4_source, &ctx));
    LIBBGP_ASSERT_EQ_U64(1u, ctx.count);
    LIBBGP_ASSERT_EQ_U64(91u, ctx.sources[0]);
    libbgp_rib4_destroy(&rib);
}

LIBBGP_TEST(rib6_foreach_best_route_covers_initial_capacity_branch)
{
    libbgp_rib6_t rib;
    static const uint8_t prefix_addr[16] = { 0x20u, 0x01u, 0x0du, 0xb8u, 0xDDu, 0u };
    static const uint8_t next_hop[16] = { 0x20u, 0x01u, 0x0du, 0xb8u, 0xFFu, 0xDDu };
    libbgp_prefix6_t prefix = p6(prefix_addr, 48u);
    libbgp_rib6_route_t route = route6(prefix, 92u, next_hop);
    rib6_iter_count_ctx_t ctx;

    memset(&ctx, 0, sizeof(ctx));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_rib6_init(&rib));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_rib6_insert(&rib, &route));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, bgp_rib6_foreach_best_route(&rib, record_rib6_source, &ctx));
    LIBBGP_ASSERT_EQ_U64(1u, ctx.count);
    LIBBGP_ASSERT_EQ_U64(92u, ctx.sources[0]);
    libbgp_rib6_destroy(&rib);
}

LIBBGP_TEST(rib6_restore_saved_if_absent_noop_when_entry_null)
{
    /* When saved->entry == NULL, restore should be a no-op returning OK.
       Exercises the uncovered branch at rib6.c line 1306-1307. */
    libbgp_rib6_t rib;
    bgp_rib6_saved_route_t saved;

    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_rib6_init(&rib));
    memset(&saved, 0, sizeof(saved));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, bgp_rib6_restore_saved_if_absent(&rib, 1u, &saved));
    libbgp_rib6_destroy(&rib);
}

LIBBGP_TEST(rib4_error_paths_cover_zero_source_saved_route_and_alloc_failures)
{
    /*
     * RFC basis: RFC 4271 §4.2 + RFC 7606 §2 (robust error handling for malformed/invalid state).
     * Covered branches: source_router_id==0 duplicate insert path, saved-route invalid-entry path,
     *                   restore-with-source-mismatch, withdraw-save invalid arg, insert_local NOMEM paths.
     * Expected result: API returns explicit ERR_* without corrupting existing RIB state.
     */
    libbgp_rib4_t rib;
    libbgp_prefix4_t zero_src_prefix = p4(10u, 96u, 0u, 0u, 24u);
    libbgp_rib4_route_t zero_src = route4(zero_src_prefix, 0u);
    libbgp_prefix4_t saved_prefix = p4(10u, 97u, 0u, 0u, 24u);
    libbgp_rib4_route_t saved_route = route4(saved_prefix, 97u);
    bgp_rib4_saved_route_t saved;
    bool had_route = false;
    uint64_t update_id = 0u;
    bgp_hashmap_entry_t bogus_entry;
    fail_after_alloc_ctx_t fail_ctx;
    libbgp_alloc_t alloc;
    bool saw_local_nomem = false;
    size_t i;

    memset(&saved, 0, sizeof(saved));
    memset(&bogus_entry, 0, sizeof(bogus_entry));

    fail_ctx.calls = 0u;
    fail_ctx.fail_at = 1u;
    alloc = fail_after_alloc_make(&fail_ctx);
    libbgp_set_alloc(&alloc);
    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_NOMEM, libbgp_rib4_init(&rib));
    libbgp_set_alloc(NULL);

    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_rib4_init(&rib));

    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_rib4_insert(&rib, &zero_src));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_EXISTS, libbgp_rib4_insert(&rib, &zero_src));

    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_INVALID, bgp_rib4_exact_update_id(&rib, 97u, NULL, &update_id));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_INVALID, bgp_rib4_withdraw_exact_save(&rib, 97u, &saved_prefix, NULL, &had_route));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, bgp_rib4_insert_save_replaced(&rib, &saved_route, NULL, NULL, NULL));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, bgp_rib4_withdraw_exact_save(&rib, 97u, &saved_prefix, &saved, &had_route));
    LIBBGP_ASSERT(had_route);
    LIBBGP_ASSERT(saved.entry != NULL);
    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_INVALID, bgp_rib4_restore_saved_if_absent(&rib, 98u, &saved));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, bgp_rib4_restore_saved_if_absent(&rib, 97u, &saved));
    bgp_rib4_saved_route_destroy(&saved);

    saved.entry = &bogus_entry;
    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_INVALID, bgp_rib4_saved_route_update_id(&saved, &update_id));
    saved.entry = NULL;

    fail_ctx.calls = 0u;
    fail_ctx.fail_at = 1u;
    alloc = fail_after_alloc_make(&fail_ctx);
    libbgp_set_alloc(&alloc);
    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_NOMEM,
        libbgp_rib4_insert_local(&rib, &saved_prefix, ip4(192u, 0u, 2u, 97u), 97));
    libbgp_set_alloc(NULL);

    fail_ctx.calls = 0u;
    fail_ctx.fail_at = 2u;
    libbgp_set_alloc(&alloc);
    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_NOMEM,
        libbgp_rib4_insert_local(&rib, &saved_prefix, ip4(192u, 0u, 2u, 98u), 98));
    libbgp_set_alloc(NULL);

    for (i = 1u; i <= 16u; i++) {
        libbgp_prefix4_t fail_prefix = p4(10u, 98u, (uint8_t)i, 0u, 24u);
        fail_ctx.calls = 0u;
        fail_ctx.fail_at = i;
        libbgp_set_alloc(&alloc);
        if (libbgp_rib4_insert_local(&rib, &fail_prefix, ip4(192u, 0u, 2u, (uint8_t)i), 99) == LIBBGP_ERR_NOMEM) {
            saw_local_nomem = true;
            libbgp_set_alloc(NULL);
            break;
        }
        libbgp_set_alloc(NULL);
        (void)libbgp_rib4_withdraw(&rib, 0u, &fail_prefix);
    }
    LIBBGP_ASSERT(saw_local_nomem);

    libbgp_rib4_destroy(&rib);
}

LIBBGP_TEST(rib6_error_paths_cover_zero_source_saved_route_and_alloc_failures)
{
    /*
     * RFC basis: RFC 4271 §4.2 + RFC 7606 §2 (robust error handling for malformed/invalid state).
     * Covered branches: source_router_id==0 duplicate insert path, saved-route invalid-entry path,
     *                   restore-with-source-mismatch, withdraw-save invalid arg, insert_local NOMEM paths.
     * Expected result: API returns explicit ERR_* without corrupting existing RIB state.
     */
    libbgp_rib6_t rib;
    const uint8_t zero_src_addr[16] = { 0x20u, 0x01u, 0x0du, 0xb8u, 0u, 0x96u };
    const uint8_t saved_addr[16] = { 0x20u, 0x01u, 0x0du, 0xb8u, 0u, 0x97u };
    const uint8_t next_hop[16] = { 0x20u, 0x01u, 0x0du, 0xb8u, 0xffu, 0x96u };
    libbgp_prefix6_t zero_src_prefix = p6(zero_src_addr, 48u);
    libbgp_prefix6_t saved_prefix = p6(saved_addr, 48u);
    libbgp_rib6_route_t zero_src = route6(zero_src_prefix, 0u, next_hop);
    libbgp_rib6_route_t saved_route = route6(saved_prefix, 97u, next_hop);
    bgp_rib6_saved_route_t saved;
    bool had_route = false;
    uint64_t update_id = 0u;
    bgp_hashmap_entry_t bogus_entry;
    fail_after_alloc_ctx_t fail_ctx;
    libbgp_alloc_t alloc;
    bool saw_local_nomem = false;
    size_t i;

    memset(&saved, 0, sizeof(saved));
    memset(&bogus_entry, 0, sizeof(bogus_entry));

    fail_ctx.calls = 0u;
    fail_ctx.fail_at = 1u;
    alloc = fail_after_alloc_make(&fail_ctx);
    libbgp_set_alloc(&alloc);
    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_NOMEM, libbgp_rib6_init(&rib));
    libbgp_set_alloc(NULL);

    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_rib6_init(&rib));

    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_rib6_insert(&rib, &zero_src));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_EXISTS, libbgp_rib6_insert(&rib, &zero_src));

    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_INVALID, bgp_rib6_exact_update_id(&rib, 97u, NULL, &update_id));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_INVALID, bgp_rib6_withdraw_exact_save(&rib, 97u, &saved_prefix, NULL, &had_route));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, bgp_rib6_insert_save_replaced(&rib, &saved_route, NULL, NULL, NULL));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, bgp_rib6_withdraw_exact_save(&rib, 97u, &saved_prefix, &saved, &had_route));
    LIBBGP_ASSERT(had_route);
    LIBBGP_ASSERT(saved.entry != NULL);
    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_INVALID, bgp_rib6_restore_saved_if_absent(&rib, 98u, &saved));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, bgp_rib6_restore_saved_if_absent(&rib, 97u, &saved));
    bgp_rib6_saved_route_destroy(&saved);

    saved.entry = &bogus_entry;
    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_INVALID, bgp_rib6_saved_route_update_id(&saved, &update_id));
    saved.entry = NULL;

    fail_ctx.calls = 0u;
    fail_ctx.fail_at = 1u;
    alloc = fail_after_alloc_make(&fail_ctx);
    libbgp_set_alloc(&alloc);
    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_NOMEM, libbgp_rib6_insert_local(&rib, &saved_prefix, next_hop, 97));
    libbgp_set_alloc(NULL);

    fail_ctx.calls = 0u;
    fail_ctx.fail_at = 2u;
    libbgp_set_alloc(&alloc);
    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_NOMEM, libbgp_rib6_insert_local(&rib, &saved_prefix, next_hop, 98));
    libbgp_set_alloc(NULL);

    for (i = 1u; i <= 16u; i++) {
        uint8_t fail_addr[16] = { 0x20u, 0x01u, 0x0du, 0xb8u, 0u, 0x98u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, (uint8_t)i, 0u };
        libbgp_prefix6_t fail_prefix = p6(fail_addr, 120u);
        fail_ctx.calls = 0u;
        fail_ctx.fail_at = i;
        libbgp_set_alloc(&alloc);
        if (libbgp_rib6_insert_local(&rib, &fail_prefix, next_hop, 99) == LIBBGP_ERR_NOMEM) {
            saw_local_nomem = true;
            libbgp_set_alloc(NULL);
            break;
        }
        libbgp_set_alloc(NULL);
        (void)libbgp_rib6_withdraw(&rib, 0u, &fail_prefix);
    }
    LIBBGP_ASSERT(saw_local_nomem);

    libbgp_rib6_destroy(&rib);
}

LIBBGP_TEST(rib4_foreach_route_visits_multiple_routes_before_stop)
{
    /* Exercise the keep_going loop where the callback returns true for
       at least one route before returning false.  This covers the
       `!keep_going` branch at line 948. */
    libbgp_rib4_t rib;
    libbgp_prefix4_t p1 = p4(10u, 92u, 1u, 0u, 24u);
    libbgp_prefix4_t p2 = p4(10u, 92u, 2u, 0u, 24u);
    libbgp_rib4_route_t r1 = route4(p1, 1u);
    libbgp_rib4_route_t r2 = route4(p2, 2u);
    rib4_iter_count_ctx_t ctx;

    memset(&ctx, 0, sizeof(ctx));
    ctx.limit = 1u;
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_rib4_init(&rib));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_rib4_insert(&rib, &r1));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_rib4_insert(&rib, &r2));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, bgp_rib4_foreach_route(&rib, record_rib4_source, &ctx));
    LIBBGP_ASSERT_EQ_U64(1u, ctx.count);
    libbgp_rib4_destroy(&rib);
}

LIBBGP_TEST(rib6_foreach_route_visits_multiple_routes_before_stop)
{
    libbgp_rib6_t rib;
    static const uint8_t a1[16] = { 0x20u, 0x01u, 0x0du, 0xb8u, 0xEEu, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 1u };
    static const uint8_t a2[16] = { 0x20u, 0x01u, 0x0du, 0xb8u, 0xEEu, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 2u };
    static const uint8_t next_hop[16] = { 0x20u, 0x01u, 0x0du, 0xb8u, 0xFFu, 0xEEu };
    libbgp_prefix6_t p1 = p6(a1, 128u);
    libbgp_prefix6_t p2 = p6(a2, 128u);
    libbgp_rib6_route_t r1 = route6(p1, 1u, next_hop);
    libbgp_rib6_route_t r2 = route6(p2, 2u, next_hop);
    rib6_iter_count_ctx_t ctx;

    memset(&ctx, 0, sizeof(ctx));
    ctx.limit = 1u;
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_rib6_init(&rib));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_rib6_insert(&rib, &r1));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_rib6_insert(&rib, &r2));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, bgp_rib6_foreach_route(&rib, record_rib6_source, &ctx));
    LIBBGP_ASSERT_EQ_U64(1u, ctx.count);
    libbgp_rib6_destroy(&rib);
}

LIBBGP_TEST(rib4_med_rfc4271_neighbor_as_gate_then_med_activation)
{
    /*
     * RFC section: RFC 4271 §9.1.2.2 (MED is comparable only across paths learned from the same neighboring AS).
     * Target branches: rib4.c:rib4_better() MED gate false path (different neighbor AS), then MED compare true path.
     * Expected result: lower MED does not win across different neighbor AS; lower MED wins when neighbor AS matches.
     */
    libbgp_rib4_t rib;
    libbgp_prefix4_t gate_prefix = p4(198u, 51u, 230u, 0u, 24u);
    libbgp_prefix4_t med_prefix = p4(198u, 51u, 231u, 0u, 24u);
    libbgp_rib4_route_t gate_baseline = route4(gate_prefix, 230u);
    libbgp_rib4_route_t gate_diff_neighbor_lower_med = route4(gate_prefix, 231u);
    libbgp_rib4_route_t med_high = route4(med_prefix, 232u);
    libbgp_rib4_route_t med_low = route4(med_prefix, 233u);
    libbgp_pattr_t *gate_baseline_path = test_as_path_attr(65001u, 65101u);
    libbgp_pattr_t *gate_diff_neighbor_path = test_as_path_attr(65002u, 65102u);
    libbgp_pattr_t *med_high_path = test_as_path_attr(65111u, 65201u);
    libbgp_pattr_t *med_low_path = test_as_path_attr(65111u, 65202u);
    libbgp_pattr_t *gate_baseline_attrs[1];
    libbgp_pattr_t *diff_attrs[1];
    libbgp_pattr_t *med_high_attrs[1];
    libbgp_pattr_t *med_low_attrs[1];

    gate_baseline_attrs[0] = gate_baseline_path;
    diff_attrs[0] = gate_diff_neighbor_path;
    med_high_attrs[0] = med_high_path;
    med_low_attrs[0] = med_low_path;

    gate_baseline.med = 200u;
    gate_baseline.update_id = 10u;
    gate_baseline.attrs = gate_baseline_attrs;
    gate_baseline.attr_count = 1u;
    gate_diff_neighbor_lower_med.med = 1u;
    gate_diff_neighbor_lower_med.update_id = 20u;
    gate_diff_neighbor_lower_med.attrs = diff_attrs;
    gate_diff_neighbor_lower_med.attr_count = 1u;
    med_high.med = 180u;
    med_high.update_id = 10u;
    med_high.attrs = med_high_attrs;
    med_high.attr_count = 1u;
    med_low.med = 20u;
    med_low.update_id = 20u;
    med_low.attrs = med_low_attrs;
    med_low.attr_count = 1u;

    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_rib4_init(&rib));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_rib4_insert(&rib, &gate_baseline));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_rib4_insert(&rib, &gate_diff_neighbor_lower_med));
    assert_rib4_best_source(&rib, ip4(198u, 51u, 230u, 1u), 230u);

    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_rib4_insert(&rib, &med_high));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_rib4_insert(&rib, &med_low));
    assert_rib4_best_source(&rib, ip4(198u, 51u, 231u, 1u), 233u);

    libbgp_rib4_destroy(&rib);
    libbgp_pattr_unref(gate_baseline_path);
    libbgp_pattr_unref(gate_diff_neighbor_path);
    libbgp_pattr_unref(med_high_path);
    libbgp_pattr_unref(med_low_path);
}

LIBBGP_TEST(rib4_source_zero_exact_update_withdraw_edges)
{
    /*
     * RFC section: RFC 4271 §9.1 (route replacement/withdrawal must be deterministic per source).
     * Target branches: rib4.c:bgp_rib4_exact_update_id() found/not-found and bgp_rib4_withdraw_exact_if_update_id() mismatch/match/not-found.
     * Expected result: source_router_id==0 route supports exact-update_id reads; wrong update_id keeps route, exact update_id withdraws it.
     */
    libbgp_rib4_t rib;
    libbgp_prefix4_t prefix = p4(10u, 231u, 0u, 0u, 24u);
    libbgp_rib4_route_t route = route4(prefix, 0u);
    uint64_t update_id = 0u;
    const libbgp_rib4_route_t *found = NULL;

    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_rib4_init(&rib));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_rib4_insert(&rib, &route));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, bgp_rib4_exact_update_id(&rib, 0u, &prefix, &update_id));
    LIBBGP_ASSERT(update_id != 0u);

    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, bgp_rib4_withdraw_exact_if_update_id(&rib, 0u, &prefix, update_id + 1u));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_rib4_lookup(&rib, ip4(10u, 231u, 0u, 1u), &found));
    LIBBGP_ASSERT(found != NULL);
    LIBBGP_ASSERT_EQ_U64(0u, found->source_router_id);

    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, bgp_rib4_withdraw_exact_if_update_id(&rib, 0u, &prefix, update_id));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_NOT_FOUND, bgp_rib4_exact_update_id(&rib, 0u, &prefix, &update_id));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_NOT_FOUND, bgp_rib4_withdraw_exact_if_update_id(&rib, 0u, &prefix, update_id));

    libbgp_rib4_destroy(&rib);
}

LIBBGP_TEST(rib4_discard_collect_non_best_source_has_no_best_delta)
{
    /*
     * RFC section: RFC 4271 §9.1.2 (best-path recomputation only affects NLRI whose best path changes).
     * Target branches: rib4.c:bgp_rib4_discard_collect() source-match branch where route is not best, plus zero active-prefix result path.
     * Expected result: removing a non-best source yields no withdrawn/replacement entries and leaves best route intact.
     */
    libbgp_rib4_t rib;
    libbgp_prefix4_t prefix = p4(10u, 232u, 0u, 0u, 24u);
    libbgp_rib4_route_t non_best = route4(prefix, 232u);
    libbgp_rib4_route_t best = route4(prefix, 233u);
    bgp_rib4_discard_result_t result;
    const libbgp_rib4_route_t *found = NULL;

    non_best.local_pref = 100u;
    best.local_pref = 200u;
    memset(&result, 0, sizeof(result));

    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_rib4_init(&rib));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_rib4_insert(&rib, &non_best));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_rib4_insert(&rib, &best));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, bgp_rib4_discard_collect(&rib, 232u, &result));

    LIBBGP_ASSERT_EQ_U64(0u, result.withdrawn_count);
    LIBBGP_ASSERT_EQ_U64(0u, result.replacement_count);
    LIBBGP_ASSERT_EQ_U64(1u, libbgp_rib4_route_count(&rib));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_rib4_lookup(&rib, ip4(10u, 232u, 0u, 1u), &found));
    LIBBGP_ASSERT(found != NULL);
    LIBBGP_ASSERT_EQ_U64(233u, found->source_router_id);

    bgp_rib4_discard_result_destroy(&result);
    libbgp_rib4_destroy(&rib);
}

LIBBGP_TEST(rib4_restore_saved_if_absent_noop_and_invalid_saved_entry)
{
    /*
     * RFC section: RFC 7606 §2 (malformed state must return explicit errors without destabilizing routing state).
     * Target branches: rib4.c:bgp_rib4_restore_saved_if_absent() saved->entry==NULL no-op and route==NULL invalid detached-entry path.
     * Expected result: NULL saved entry is accepted as no-op; detached entry with NULL route is rejected as LIBBGP_ERR_INVALID.
     */
    libbgp_rib4_t rib;
    bgp_rib4_saved_route_t saved;
    bgp_hashmap_entry_t bogus;
    uint64_t update_id = 123u;

    memset(&saved, 0, sizeof(saved));
    memset(&bogus, 0, sizeof(bogus));

    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_rib4_init(&rib));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, bgp_rib4_restore_saved_if_absent(&rib, 234u, &saved));

    saved.entry = &bogus;
    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_INVALID, bgp_rib4_restore_saved_if_absent(&rib, 234u, &saved));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_INVALID, bgp_rib4_saved_route_update_id(&saved, &update_id));
    LIBBGP_ASSERT_EQ_U64(0u, update_id);
    saved.entry = NULL;

    libbgp_rib4_destroy(&rib);
}

LIBBGP_TEST(rib4_foreach_best_route_continues_then_stops_on_callback_false)
{
    /*
     * RFC section: RFC 4271 §9.1 (best-path set is enumerable, callback controls delivery pacing only).
     * Target branches: rib4.c:bgp_rib4_foreach_best_route() keep_going true continuation and callback-driven early-stop false branch.
     * Expected result: limit=2 visits exactly two best routes; limit=0 visits all best routes.
     */
    libbgp_rib4_t rib;
    libbgp_rib4_route_t a = route4(p4(10u, 233u, 1u, 0u, 24u), 1u);
    libbgp_rib4_route_t b = route4(p4(10u, 233u, 2u, 0u, 24u), 2u);
    libbgp_rib4_route_t c = route4(p4(10u, 233u, 3u, 0u, 24u), 3u);
    rib4_iter_count_ctx_t ctx;

    memset(&ctx, 0, sizeof(ctx));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_rib4_init(&rib));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_rib4_insert(&rib, &a));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_rib4_insert(&rib, &b));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_rib4_insert(&rib, &c));

    ctx.limit = 2u;
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, bgp_rib4_foreach_best_route(&rib, record_rib4_source, &ctx));
    LIBBGP_ASSERT_EQ_U64(2u, ctx.count);

    memset(&ctx, 0, sizeof(ctx));
    ctx.limit = 0u;
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, bgp_rib4_foreach_best_route(&rib, record_rib4_source, &ctx));
    LIBBGP_ASSERT_EQ_U64(3u, ctx.count);
    LIBBGP_ASSERT(rib4_sources_contain(&ctx, 1u));
    LIBBGP_ASSERT(rib4_sources_contain(&ctx, 2u));
    LIBBGP_ASSERT(rib4_sources_contain(&ctx, 3u));

    libbgp_rib4_destroy(&rib);
}

LIBBGP_TEST(rib6_source_zero_exact_update_withdraw_edges)
{
    /*
     * RFC section: RFC 4271 §9.1 (route replacement/withdrawal must be deterministic per source).
     * Target branches: rib6.c:bgp_rib6_exact_update_id() found/not-found and bgp_rib6_withdraw_exact_if_update_id() mismatch/match/not-found.
     * Expected result: source_router_id==0 route supports exact-update_id reads; wrong update_id keeps route, exact update_id withdraws it.
     */
    libbgp_rib6_t rib;
    const uint8_t prefix_addr[16] = { 0x20u, 0x01u, 0x0du, 0xb8u, 0u, 0xe7u };
    const uint8_t dest[16] = { 0x20u, 0x01u, 0x0du, 0xb8u, 0u, 0xe7u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 1u };
    const uint8_t next_hop[16] = { 0x20u, 0x01u, 0x0du, 0xb8u, 0xffu, 0xe7u };
    libbgp_prefix6_t prefix = p6(prefix_addr, 48u);
    libbgp_rib6_route_t route = route6(prefix, 0u, next_hop);
    uint64_t update_id = 0u;
    const libbgp_rib6_route_t *found = NULL;

    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_rib6_init(&rib));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_rib6_insert(&rib, &route));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, bgp_rib6_exact_update_id(&rib, 0u, &prefix, &update_id));
    LIBBGP_ASSERT(update_id != 0u);

    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, bgp_rib6_withdraw_exact_if_update_id(&rib, 0u, &prefix, update_id + 1u));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_rib6_lookup(&rib, dest, &found));
    LIBBGP_ASSERT(found != NULL);
    LIBBGP_ASSERT_EQ_U64(0u, found->source_router_id);

    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, bgp_rib6_withdraw_exact_if_update_id(&rib, 0u, &prefix, update_id));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_NOT_FOUND, bgp_rib6_exact_update_id(&rib, 0u, &prefix, &update_id));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_NOT_FOUND, bgp_rib6_withdraw_exact_if_update_id(&rib, 0u, &prefix, update_id));

    libbgp_rib6_destroy(&rib);
}

LIBBGP_TEST(rib4_lookup_tie_breaks_on_noncanonical_same_length_prefixes)
{
    /*
     * RFC section: RFC 7606 §2 + RFC 4271 §9.1.2.2 (robust handling of abnormal input with deterministic best-path choice).
     * Target branches: rib4.c radix lookup maintenance for equivalent noncanonical prefixes.
     * Expected result: global lookup preserves full-scan tie-break behavior and falls back after exact withdraw.
     */
    libbgp_rib4_t rib;
    libbgp_prefix4_t canonical = p4(10u, 245u, 0u, 0u, 24u);
    libbgp_prefix4_t noncanonical;
    libbgp_rib4_route_t low = route4(canonical, 96u);
    libbgp_rib4_route_t high;
    const libbgp_rib4_route_t *found = NULL;
    uint32_t dest = ip4(10u, 245u, 0u, 99u);

    noncanonical.addr = ip4(10u, 245u, 0u, 128u);
    noncanonical.len = 24u;
    high = route4(noncanonical, 97u);
    low.local_pref = 100u;
    high.local_pref = 250u;

    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_rib4_init(&rib));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_rib4_insert(&rib, &high));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_rib4_insert(&rib, &low));
    LIBBGP_ASSERT_EQ_U64(2u, libbgp_rib4_route_count(&rib));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_rib4_lookup(&rib, dest, &found));
    LIBBGP_ASSERT(found != NULL);
    LIBBGP_ASSERT_EQ_U64(97u, found->source_router_id);
    LIBBGP_ASSERT_EQ_U64(250u, found->local_pref);
    LIBBGP_ASSERT_EQ_U64(noncanonical.addr, found->prefix.addr);

    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_rib4_withdraw(&rib, 97u, &noncanonical));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_rib4_lookup(&rib, dest, &found));
    LIBBGP_ASSERT(found != NULL);
    LIBBGP_ASSERT_EQ_U64(96u, found->source_router_id);
    LIBBGP_ASSERT_EQ_U64(canonical.addr, found->prefix.addr);

    libbgp_rib4_destroy(&rib);
}

LIBBGP_TEST(rib6_lookup_tie_breaks_on_noncanonical_same_length_prefixes)
{
    /*
     * RFC section: RFC 7606 §2 + RFC 4271 §9.1.2.2 (robust handling of abnormal input with deterministic best-path choice).
     * Target branches: rib6.c radix lookup maintenance for equivalent noncanonical prefixes.
     * Expected result: global lookup preserves full-scan tie-break behavior and falls back after exact withdraw.
     */
    libbgp_rib6_t rib;
    const uint8_t base_addr[16] = { 0x20u, 0x01u, 0x0du, 0xb8u, 0u, 0xf5u };
    const uint8_t dest[16] = { 0x20u, 0x01u, 0x0du, 0xb8u, 0u, 0xf5u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 1u };
    const uint8_t next_hop[16] = { 0x20u, 0x01u, 0x0du, 0xb8u, 0xffu, 0xf5u };
    libbgp_prefix6_t canonical = p6(base_addr, 64u);
    libbgp_prefix6_t noncanonical = canonical;
    libbgp_rib6_route_t low = route6(canonical, 98u, next_hop);
    libbgp_rib6_route_t high;
    const libbgp_rib6_route_t *found = NULL;

    noncanonical.addr[15] = 0x80u;
    high = route6(noncanonical, 99u, next_hop);
    low.local_pref = 100u;
    high.local_pref = 250u;

    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_rib6_init(&rib));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_rib6_insert(&rib, &high));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_rib6_insert(&rib, &low));
    LIBBGP_ASSERT_EQ_U64(2u, libbgp_rib6_route_count(&rib));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_rib6_lookup(&rib, dest, &found));
    LIBBGP_ASSERT(found != NULL);
    LIBBGP_ASSERT_EQ_U64(99u, found->source_router_id);
    LIBBGP_ASSERT_EQ_U64(250u, found->local_pref);
    LIBBGP_ASSERT_EQ_U64(0x80u, found->prefix.addr[15]);

    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_rib6_withdraw(&rib, 99u, &noncanonical));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_rib6_lookup(&rib, dest, &found));
    LIBBGP_ASSERT(found != NULL);
    LIBBGP_ASSERT_EQ_U64(98u, found->source_router_id);
    LIBBGP_ASSERT_EQ_U64(0u, found->prefix.addr[15]);

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
        { "rib4_foreach_best_route_avoids_per_prefix_realloc", rib4_foreach_best_route_avoids_per_prefix_realloc },
        { "rib4_discard_collect_preserves_replacement_correctness", rib4_discard_collect_preserves_replacement_correctness },
        { "rib4_discard_large", rib4_discard_large },
        { "rib4_med_comparison_uses_neighbor_as_from_as_path", rib4_med_comparison_uses_neighbor_as_from_as_path },
        { "rib4_med_not_compared_without_neighbor_as", rib4_med_not_compared_without_neighbor_as },
        { "rib4_med_ignores_missing_wrong_type_and_different_neighbor_as", rib4_med_ignores_missing_wrong_type_and_different_neighbor_as },
        { "rib4_neighbor_as_uses_first_as_sequence_segment", rib4_neighbor_as_uses_first_as_sequence_segment },
        { "rib4_neighbor_as_skips_null_attrs_and_rejects_malformed_path", rib4_neighbor_as_skips_null_attrs_and_rejects_malformed_path },
        { "rib6_neighbor_as_skips_null_attrs_and_rejects_malformed_path", rib6_neighbor_as_skips_null_attrs_and_rejects_malformed_path },
        { "rib4_saved_route_withdraw_restore_and_conflict_paths", rib4_saved_route_withdraw_restore_and_conflict_paths },
        { "rib4_discard_collect_reports_allocator_failures", rib4_discard_collect_reports_allocator_failures },
        { "rib4_insert_defaults_local_pref_and_update_id", rib4_insert_defaults_local_pref_and_update_id },
        { "rib4_insert_reports_only_best_path_changes", rib4_insert_reports_only_best_path_changes },
        { "rib4_insert_reports_replacement_best_when_better_route_wins", rib4_insert_reports_replacement_best_when_better_route_wins },
        { "rib4_insert_reports_same_update_id_best_replacement", rib4_insert_reports_same_update_id_best_replacement },
        { "rib4_withdraw_reports_replacement_vs_unreachable", rib4_withdraw_reports_replacement_vs_unreachable },
        { "rib6_best_route_ordering_for_same_prefix", rib6_best_route_ordering_for_same_prefix },
        { "rib6_foreach_best_route_visits_one_route_per_prefix", rib6_foreach_best_route_visits_one_route_per_prefix },
        { "rib6_foreach_best_route_avoids_per_prefix_realloc", rib6_foreach_best_route_avoids_per_prefix_realloc },
        { "rib6_discard_collect_preserves_replacement_correctness", rib6_discard_collect_preserves_replacement_correctness },
        { "rib6_med_not_compared_without_neighbor_as", rib6_med_not_compared_without_neighbor_as },
        { "rib6_med_ignores_missing_wrong_type_and_different_neighbor_as", rib6_med_ignores_missing_wrong_type_and_different_neighbor_as },
        { "rib6_neighbor_as_uses_first_as_sequence_segment", rib6_neighbor_as_uses_first_as_sequence_segment },
        { "rib6_insert_defaults_local_pref_and_update_id", rib6_insert_defaults_local_pref_and_update_id },
        { "rib6_insert_refs_attrs_and_destroy_unrefs", rib6_insert_refs_attrs_and_destroy_unrefs },
        { "rib6_best_route_prefers_lower_update_id", rib6_best_route_prefers_lower_update_id },
        { "rib6_foreach_best_route_stops_stored_route_iteration_early", rib6_foreach_best_route_stops_stored_route_iteration_early },
        { "rib6_med_comparison_uses_neighbor_as_from_as_path", rib6_med_comparison_uses_neighbor_as_from_as_path },
        { "rib6_discard_large", rib6_discard_large },
        { "rib6_insert_reports_same_update_id_best_replacement", rib6_insert_reports_same_update_id_best_replacement },
        { "rib6_insert_and_withdraw_track_best_changes", rib6_insert_and_withdraw_track_best_changes },
        { "rib6_withdraw_track_reports_unreachable_and_rejects_invalid_args", rib6_withdraw_track_reports_unreachable_and_rejects_invalid_args },
        { "rib4_and_rib6_change_kind_values_match", rib4_and_rib6_change_kind_values_match },
        { "rib4_and_rib6_best_path_parity_for_core_tie_breakers", rib4_and_rib6_best_path_parity_for_core_tie_breakers },
        { "rib_best_route_compares_router_ids_as_network_order", rib_best_route_compares_router_ids_as_network_order },
        { "rib4_insert_allocation_failures_preserve_existing_routes", rib4_insert_allocation_failures_preserve_existing_routes },
        { "rib4_snapshot_clone_rejects_invalid_and_clears_on_alloc_failure", rib4_snapshot_clone_rejects_invalid_and_clears_on_alloc_failure },
        { "rib4_replace_withdraw_discard_and_scoped_lookup", rib4_replace_withdraw_discard_and_scoped_lookup },
        { "rib4_lookup_returns_borrowed_pointer_replaced_by_mutation", rib4_lookup_returns_borrowed_pointer_replaced_by_mutation },
        { "rib4_insert_refs_attrs_and_destroy_unrefs", rib4_insert_refs_attrs_and_destroy_unrefs },
        { "rib6_insert_allocation_failures_preserve_existing_routes", rib6_insert_allocation_failures_preserve_existing_routes },
        { "rib6_snapshot_clone_rejects_invalid_and_clears_on_alloc_failure", rib6_snapshot_clone_rejects_invalid_and_clears_on_alloc_failure },
        { "rib6_insert_lookup_withdraw_discard_and_scoped", rib6_insert_lookup_withdraw_discard_and_scoped },
        { "rib6_insert_local_creates_legacy_path_attributes", rib6_insert_local_creates_legacy_path_attributes },
        { "rib6_insert_local_rejects_duplicate_prefix", rib6_insert_local_rejects_duplicate_prefix },
        { "rib4_rejects_invalid_args_and_stops_foreach_route", rib4_rejects_invalid_args_and_stops_foreach_route },
        { "rib6_rejects_invalid_args_and_stops_foreach_route", rib6_rejects_invalid_args_and_stops_foreach_route },
        { "rib4_rejects_invalid_prefixes_on_local_clone_lookup_and_withdraw", rib4_rejects_invalid_prefixes_on_local_clone_lookup_and_withdraw },
        { "rib6_rejects_invalid_prefixes_on_local_clone_lookup_and_withdraw", rib6_rejects_invalid_prefixes_on_local_clone_lookup_and_withdraw },
        { "rib4_foreach_empty_tables_accept_valid_callback", rib4_foreach_empty_tables_accept_valid_callback },
        { "rib6_foreach_empty_tables_accept_valid_callback", rib6_foreach_empty_tables_accept_valid_callback },
        { "rib4_saved_route_update_restore_and_conditional_withdraw", rib4_saved_route_update_restore_and_conditional_withdraw },
        { "rib4_lookup_covers_default_exact_and_boundary_prefixes", rib4_lookup_covers_default_exact_and_boundary_prefixes },
        { "rib6_lookup_covers_default_exact_and_boundary_prefixes", rib6_lookup_covers_default_exact_and_boundary_prefixes },
        { "rib4_lookup_radix_updates_after_withdraw_restore_and_discard", rib4_lookup_radix_updates_after_withdraw_restore_and_discard },
        { "rib6_lookup_radix_updates_partial_prefix_after_withdraw_and_discard", rib6_lookup_radix_updates_partial_prefix_after_withdraw_and_discard },
        { "rib4_insert_save_replaced_reports_replaced_route", rib4_insert_save_replaced_reports_replaced_route },
        { "rib6_insert_save_replaced_reports_replaced_route", rib6_insert_save_replaced_reports_replaced_route },
        { "rib4_withdraw_track_reports_no_change_and_rejects_invalid_args", rib4_withdraw_track_reports_no_change_and_rejects_invalid_args },
        { "rib6_discard_empty_and_withdraw_missing_preserve_routes", rib6_discard_empty_and_withdraw_missing_preserve_routes },
        { "rib4_discard_empty_and_withdraw_missing_preserve_routes", rib4_discard_empty_and_withdraw_missing_preserve_routes },
        { "rib4_med_ignores_as_path_without_as_sequence", rib4_med_ignores_as_path_without_as_sequence },
        { "rib6_med_ignores_as_path_without_as_sequence", rib6_med_ignores_as_path_without_as_sequence },
        { "rib6_discard_collect_reports_allocator_failures", rib6_discard_collect_reports_allocator_failures },
        { "rib6_saved_route_update_restore_and_conditional_withdraw", rib6_saved_route_update_restore_and_conditional_withdraw },
        { "rib4_scoped_lookup_keeps_adj_rib_sources_separate", rib4_scoped_lookup_keeps_adj_rib_sources_separate },
        { "rib6_scoped_lookup_keeps_adj_rib_sources_separate", rib6_scoped_lookup_keeps_adj_rib_sources_separate },
        { "rib6_lookup_prefers_partial_byte_prefix_over_default", rib6_lookup_prefers_partial_byte_prefix_over_default },
        { "rib4_better_ties_through_router_id_and_ibgp_and_local_pref_zero", rib4_better_ties_through_router_id_and_ibgp_and_local_pref_zero },
        { "rib6_better_ties_through_router_id_and_ibgp_and_local_pref_zero", rib6_better_ties_through_router_id_and_ibgp_and_local_pref_zero },
        { "rib4_scoped_lookup_tiebreaks_same_prefix_length_via_better", rib4_scoped_lookup_tiebreaks_same_prefix_length_via_better },
        { "rib6_scoped_lookup_tiebreaks_same_prefix_length_via_better", rib6_scoped_lookup_tiebreaks_same_prefix_length_via_better },
        { "rib6_withdraw_track_best_reports_replacement_best", rib6_withdraw_track_best_reports_replacement_best },
        { "rib4_foreach_best_route_covers_initial_capacity_branch", rib4_foreach_best_route_covers_initial_capacity_branch },
        { "rib6_foreach_best_route_covers_initial_capacity_branch", rib6_foreach_best_route_covers_initial_capacity_branch },
        { "rib6_restore_saved_if_absent_noop_when_entry_null", rib6_restore_saved_if_absent_noop_when_entry_null },
        { "rib4_error_paths_cover_zero_source_saved_route_and_alloc_failures", rib4_error_paths_cover_zero_source_saved_route_and_alloc_failures },
        { "rib6_error_paths_cover_zero_source_saved_route_and_alloc_failures", rib6_error_paths_cover_zero_source_saved_route_and_alloc_failures },
        { "rib4_foreach_route_visits_multiple_routes_before_stop", rib4_foreach_route_visits_multiple_routes_before_stop },
        { "rib6_foreach_route_visits_multiple_routes_before_stop", rib6_foreach_route_visits_multiple_routes_before_stop },
        { "rib4_med_rfc4271_neighbor_as_gate_then_med_activation", rib4_med_rfc4271_neighbor_as_gate_then_med_activation },
        { "rib4_source_zero_exact_update_withdraw_edges", rib4_source_zero_exact_update_withdraw_edges },
        { "rib4_discard_collect_non_best_source_has_no_best_delta", rib4_discard_collect_non_best_source_has_no_best_delta },
        { "rib4_restore_saved_if_absent_noop_and_invalid_saved_entry", rib4_restore_saved_if_absent_noop_and_invalid_saved_entry },
        { "rib4_foreach_best_route_continues_then_stops_on_callback_false", rib4_foreach_best_route_continues_then_stops_on_callback_false },
        { "rib6_source_zero_exact_update_withdraw_edges", rib6_source_zero_exact_update_withdraw_edges },
        { "rib4_lookup_tie_breaks_on_noncanonical_same_length_prefixes", rib4_lookup_tie_breaks_on_noncanonical_same_length_prefixes },
        { "rib6_lookup_tie_breaks_on_noncanonical_same_length_prefixes", rib6_lookup_tie_breaks_on_noncanonical_same_length_prefixes }
    };

    return libbgp_run_tests("rib", tests, LIBBGP_ARRAY_LEN(tests));
}
