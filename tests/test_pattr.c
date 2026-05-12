#include "test_main.h"

#include "libbgp/alloc.h"
#include "libbgp/pattr.h"
#include "libbgp/types.h"

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

LIBBGP_TEST(pattr_new_ref_unref_initializes_representative_types)
{
    libbgp_pattr_t *origin = libbgp_pattr_new(LIBBGP_PATTR_ORIGIN);
    libbgp_pattr_t *as4 = libbgp_pattr_new(LIBBGP_PATTR_AS4_PATH);
    libbgp_pattr_t *mp = libbgp_pattr_new(LIBBGP_PATTR_MP_REACH_IPV6);
    libbgp_pattr_t *unknown = libbgp_pattr_new(LIBBGP_PATTR_UNKNOWN);

    LIBBGP_ASSERT(origin != NULL);
    LIBBGP_ASSERT_EQ_U64(1u, origin->refcount);
    LIBBGP_ASSERT_EQ_U64(0x40u, origin->flags);
    LIBBGP_ASSERT_EQ_U64(1u, origin->type_code);

    LIBBGP_ASSERT(as4 != NULL);
    LIBBGP_ASSERT_EQ_U64(0xc0u, as4->flags);
    LIBBGP_ASSERT_EQ_U64(17u, as4->type_code);
    LIBBGP_ASSERT(as4->data.as_path.is_4b);

    LIBBGP_ASSERT(mp != NULL);
    LIBBGP_ASSERT_EQ_U64(0x80u, mp->flags);
    LIBBGP_ASSERT_EQ_U64(14u, mp->type_code);

    LIBBGP_ASSERT(unknown != NULL);
    LIBBGP_ASSERT_EQ_U64(0u, unknown->flags);
    LIBBGP_ASSERT_EQ_U64(0u, unknown->type_code);
    LIBBGP_ASSERT(unknown->data.unknown.value == NULL);
    LIBBGP_ASSERT_EQ_U64(0u, unknown->data.unknown.len);

    LIBBGP_ASSERT(libbgp_pattr_new((libbgp_pattr_type_t)99) == NULL);
    LIBBGP_ASSERT(libbgp_pattr_ref(NULL) == NULL);
    LIBBGP_ASSERT(libbgp_pattr_ref(origin) == origin);
    LIBBGP_ASSERT_EQ_U64(2u, origin->refcount);
    origin->refcount = UINT32_MAX;
    LIBBGP_ASSERT(libbgp_pattr_ref(origin) == origin);
    LIBBGP_ASSERT_EQ_U64(UINT32_MAX, origin->refcount);
    origin->refcount = 1u;

    libbgp_pattr_unref(NULL);
    libbgp_pattr_unref(origin);
    libbgp_pattr_unref(as4);
    libbgp_pattr_unref(mp);
    libbgp_pattr_unref(unknown);
}

LIBBGP_TEST(pattr_type_from_buf_and_names)
{
    const uint8_t origin[] = { 0x40u, 1u, 1u, 0u };
    const uint8_t extended_as4[] = { 0xd0u, 17u, 0u, 0u };
    const uint8_t unknown[] = { 0x80u, 99u, 0u };

    LIBBGP_ASSERT_EQ_I64(LIBBGP_PATTR_UNKNOWN, libbgp_pattr_type_from_buf(NULL, 0u));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_PATTR_UNKNOWN, libbgp_pattr_type_from_buf(origin, 2u));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_PATTR_ORIGIN, libbgp_pattr_type_from_buf(origin, sizeof(origin)));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_PATTR_AS4_PATH, libbgp_pattr_type_from_buf(extended_as4, sizeof(extended_as4)));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_PATTR_UNKNOWN, libbgp_pattr_type_from_buf(unknown, sizeof(unknown)));
    LIBBGP_ASSERT(strcmp("ORIGIN", libbgp_pattr_type_name(LIBBGP_PATTR_ORIGIN)) == 0);
    LIBBGP_ASSERT(strcmp("MP_UNREACH_IPV6", libbgp_pattr_type_name(LIBBGP_PATTR_MP_UNREACH_IPV6)) == 0);
    LIBBGP_ASSERT(strcmp("UNKNOWN", libbgp_pattr_type_name((libbgp_pattr_type_t)99)) == 0);
}

static void assert_roundtrip(libbgp_pattr_t *attr, const uint8_t *wire, size_t wire_len)
{
    uint8_t out[512];
    size_t used = 0u;
    size_t out_len = 0u;

    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_pattr_parse(attr, wire, wire_len, &used));
    LIBBGP_ASSERT_EQ_U64(wire_len, used);
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_pattr_write(attr, out, sizeof(out), &out_len));
    LIBBGP_ASSERT_EQ_U64(wire_len, out_len);
    LIBBGP_ASSERT_BYTES_EQ(wire, out, wire_len);
}

static void assert_roundtrip_as4(libbgp_pattr_t *attr, const uint8_t *wire, size_t wire_len)
{
    uint8_t out[512];
    size_t used = 0u;
    size_t out_len = 0u;

    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_pattr_parse_as4(attr, wire, wire_len, true, &used));
    LIBBGP_ASSERT_EQ_U64(wire_len, used);
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_pattr_write(attr, out, sizeof(out), &out_len));
    LIBBGP_ASSERT_EQ_U64(wire_len, out_len);
    LIBBGP_ASSERT_BYTES_EQ(wire, out, wire_len);
}

LIBBGP_TEST(pattr_parse_write_fixed_scalar_attributes)
{
    const uint8_t origin[] = { 0x40u, 1u, 1u, 2u };
    const uint8_t origin_extended[] = { 0x50u, 1u, 0u, 1u, 0u };
    const uint8_t bad_origin[] = { 0x40u, 1u, 1u, 3u };
    const uint8_t next_hop[] = { 0x40u, 3u, 4u, 192u, 0u, 2u, 1u };
    const uint8_t med[] = { 0x80u, 4u, 4u, 0u, 0u, 0x10u, 0u };
    const uint8_t local_pref[] = { 0x40u, 5u, 4u, 0u, 0u, 0u, 100u };
    const uint8_t atomic[] = { 0x40u, 6u, 0u };
    libbgp_pattr_t *attr = libbgp_pattr_new(LIBBGP_PATTR_UNKNOWN);

    LIBBGP_ASSERT(attr != NULL);
    assert_roundtrip(attr, origin, sizeof(origin));
    LIBBGP_ASSERT_EQ_U64(2u, attr->data.origin.origin);
    assert_roundtrip(attr, origin_extended, sizeof(origin_extended));
    LIBBGP_ASSERT_EQ_U64(0u, attr->data.origin.origin);
    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_INVALID, libbgp_pattr_parse(attr, bad_origin, sizeof(bad_origin), NULL));
    assert_roundtrip(attr, next_hop, sizeof(next_hop));
    LIBBGP_ASSERT_EQ_U64(0xc0000201u, attr->data.next_hop.next_hop);
    assert_roundtrip(attr, med, sizeof(med));
    LIBBGP_ASSERT_EQ_U64(0x1000u, attr->data.med.value);
    assert_roundtrip(attr, local_pref, sizeof(local_pref));
    LIBBGP_ASSERT_EQ_U64(100u, attr->data.local_pref.value);
    assert_roundtrip(attr, atomic, sizeof(atomic));

    attr->type = LIBBGP_PATTR_ORIGIN;
    attr->flags = 0x40u;
    attr->type_code = 1u;
    attr->data.origin.origin = 3u;
    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_BAD_LEN, libbgp_pattr_write(attr, (uint8_t *)origin, sizeof(origin), NULL));

    libbgp_pattr_unref(attr);
}

LIBBGP_TEST(pattr_parse_rejects_malformed_known_flags)
{
    const uint8_t origin_optional[] = { 0x80u, 1u, 1u, 0u };
    const uint8_t origin_unrelated_bit[] = { 0x41u, 1u, 1u, 0u };
    const uint8_t med_transitive[] = { 0x40u, 4u, 4u, 0u, 0u, 0u, 1u };
    const uint8_t med_partial[] = { 0xa0u, 4u, 4u, 0u, 0u, 0u, 1u };
    const uint8_t community_partial[] = {
        0xe0u, 8u, 4u, 0u, 0u, 0u, 1u
    };
    const uint8_t mp_reach_transitive[] = {
        0xc0u, 14u, 21u,
        0u, 2u, 1u, 16u,
        0x20u, 0x01u, 0x0du, 0xb8u, 0u, 0u, 0u, 0u,
        0u, 0u, 0u, 0u, 0u, 0u, 0u, 1u,
        0u
    };
    const uint8_t unknown_well_known[] = { 0x40u, 99u, 1u, 0xaau };
    const uint8_t unknown_optional[] = { 0x80u, 99u, 1u, 0xaau };
    const uint8_t unknown_unrelated_bit[] = { 0x8fu, 99u, 1u, 0xaau };
    libbgp_pattr_t *attr = libbgp_pattr_new(LIBBGP_PATTR_UNKNOWN);

    LIBBGP_ASSERT(attr != NULL);
    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_INVALID, libbgp_pattr_parse(attr, origin_optional, sizeof(origin_optional), NULL));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_INVALID, libbgp_pattr_parse(attr, origin_unrelated_bit, sizeof(origin_unrelated_bit), NULL));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_INVALID, libbgp_pattr_parse(attr, med_transitive, sizeof(med_transitive), NULL));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_INVALID, libbgp_pattr_parse(attr, med_partial, sizeof(med_partial), NULL));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_INVALID, libbgp_pattr_parse(attr, mp_reach_transitive, sizeof(mp_reach_transitive), NULL));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_INVALID, libbgp_pattr_parse(attr, unknown_well_known, sizeof(unknown_well_known), NULL));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_INVALID, libbgp_pattr_parse(attr, unknown_unrelated_bit, sizeof(unknown_unrelated_bit), NULL));
    assert_roundtrip(attr, unknown_optional, sizeof(unknown_optional));
    LIBBGP_ASSERT_EQ_U64(0x80u, attr->flags);
    assert_roundtrip(attr, community_partial, sizeof(community_partial));
    LIBBGP_ASSERT_EQ_U64(0xe0u, attr->flags);

    libbgp_pattr_unref(attr);
}

LIBBGP_TEST(pattr_parse_write_aggregator_community_and_as_paths)
{
    const uint8_t aggregator[] = {
        0xc0u, 7u, 6u, 0xfdu, 0xe8u, 192u, 0u, 2u, 9u
    };
    const uint8_t aggregator_4b[] = {
        0xc0u, 7u, 8u, 0u, 1u, 0u, 1u, 192u, 0u, 2u, 9u
    };
    const uint8_t as4_aggregator[] = {
        0xc0u, 18u, 8u, 0u, 1u, 0u, 1u, 198u, 51u, 100u, 1u
    };
    const uint8_t community[] = {
        0xc0u, 8u, 8u, 0u, 0u, 0u, 1u, 0xffu, 0xffu, 0xffu, 0x01u
    };
    const uint8_t bad_community[] = { 0xc0u, 8u, 3u, 1u, 2u, 3u };
    const uint8_t as_path[] = {
        0x40u, 2u, 6u, 2u, 2u, 0xfdu, 0xe8u, 0xfdu, 0xe9u
    };
    const uint8_t as4_path[] = {
        0xc0u, 17u, 10u, 2u, 2u,
        0u, 1u, 0u, 1u, 0u, 1u, 0u, 2u
    };
    const uint8_t as_path_4b[] = {
        0x40u, 2u, 10u, 2u, 2u,
        0u, 1u, 0u, 1u, 0u, 1u, 0u, 2u
    };
    const uint8_t short_as_path[] = { 0x40u, 2u, 4u, 2u, 2u, 0u, 1u };
    const uint8_t invalid_segment[] = { 0x40u, 2u, 4u, 3u, 1u, 0u, 1u };
    uint32_t bad_asns[] = { 65536u };
    libbgp_as_path_segment_t bad_segment;
    libbgp_pattr_t *attr = libbgp_pattr_new(LIBBGP_PATTR_UNKNOWN);
    libbgp_pattr_t *bad_write = libbgp_pattr_new(LIBBGP_PATTR_AS_PATH);
    libbgp_pattr_t *bad_aggregator = libbgp_pattr_new(LIBBGP_PATTR_AGGREGATOR);

    LIBBGP_ASSERT(attr != NULL);
    LIBBGP_ASSERT(bad_write != NULL);
    LIBBGP_ASSERT(bad_aggregator != NULL);
    assert_roundtrip(attr, aggregator, sizeof(aggregator));
    LIBBGP_ASSERT_EQ_U64(65000u, attr->data.aggregator.asn);
    LIBBGP_ASSERT(!attr->data.aggregator.is_4b);
    assert_roundtrip_as4(attr, aggregator_4b, sizeof(aggregator_4b));
    LIBBGP_ASSERT_EQ_U64(65537u, attr->data.aggregator.asn);
    LIBBGP_ASSERT(attr->data.aggregator.is_4b);
    assert_roundtrip(attr, as4_aggregator, sizeof(as4_aggregator));
    LIBBGP_ASSERT_EQ_U64(65537u, attr->data.aggregator.asn);
    LIBBGP_ASSERT(attr->data.aggregator.is_4b);
    assert_roundtrip(attr, community, sizeof(community));
    LIBBGP_ASSERT_EQ_U64(2u, attr->data.community.count);
    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_BAD_LEN, libbgp_pattr_parse(attr, bad_community, sizeof(bad_community), NULL));
    assert_roundtrip(attr, as_path, sizeof(as_path));
    LIBBGP_ASSERT_EQ_U64(1u, attr->data.as_path.segment_count);
    LIBBGP_ASSERT(!attr->data.as_path.is_4b);
    LIBBGP_ASSERT_EQ_U64(65000u, attr->data.as_path.segments[0].asns[0]);
    assert_roundtrip(attr, as4_path, sizeof(as4_path));
    LIBBGP_ASSERT(attr->data.as_path.is_4b);
    LIBBGP_ASSERT_EQ_U64(65538u, attr->data.as_path.segments[0].asns[1]);
    assert_roundtrip_as4(attr, as_path_4b, sizeof(as_path_4b));
    LIBBGP_ASSERT_EQ_U64(LIBBGP_PATTR_AS_PATH, attr->type);
    LIBBGP_ASSERT(attr->data.as_path.is_4b);
    LIBBGP_ASSERT_EQ_U64(65538u, attr->data.as_path.segments[0].asns[1]);
    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_BAD_LEN, libbgp_pattr_parse(attr, short_as_path, sizeof(short_as_path), NULL));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_INVALID, libbgp_pattr_parse(attr, invalid_segment, sizeof(invalid_segment), NULL));

    bad_write->data.as_path.segment_count = 1u;
    bad_write->data.as_path.segments = NULL;
    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_BAD_LEN, libbgp_pattr_write(bad_write, (uint8_t *)community, sizeof(community), NULL));

    bad_segment.type = 2u;
    bad_segment.asn_count = 1u;
    bad_segment.asns = bad_asns;
    bad_write->data.as_path.segment_count = 1u;
    bad_write->data.as_path.segments = &bad_segment;
    bad_write->data.as_path.is_4b = false;
    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_BAD_LEN, libbgp_pattr_write(bad_write, (uint8_t *)community, sizeof(community), NULL));
    bad_write->data.as_path.segments = NULL;
    bad_write->data.as_path.segment_count = 0u;

    bad_aggregator->data.aggregator.asn = 65536u;
    bad_aggregator->data.aggregator.router_id = 1u;
    bad_aggregator->data.aggregator.is_4b = false;
    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_BAD_LEN, libbgp_pattr_write(bad_aggregator, (uint8_t *)community, sizeof(community), NULL));
    libbgp_pattr_unref(bad_aggregator);
    libbgp_pattr_unref(bad_write);
    libbgp_pattr_unref(attr);
}

LIBBGP_TEST(pattr_write_rejects_type_code_and_as_width_mismatch)
{
    uint8_t out[16];
    size_t out_len = 0u;
    uint32_t asns[] = { 65000u };
    libbgp_as_path_segment_t segment;
    libbgp_pattr_t *origin = libbgp_pattr_new(LIBBGP_PATTR_ORIGIN);
    libbgp_pattr_t *med = libbgp_pattr_new(LIBBGP_PATTR_MED);
    libbgp_pattr_t *as_path = libbgp_pattr_new(LIBBGP_PATTR_AS_PATH);
    libbgp_pattr_t *as4_path = libbgp_pattr_new(LIBBGP_PATTR_AS4_PATH);
    libbgp_pattr_t *unknown = libbgp_pattr_new(LIBBGP_PATTR_UNKNOWN);

    LIBBGP_ASSERT(origin != NULL);
    LIBBGP_ASSERT(med != NULL);
    LIBBGP_ASSERT(as_path != NULL);
    LIBBGP_ASSERT(as4_path != NULL);
    LIBBGP_ASSERT(unknown != NULL);

    origin->type_code = LIBBGP_PATTR_CODE_AS_PATH;
    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_BAD_LEN, libbgp_pattr_write(origin, out, sizeof(out), NULL));
    origin->type_code = LIBBGP_PATTR_CODE_ORIGIN;

    origin->flags = LIBBGP_PATTR_FLAG_OPTIONAL;
    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_BAD_LEN, libbgp_pattr_write(origin, out, sizeof(out), NULL));
    origin->flags = LIBBGP_PATTR_FLAG_TRANSITIVE | LIBBGP_PATTR_FLAG_EXTENDED_LENGTH;
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_pattr_write(origin, out, sizeof(out), &out_len));
    LIBBGP_ASSERT_EQ_U64(5u, out_len);
    LIBBGP_ASSERT_EQ_U64(0x50u, out[0]);

    med->data.med.value = 1u;
    med->flags = (uint8_t)(LIBBGP_PATTR_FLAG_OPTIONAL | 0x01u);
    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_BAD_LEN, libbgp_pattr_write(med, out, sizeof(out), NULL));

    segment.type = 2u;
    segment.asn_count = 1u;
    segment.asns = asns;
    as_path->data.as_path.segment_count = 1u;
    as_path->data.as_path.segments = &segment;
    as_path->data.as_path.is_4b = true;
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_pattr_write(as_path, out, sizeof(out), &out_len));
    LIBBGP_ASSERT_EQ_U64(9u, out_len);
    LIBBGP_ASSERT_EQ_U64(0x40u, out[0]);
    LIBBGP_ASSERT_EQ_U64(2u, out[1]);
    LIBBGP_ASSERT_EQ_U64(6u, out[2]);
    as_path->data.as_path.segments = NULL;
    as_path->data.as_path.segment_count = 0u;

    as4_path->data.as_path.segment_count = 1u;
    as4_path->data.as_path.segments = &segment;
    as4_path->data.as_path.is_4b = false;
    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_BAD_LEN, libbgp_pattr_write(as4_path, out, sizeof(out), NULL));
    as4_path->data.as_path.segments = NULL;
    as4_path->data.as_path.segment_count = 0u;

    unknown->flags = 0x8fu;
    unknown->type_code = 200u;
    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_BAD_LEN, libbgp_pattr_write(unknown, out, sizeof(out), &out_len));
    unknown->flags = 0x80u;
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_pattr_write(unknown, out, sizeof(out), &out_len));
    LIBBGP_ASSERT_EQ_U64(3u, out_len);
    LIBBGP_ASSERT_EQ_U64(0x80u, out[0]);

    libbgp_pattr_unref(unknown);
    libbgp_pattr_unref(as4_path);
    libbgp_pattr_unref(as_path);
    libbgp_pattr_unref(med);
    libbgp_pattr_unref(origin);
}

LIBBGP_TEST(pattr_parse_write_mp_reach_and_unreach_ipv6)
{
    const uint8_t mp_reach[] = {
        0x80u, 14u, 26u,
        0u, 2u, 1u, 16u,
        0x20u, 0x01u, 0x0du, 0xb8u, 0u, 0u, 0u, 0u,
        0u, 0u, 0u, 0u, 0u, 0u, 0u, 1u,
        0u,
        32u, 0x20u, 0x01u, 0x0du, 0xb8u
    };
    const uint8_t bad_nexthop[] = {
        0x80u, 14u, 8u, 0u, 2u, 1u, 3u, 1u, 2u, 3u, 0u
    };
    const uint8_t bad_snpa[] = {
        0x80u, 14u, 9u, 0u, 2u, 1u, 4u, 1u, 2u, 3u, 4u, 1u
    };
    const uint8_t mp_unreach[] = {
        0x80u, 15u, 8u, 0u, 2u, 1u, 32u, 0x20u, 0x01u, 0x0du, 0xb8u
    };
    libbgp_pattr_t *attr = libbgp_pattr_new(LIBBGP_PATTR_UNKNOWN);

    LIBBGP_ASSERT(attr != NULL);
    assert_roundtrip(attr, mp_reach, sizeof(mp_reach));
    LIBBGP_ASSERT_EQ_U64(16u, attr->data.mp_reach_ipv6.nexthop_len);
    LIBBGP_ASSERT_EQ_U64(1u, attr->data.mp_reach_ipv6.nlri_count);
    LIBBGP_ASSERT_EQ_U64(32u, attr->data.mp_reach_ipv6.nlri[0].len);
    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_INVALID, libbgp_pattr_parse(attr, bad_nexthop, sizeof(bad_nexthop), NULL));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_INVALID, libbgp_pattr_parse(attr, bad_snpa, sizeof(bad_snpa), NULL));
    assert_roundtrip(attr, mp_unreach, sizeof(mp_unreach));
    LIBBGP_ASSERT_EQ_U64(1u, attr->data.mp_unreach_ipv6.withdrawn_count);
    LIBBGP_ASSERT_EQ_U64(32u, attr->data.mp_unreach_ipv6.withdrawn[0].len);
    libbgp_pattr_unref(attr);
}

LIBBGP_TEST(pattr_mp_reach_unsupported_afi_safi_falls_back_to_unknown_passthrough)
{
    const uint8_t mp_reach[] = {
        0x80u, 14u, 9u,
        0u, 1u, 1u, 4u, 192u, 0u, 2u, 1u, 0u
    };
    libbgp_pattr_t *attr = libbgp_pattr_new(LIBBGP_PATTR_UNKNOWN);

    LIBBGP_ASSERT(attr != NULL);
    assert_roundtrip(attr, mp_reach, sizeof(mp_reach));
    LIBBGP_ASSERT_EQ_U64(LIBBGP_PATTR_UNKNOWN, attr->type);
    LIBBGP_ASSERT_EQ_U64(LIBBGP_PATTR_CODE_MP_REACH_NLRI, attr->type_code);
    LIBBGP_ASSERT_EQ_U64(sizeof(mp_reach) - 3u, attr->data.unknown.len);
    LIBBGP_ASSERT_BYTES_EQ(mp_reach + 3u, attr->data.unknown.value, sizeof(mp_reach) - 3u);

    libbgp_pattr_unref(attr);
}

LIBBGP_TEST(pattr_mp_unreach_unsupported_afi_safi_falls_back_to_unknown_passthrough)
{
    const uint8_t mp_unreach[] = {
        0x80u, 15u, 8u,
        0u, 1u, 1u, 32u, 192u, 0u, 2u, 0u
    };
    libbgp_pattr_t *attr = libbgp_pattr_new(LIBBGP_PATTR_UNKNOWN);

    LIBBGP_ASSERT(attr != NULL);
    assert_roundtrip(attr, mp_unreach, sizeof(mp_unreach));
    LIBBGP_ASSERT_EQ_U64(LIBBGP_PATTR_UNKNOWN, attr->type);
    LIBBGP_ASSERT_EQ_U64(LIBBGP_PATTR_CODE_MP_UNREACH_NLRI, attr->type_code);
    LIBBGP_ASSERT_EQ_U64(sizeof(mp_unreach) - 3u, attr->data.unknown.len);
    LIBBGP_ASSERT_BYTES_EQ(mp_unreach + 3u, attr->data.unknown.value, sizeof(mp_unreach) - 3u);

    libbgp_pattr_unref(attr);
}

LIBBGP_TEST(pattr_parse_write_mp_reach_ipv6_with_global_and_linklocal_nexthop)
{
    const uint8_t global_nexthop[] = {
        0x20u, 0x01u, 0x0du, 0xb8u, 0u, 0u, 0u, 0u,
        0u, 0u, 0u, 0u, 0u, 0u, 0u, 1u
    };
    const uint8_t linklocal_nexthop[] = {
        0xfeu, 0x80u, 0u, 0u, 0u, 0u, 0u, 0u,
        0u, 0u, 0u, 0u, 0u, 0u, 0u, 1u
    };
    const uint8_t mp_reach[] = {
        0x80u, 14u, 42u,
        0u, 2u, 1u, 32u,
        0x20u, 0x01u, 0x0du, 0xb8u, 0u, 0u, 0u, 0u,
        0u, 0u, 0u, 0u, 0u, 0u, 0u, 1u,
        0xfeu, 0x80u, 0u, 0u, 0u, 0u, 0u, 0u,
        0u, 0u, 0u, 0u, 0u, 0u, 0u, 1u,
        0u,
        32u, 0x20u, 0x01u, 0x0du, 0xb8u
    };
    libbgp_pattr_t *attr = libbgp_pattr_new(LIBBGP_PATTR_UNKNOWN);

    LIBBGP_ASSERT(attr != NULL);
    assert_roundtrip(attr, mp_reach, sizeof(mp_reach));
    LIBBGP_ASSERT_EQ_U64(LIBBGP_PATTR_MP_REACH_IPV6, attr->type);
    LIBBGP_ASSERT_EQ_U64(32u, attr->data.mp_reach_ipv6.nexthop_len);
    LIBBGP_ASSERT_BYTES_EQ(global_nexthop, attr->data.mp_reach_ipv6.nexthop, sizeof(global_nexthop));
    LIBBGP_ASSERT_BYTES_EQ(linklocal_nexthop, attr->data.mp_reach_ipv6.nexthop + 16u, sizeof(linklocal_nexthop));

    libbgp_pattr_unref(attr);
}

LIBBGP_TEST(pattr_parse_write_unknown_extended_and_zero_length)
{
    const uint8_t unknown[] = { 0x80u, 99u, 3u, 1u, 2u, 3u };
    const uint8_t extended[] = { 0x90u, 100u, 0x01u, 0x00u };
    const uint8_t zero[] = { 0x80u, 101u, 0u };
    uint8_t extended_wire[260];
    uint8_t out[260];
    size_t out_len = 0u;
    size_t i;
    libbgp_pattr_t *attr = libbgp_pattr_new(LIBBGP_PATTR_UNKNOWN);

    LIBBGP_ASSERT(attr != NULL);
    assert_roundtrip(attr, unknown, sizeof(unknown));
    LIBBGP_ASSERT_EQ_U64(99u, attr->type_code);
    LIBBGP_ASSERT_EQ_U64(3u, attr->data.unknown.len);
    assert_roundtrip(attr, zero, sizeof(zero));
    LIBBGP_ASSERT(attr->data.unknown.value == NULL);
    LIBBGP_ASSERT_EQ_U64(0u, attr->data.unknown.len);

    memcpy(extended_wire, extended, sizeof(extended));
    for (i = 0u; i < 256u; i++) {
        extended_wire[4u + i] = (uint8_t)i;
    }
    assert_roundtrip(attr, extended_wire, sizeof(extended_wire));

    attr->flags = 0x80u;
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_pattr_write(attr, out, sizeof(out), &out_len));
    LIBBGP_ASSERT_EQ_U64(sizeof(extended_wire), out_len);
    LIBBGP_ASSERT_EQ_U64(0x90u, out[0]);
    LIBBGP_ASSERT_BYTES_EQ(extended_wire + 1u, out + 1u, sizeof(extended_wire) - 1u);

    libbgp_pattr_unref(attr);
}

LIBBGP_TEST(pattr_format_provides_debug_strings)
{
    libbgp_pattr_t *origin = libbgp_pattr_new(LIBBGP_PATTR_ORIGIN);
    libbgp_pattr_t *as_path = libbgp_pattr_new(LIBBGP_PATTR_AS_PATH);
    libbgp_pattr_t *next_hop = libbgp_pattr_new(LIBBGP_PATTR_NEXT_HOP);
    libbgp_pattr_t *mp_reach = libbgp_pattr_new(LIBBGP_PATTR_MP_REACH_IPV6);
    libbgp_as_path_segment_t *segment;
    uint32_t *asns;
    libbgp_prefix6_t *prefix6;
    char buf[256];
    char tiny[8];
    size_t out_len = 0u;

    LIBBGP_ASSERT(origin != NULL);
    LIBBGP_ASSERT(as_path != NULL);
    LIBBGP_ASSERT(next_hop != NULL);
    LIBBGP_ASSERT(mp_reach != NULL);

    origin->data.origin.origin = 1u;
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_pattr_format(origin, buf, sizeof(buf), &out_len));
    LIBBGP_ASSERT(strstr(buf, "ORIGIN") != NULL);
    LIBBGP_ASSERT(strstr(buf, "origin=1") != NULL);
    LIBBGP_ASSERT_EQ_U64(strlen(buf), out_len);

    segment = (libbgp_as_path_segment_t *)calloc(1u, sizeof(*segment));
    asns = (uint32_t *)calloc(2u, sizeof(*asns));
    LIBBGP_ASSERT(segment != NULL);
    LIBBGP_ASSERT(asns != NULL);
    asns[0] = 64512u;
    asns[1] = 64513u;
    segment->type = 2u;
    segment->asn_count = 2u;
    segment->asns = asns;
    as_path->data.as_path.segment_count = 1u;
    as_path->data.as_path.segments = segment;
    as_path->data.as_path.is_4b = true;
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_pattr_format(as_path, buf, sizeof(buf), &out_len));
    LIBBGP_ASSERT(strstr(buf, "AS_PATH") != NULL);
    LIBBGP_ASSERT(strstr(buf, "64512") != NULL);
    LIBBGP_ASSERT(strstr(buf, "64513") != NULL);
    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_BUFFER, libbgp_pattr_format(as_path, tiny, sizeof(tiny), &out_len));
    LIBBGP_ASSERT(out_len >= sizeof(tiny));

    next_hop->data.next_hop.next_hop = 0xc0000201u;
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_pattr_format(next_hop, buf, sizeof(buf), NULL));
    LIBBGP_ASSERT(strstr(buf, "NEXT_HOP") != NULL);
    LIBBGP_ASSERT(strstr(buf, "0xc0000201") != NULL);

    prefix6 = (libbgp_prefix6_t *)calloc(1u, sizeof(*prefix6));
    LIBBGP_ASSERT(prefix6 != NULL);
    prefix6->addr[0] = 0x20u;
    prefix6->addr[1] = 0x01u;
    prefix6->addr[2] = 0x0du;
    prefix6->addr[3] = 0xb8u;
    prefix6->len = 32u;
    mp_reach->data.mp_reach_ipv6.nexthop[0] = 0x20u;
    mp_reach->data.mp_reach_ipv6.nexthop[1] = 0x01u;
    mp_reach->data.mp_reach_ipv6.nexthop_len = 16u;
    mp_reach->data.mp_reach_ipv6.nlri = prefix6;
    mp_reach->data.mp_reach_ipv6.nlri_count = 1u;
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_pattr_format(mp_reach, buf, sizeof(buf), NULL));
    LIBBGP_ASSERT(strstr(buf, "MP_REACH_IPV6") != NULL);
    LIBBGP_ASSERT(strstr(buf, "nexthop_len=16") != NULL);
    LIBBGP_ASSERT(strstr(buf, "nlri_count=1") != NULL);

    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_INVALID, libbgp_pattr_format(NULL, buf, sizeof(buf), NULL));

    libbgp_pattr_unref(mp_reach);
    libbgp_pattr_unref(next_hop);
    libbgp_pattr_unref(as_path);
    libbgp_pattr_unref(origin);
}

LIBBGP_TEST(pattr_forwarded_unknown_optional_transitive_sets_partial)
{
    const uint8_t raw[] = { 0xc0u, 99u, 2u, 0x12u, 0x34u };
    uint8_t out[16];
    size_t used = 0u;
    size_t out_len = 0u;
    libbgp_pattr_t *attr = libbgp_pattr_new(LIBBGP_PATTR_UNKNOWN);

    LIBBGP_ASSERT(attr != NULL);
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_pattr_parse(attr, raw, sizeof(raw), &used));
    LIBBGP_ASSERT_EQ_U64(sizeof(raw), used);
    LIBBGP_ASSERT_EQ_U64(0u, attr->flags & LIBBGP_PATTR_FLAG_PARTIAL);

    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_pattr_prepare_for_ebgp_forward(attr));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_pattr_write(attr, out, sizeof(out), &out_len));
    LIBBGP_ASSERT_EQ_U64(sizeof(raw), out_len);
    LIBBGP_ASSERT_EQ_U64(0xe0u, out[0]);
    LIBBGP_ASSERT_EQ_U64(99u, out[1]);

    libbgp_pattr_unref(attr);
}

LIBBGP_TEST(pattr_parse_write_error_edges_and_nomem_preserves_old_state)
{
    const uint8_t valid_unknown[] = { 0x80u, 99u, 2u, 1u, 2u };
    const uint8_t second_unknown[] = { 0x80u, 100u, 2u, 3u, 4u };
    const uint8_t short_header[] = { 0x80u, 1u };
    const uint8_t short_extended[] = { 0x90u, 1u, 0u };
    const uint8_t short_value[] = { 0x40u, 1u, 2u, 0u };
    uint8_t tiny[2];
    size_t marker = 77u;
    uint8_t *old_value;
    uint8_t old_copy[2];
    fail_after_alloc_ctx_t fail_ctx = { 0u, 1u };
    libbgp_alloc_t fail_alloc;
    libbgp_pattr_t *attr = libbgp_pattr_new(LIBBGP_PATTR_UNKNOWN);

    LIBBGP_ASSERT(attr != NULL);
    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_BAD_LEN, libbgp_pattr_parse(NULL, valid_unknown, sizeof(valid_unknown), &marker));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_BAD_LEN, libbgp_pattr_parse(attr, NULL, sizeof(valid_unknown), &marker));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_BAD_LEN, libbgp_pattr_parse(attr, short_header, sizeof(short_header), &marker));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_BAD_LEN, libbgp_pattr_parse(attr, short_extended, sizeof(short_extended), &marker));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_BAD_LEN, libbgp_pattr_parse(attr, short_value, sizeof(short_value), &marker));
    LIBBGP_ASSERT_EQ_U64(77u, marker);

    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_pattr_parse(attr, valid_unknown, sizeof(valid_unknown), NULL));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_BUFFER, libbgp_pattr_write(attr, tiny, sizeof(tiny), &marker));
    LIBBGP_ASSERT_EQ_U64(77u, marker);

    old_value = attr->data.unknown.value;
    memcpy(old_copy, old_value, sizeof(old_copy));
    fail_alloc = fail_after_alloc_make(&fail_ctx);
    libbgp_set_alloc(&fail_alloc);
    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_NOMEM, libbgp_pattr_parse(attr, second_unknown, sizeof(second_unknown), NULL));
    LIBBGP_ASSERT_EQ_U64(1u, fail_ctx.calls);
    LIBBGP_ASSERT_EQ_U64(99u, attr->type_code);
    LIBBGP_ASSERT(attr->data.unknown.value == old_value);
    LIBBGP_ASSERT_BYTES_EQ(old_copy, attr->data.unknown.value, sizeof(old_copy));
    libbgp_set_alloc(NULL);

    attr->data.unknown.len = 1u;
    attr->data.unknown.value = NULL;
    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_BAD_LEN, libbgp_pattr_write(attr, tiny, sizeof(tiny), NULL));
    attr->data.unknown.value = old_value;
    attr->data.unknown.len = sizeof(old_copy);
    libbgp_pattr_unref(attr);
}

int main(void)
{
    const libbgp_test_case_t tests[] = {
        { "pattr_new_ref_unref_initializes_representative_types", pattr_new_ref_unref_initializes_representative_types },
        { "pattr_type_from_buf_and_names", pattr_type_from_buf_and_names },
        { "pattr_parse_write_fixed_scalar_attributes", pattr_parse_write_fixed_scalar_attributes },
        { "pattr_parse_rejects_malformed_known_flags", pattr_parse_rejects_malformed_known_flags },
        { "pattr_parse_write_aggregator_community_and_as_paths", pattr_parse_write_aggregator_community_and_as_paths },
        { "pattr_write_rejects_type_code_and_as_width_mismatch", pattr_write_rejects_type_code_and_as_width_mismatch },
        { "pattr_parse_write_mp_reach_and_unreach_ipv6", pattr_parse_write_mp_reach_and_unreach_ipv6 },
        { "pattr_mp_reach_unsupported_afi_safi_falls_back_to_unknown_passthrough", pattr_mp_reach_unsupported_afi_safi_falls_back_to_unknown_passthrough },
        { "pattr_mp_unreach_unsupported_afi_safi_falls_back_to_unknown_passthrough", pattr_mp_unreach_unsupported_afi_safi_falls_back_to_unknown_passthrough },
        { "pattr_parse_write_mp_reach_ipv6_with_global_and_linklocal_nexthop", pattr_parse_write_mp_reach_ipv6_with_global_and_linklocal_nexthop },
        { "pattr_parse_write_unknown_extended_and_zero_length", pattr_parse_write_unknown_extended_and_zero_length },
        { "pattr_forwarded_unknown_optional_transitive_sets_partial", pattr_forwarded_unknown_optional_transitive_sets_partial },
        { "pattr_format_provides_debug_strings", pattr_format_provides_debug_strings },
        { "pattr_parse_write_error_edges_and_nomem_preserves_old_state", pattr_parse_write_error_edges_and_nomem_preserves_old_state }
    };

    return libbgp_run_tests("pattr", tests, LIBBGP_ARRAY_LEN(tests));
}
