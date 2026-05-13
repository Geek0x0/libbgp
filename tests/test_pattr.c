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
    {
        const uint8_t expected_next_hop[] = { 192u, 0u, 2u, 1u };
        uint8_t stored_next_hop[4];

        memcpy(stored_next_hop, &attr->data.next_hop.next_hop, sizeof(stored_next_hop));
        LIBBGP_ASSERT_BYTES_EQ(expected_next_hop, stored_next_hop, sizeof(expected_next_hop));
    }
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

LIBBGP_TEST(pattr_parse_rejects_as_path_segment_count_overrun_variants)
{
    const uint8_t seq_declares_two_has_one[] = {
        LIBBGP_PATTR_FLAG_TRANSITIVE, LIBBGP_PATTR_CODE_AS_PATH, 4u,
        2u, 2u, 0xfdu, 0xe8u
    };
    const uint8_t set_declares_one_missing_asn[] = {
        LIBBGP_PATTR_FLAG_TRANSITIVE, LIBBGP_PATTR_CODE_AS_PATH, 2u,
        1u, 1u
    };
    const uint8_t zero_count_set[] = {
        LIBBGP_PATTR_FLAG_TRANSITIVE, LIBBGP_PATTR_CODE_AS_PATH, 2u,
        1u, 0u
    };
    size_t consumed = 99u;
    libbgp_pattr_t *attr = libbgp_pattr_new(LIBBGP_PATTR_UNKNOWN);

    LIBBGP_ASSERT(attr != NULL);
    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_BAD_LEN, libbgp_pattr_parse(attr, seq_declares_two_has_one, sizeof(seq_declares_two_has_one), &consumed));
    LIBBGP_ASSERT_EQ_U64(99u, consumed);
    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_BAD_LEN, libbgp_pattr_parse(attr, set_declares_one_missing_asn, sizeof(set_declares_one_missing_asn), &consumed));
    LIBBGP_ASSERT_EQ_U64(99u, consumed);
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_pattr_parse(attr, zero_count_set, sizeof(zero_count_set), &consumed));
    LIBBGP_ASSERT_EQ_U64(sizeof(zero_count_set), consumed);
    LIBBGP_ASSERT_EQ_U64(1u, attr->data.as_path.segment_count);
    LIBBGP_ASSERT_EQ_U64(0u, attr->data.as_path.segments[0].asn_count);
    LIBBGP_ASSERT(attr->data.as_path.segments[0].asns == NULL);

    libbgp_pattr_unref(attr);
}

LIBBGP_TEST(pattr_parse_as_path_allocation_failure_cleans_partial_segments)
{
    const uint8_t two_segments[] = {
        LIBBGP_PATTR_FLAG_TRANSITIVE, LIBBGP_PATTR_CODE_AS_PATH, 10u,
        2u, 1u, 0xfdu, 0xe8u,
        1u, 2u, 0xfdu, 0xe9u, 0xfdu, 0xeau
    };
    fail_after_alloc_ctx_t fail_ctx = { 0u, 3u };
    libbgp_alloc_t fail_alloc = fail_after_alloc_make(&fail_ctx);
    libbgp_err_t err;
    libbgp_pattr_t *attr = libbgp_pattr_new(LIBBGP_PATTR_UNKNOWN);

    LIBBGP_ASSERT(attr != NULL);
    libbgp_set_alloc(&fail_alloc);
    err = libbgp_pattr_parse(attr, two_segments, sizeof(two_segments), NULL);
    libbgp_set_alloc(NULL);

    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_NOMEM, err);
    LIBBGP_ASSERT_EQ_U64(3u, fail_ctx.calls);
    LIBBGP_ASSERT_EQ_U64(LIBBGP_PATTR_UNKNOWN, attr->type);
    LIBBGP_ASSERT(attr->data.unknown.value == NULL);

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

LIBBGP_TEST(pattr_wire_len_matches_write_and_rejects_invalid_write_state)
{
    uint8_t out[260];
    uint8_t unknown_value[256];
    size_t wire_len = 0u;
    size_t out_len = 0u;
    uint32_t bad_asn = 70000u;
    libbgp_as_path_segment_t segment;
    libbgp_pattr_t *origin = libbgp_pattr_new(LIBBGP_PATTR_ORIGIN);
    libbgp_pattr_t *unknown = libbgp_pattr_new(LIBBGP_PATTR_UNKNOWN);
    libbgp_pattr_t *as_path = libbgp_pattr_new(LIBBGP_PATTR_AS_PATH);

    LIBBGP_ASSERT(origin != NULL);
    LIBBGP_ASSERT(unknown != NULL);
    LIBBGP_ASSERT(as_path != NULL);
    memset(unknown_value, 0xa5, sizeof(unknown_value));

    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_pattr_wire_len(origin, &wire_len));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_pattr_write(origin, out, sizeof(out), &out_len));
    LIBBGP_ASSERT_EQ_U64(out_len, wire_len);
    LIBBGP_ASSERT_EQ_U64(4u, wire_len);

    origin->flags = LIBBGP_PATTR_FLAG_TRANSITIVE | LIBBGP_PATTR_FLAG_EXTENDED_LENGTH;
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_pattr_wire_len(origin, &wire_len));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_pattr_write(origin, out, sizeof(out), &out_len));
    LIBBGP_ASSERT_EQ_U64(out_len, wire_len);
    LIBBGP_ASSERT_EQ_U64(5u, wire_len);

    unknown->flags = LIBBGP_PATTR_FLAG_OPTIONAL;
    unknown->type_code = 200u;
    unknown->data.unknown.value = unknown_value;
    unknown->data.unknown.len = sizeof(unknown_value);
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_pattr_wire_len(unknown, &wire_len));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_pattr_write(unknown, out, sizeof(out), &out_len));
    LIBBGP_ASSERT_EQ_U64(out_len, wire_len);
    LIBBGP_ASSERT_EQ_U64(260u, wire_len);
    unknown->data.unknown.value = NULL;
    unknown->data.unknown.len = 0u;

    origin->data.origin.origin = 3u;
    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_BAD_LEN, libbgp_pattr_wire_len(origin, &wire_len));

    segment.type = 2u;
    segment.asn_count = 1u;
    segment.asns = &bad_asn;
    as_path->data.as_path.segment_count = 1u;
    as_path->data.as_path.segments = &segment;
    as_path->data.as_path.is_4b = false;
    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_BAD_LEN, libbgp_pattr_wire_len(as_path, &wire_len));
    as_path->data.as_path.segments = NULL;
    as_path->data.as_path.segment_count = 0u;

    libbgp_pattr_unref(as_path);
    libbgp_pattr_unref(unknown);
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

LIBBGP_TEST(pattr_mp_unreach_many_prefixes)
{
    uint8_t buf[512];
    size_t pos = 0u;
    size_t len_pos;
    size_t consumed = 0u;
    size_t i;
    uint16_t value_len;
    libbgp_pattr_t *attr;

    buf[pos++] = LIBBGP_PATTR_FLAG_OPTIONAL | LIBBGP_PATTR_FLAG_EXTENDED_LENGTH;
    buf[pos++] = LIBBGP_PATTR_CODE_MP_UNREACH_NLRI;
    len_pos = pos;
    pos += 2u;
    buf[pos++] = 0u;
    buf[pos++] = 2u;
    buf[pos++] = LIBBGP_SAFI_UNICAST;
    for (i = 0u; i < 30u; i++) {
        buf[pos++] = 48u;
        buf[pos++] = 0x20u;
        buf[pos++] = 0x01u;
        buf[pos++] = 0x0du;
        buf[pos++] = 0xb8u;
        buf[pos++] = (uint8_t)(i >> 8);
        buf[pos++] = (uint8_t)i;
    }
    value_len = (uint16_t)(pos - 4u);
    buf[len_pos] = (uint8_t)(value_len >> 8);
    buf[len_pos + 1u] = (uint8_t)value_len;

    attr = libbgp_pattr_new(LIBBGP_PATTR_UNKNOWN);
    LIBBGP_ASSERT(attr != NULL);
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_pattr_parse(attr, buf, pos, &consumed));
    LIBBGP_ASSERT_EQ_U64(pos, consumed);
    LIBBGP_ASSERT_EQ_U64(LIBBGP_PATTR_MP_UNREACH_IPV6, attr->type);
    LIBBGP_ASSERT_EQ_U64(30u, attr->data.mp_unreach_ipv6.withdrawn_count);
    LIBBGP_ASSERT(attr->data.mp_unreach_ipv6.withdrawn != NULL);
    LIBBGP_ASSERT_EQ_U64(48u, attr->data.mp_unreach_ipv6.withdrawn[0].len);
    LIBBGP_ASSERT_EQ_U64(48u, attr->data.mp_unreach_ipv6.withdrawn[29].len);
    LIBBGP_ASSERT_BYTES_EQ(buf + 8u, attr->data.mp_unreach_ipv6.withdrawn[0].addr, 6u);
    LIBBGP_ASSERT_BYTES_EQ(buf + 8u + 29u * 7u, attr->data.mp_unreach_ipv6.withdrawn[29].addr, 6u);

    libbgp_pattr_unref(attr);
}

LIBBGP_TEST(pattr_parse_mp_reach_ipv6_rejects_unsupported_nexthop_lengths)
{
    const uint8_t short_unsupported_nexthop[] = {
        LIBBGP_PATTR_FLAG_OPTIONAL, LIBBGP_PATTR_CODE_MP_REACH_NLRI, 8u,
        0u, 2u, 1u, 3u,
        0x20u, 0x01u, 0x0du, 0u
    };
    const uint8_t long_unsupported_nexthop[] = {
        LIBBGP_PATTR_FLAG_OPTIONAL, LIBBGP_PATTR_CODE_MP_REACH_NLRI, 38u,
        0u, 2u, 1u, 33u,
        0x20u, 0x01u, 0x0du, 0xb8u, 0u, 0u, 0u, 0u,
        0u, 0u, 0u, 0u, 0u, 0u, 0u, 1u,
        0xfeu, 0x80u, 0u, 0u, 0u, 0u, 0u, 0u,
        0u, 0u, 0u, 0u, 0u, 0u, 0u, 1u,
        0u, 0u
    };
    libbgp_pattr_t *attr = libbgp_pattr_new(LIBBGP_PATTR_UNKNOWN);

    LIBBGP_ASSERT(attr != NULL);
    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_INVALID, libbgp_pattr_parse(attr, short_unsupported_nexthop, sizeof(short_unsupported_nexthop), NULL));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_INVALID, libbgp_pattr_parse(attr, long_unsupported_nexthop, sizeof(long_unsupported_nexthop), NULL));

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

LIBBGP_TEST(pattr_next_hop_parse_write_preserves_network_order_bytes)
{
    const uint8_t raw[] = { 0x40u, 3u, 4u, 192u, 0u, 2u, 254u };
    const uint8_t expected_next_hop[] = { 192u, 0u, 2u, 254u };
    uint8_t stored_next_hop[4];
    uint8_t out[16];
    size_t used = 0u;
    size_t out_len = 0u;
    libbgp_pattr_t *attr = libbgp_pattr_new(LIBBGP_PATTR_NEXT_HOP);

    LIBBGP_ASSERT(attr != NULL);
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_pattr_parse(attr, raw, sizeof(raw), &used));
    LIBBGP_ASSERT_EQ_U64(sizeof(raw), used);
    memcpy(stored_next_hop, &attr->data.next_hop.next_hop, sizeof(stored_next_hop));
    LIBBGP_ASSERT_BYTES_EQ(expected_next_hop, stored_next_hop, sizeof(expected_next_hop));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_pattr_write(attr, out, sizeof(out), &out_len));
    LIBBGP_ASSERT_EQ_U64(sizeof(raw), out_len);
    LIBBGP_ASSERT_BYTES_EQ(raw, out, sizeof(raw));

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

LIBBGP_TEST(pattr_parse_rejects_invalid_fixed_attribute_lengths)
{
    const uint8_t origin_short[] = { 0x40u, 1u, 0u };
    const uint8_t origin_long[] = { 0x40u, 1u, 2u, 0u, 1u };
    const uint8_t next_hop_short[] = { 0x40u, 3u, 3u, 192u, 0u, 2u };
    const uint8_t next_hop_long[] = { 0x40u, 3u, 5u, 192u, 0u, 2u, 1u, 0u };
    const uint8_t med_short[] = { 0x80u, 4u, 3u, 0u, 0u, 1u };
    const uint8_t local_pref_long[] = { 0x40u, 5u, 5u, 0u, 0u, 0u, 100u, 0u };
    const uint8_t atomic_nonzero[] = { 0x40u, 6u, 1u, 0u };
    const uint8_t aggregator_short[] = { 0xc0u, 7u, 5u, 0xfdu, 0xe8u, 192u, 0u, 2u };
    const uint8_t aggregator_4b_short[] = { 0xc0u, 7u, 7u, 0u, 1u, 0u, 1u, 192u, 0u, 2u };
    const uint8_t as4_aggregator_short[] = { 0xc0u, 18u, 7u, 0u, 1u, 0u, 1u, 198u, 51u, 100u };
    libbgp_pattr_t *attr = libbgp_pattr_new(LIBBGP_PATTR_UNKNOWN);

    LIBBGP_ASSERT(attr != NULL);
    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_BAD_LEN, libbgp_pattr_parse(attr, origin_short, sizeof(origin_short), NULL));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_BAD_LEN, libbgp_pattr_parse(attr, origin_long, sizeof(origin_long), NULL));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_BAD_LEN, libbgp_pattr_parse(attr, next_hop_short, sizeof(next_hop_short), NULL));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_BAD_LEN, libbgp_pattr_parse(attr, next_hop_long, sizeof(next_hop_long), NULL));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_BAD_LEN, libbgp_pattr_parse(attr, med_short, sizeof(med_short), NULL));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_BAD_LEN, libbgp_pattr_parse(attr, local_pref_long, sizeof(local_pref_long), NULL));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_BAD_LEN, libbgp_pattr_parse(attr, atomic_nonzero, sizeof(atomic_nonzero), NULL));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_BAD_LEN, libbgp_pattr_parse(attr, aggregator_short, sizeof(aggregator_short), NULL));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_BAD_LEN, libbgp_pattr_parse_as4(attr, aggregator_4b_short, sizeof(aggregator_4b_short), true, NULL));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_BAD_LEN, libbgp_pattr_parse(attr, as4_aggregator_short, sizeof(as4_aggregator_short), NULL));

    libbgp_pattr_unref(attr);
}

LIBBGP_TEST(pattr_parse_rejects_malformed_mp_reach_and_unreach_lengths)
{
    const uint8_t mp_reach_too_short[] = { 0x80u, 14u, 4u, 0u, 2u, 1u, 16u };
    const uint8_t mp_reach_truncated_nexthop[] = {
        0x80u, 14u, 20u,
        0u, 2u, 1u, 32u,
        0x20u, 0x01u, 0x0du, 0xb8u, 0u, 0u, 0u, 0u,
        0u, 0u, 0u, 0u, 0u, 0u, 0u, 1u
    };
    const uint8_t mp_reach_truncated_prefix[] = {
        0x80u, 14u, 23u,
        0u, 2u, 1u, 16u,
        0x20u, 0x01u, 0x0du, 0xb8u, 0u, 0u, 0u, 0u,
        0u, 0u, 0u, 0u, 0u, 0u, 0u, 1u,
        0u,
        32u, 0x20u
    };
    const uint8_t mp_unreach_too_short[] = { 0x80u, 15u, 2u, 0u, 2u };
    const uint8_t mp_unreach_truncated_prefix[] = {
        0x80u, 15u, 5u,
        0u, 2u, 1u,
        32u, 0x20u
    };
    libbgp_pattr_t *attr = libbgp_pattr_new(LIBBGP_PATTR_UNKNOWN);

    LIBBGP_ASSERT(attr != NULL);
    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_BAD_LEN, libbgp_pattr_parse(attr, mp_reach_too_short, sizeof(mp_reach_too_short), NULL));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_BAD_LEN, libbgp_pattr_parse(attr, mp_reach_truncated_nexthop, sizeof(mp_reach_truncated_nexthop), NULL));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_BAD_LEN, libbgp_pattr_parse(attr, mp_reach_truncated_prefix, sizeof(mp_reach_truncated_prefix), NULL));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_BAD_LEN, libbgp_pattr_parse(attr, mp_unreach_too_short, sizeof(mp_unreach_too_short), NULL));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_BAD_LEN, libbgp_pattr_parse(attr, mp_unreach_truncated_prefix, sizeof(mp_unreach_truncated_prefix), NULL));

    libbgp_pattr_unref(attr);
}

LIBBGP_TEST(pattr_write_rejects_public_count_array_mismatches)
{
    uint8_t out[64];
    libbgp_pattr_t *community = libbgp_pattr_new(LIBBGP_PATTR_COMMUNITY);
    libbgp_pattr_t *mp_reach = libbgp_pattr_new(LIBBGP_PATTR_MP_REACH_IPV6);
    libbgp_pattr_t *mp_unreach = libbgp_pattr_new(LIBBGP_PATTR_MP_UNREACH_IPV6);
    libbgp_pattr_t *unknown = libbgp_pattr_new(LIBBGP_PATTR_UNKNOWN);

    LIBBGP_ASSERT(community != NULL);
    LIBBGP_ASSERT(mp_reach != NULL);
    LIBBGP_ASSERT(mp_unreach != NULL);
    LIBBGP_ASSERT(unknown != NULL);

    community->data.community.count = 1u;
    community->data.community.values = NULL;
    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_BAD_LEN, libbgp_pattr_write(community, out, sizeof(out), NULL));

    mp_reach->data.mp_reach_ipv6.nexthop_len = 16u;
    mp_reach->data.mp_reach_ipv6.nlri_count = 1u;
    mp_reach->data.mp_reach_ipv6.nlri = NULL;
    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_BAD_LEN, libbgp_pattr_write(mp_reach, out, sizeof(out), NULL));

    mp_unreach->data.mp_unreach_ipv6.withdrawn_count = 1u;
    mp_unreach->data.mp_unreach_ipv6.withdrawn = NULL;
    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_BAD_LEN, libbgp_pattr_write(mp_unreach, out, sizeof(out), NULL));

    unknown->flags = 0x80u;
    unknown->type_code = 99u;
    unknown->data.unknown.len = 1u;
    unknown->data.unknown.value = NULL;
    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_BAD_LEN, libbgp_pattr_write(unknown, out, sizeof(out), NULL));

    libbgp_pattr_unref(unknown);
    libbgp_pattr_unref(mp_unreach);
    libbgp_pattr_unref(mp_reach);
    libbgp_pattr_unref(community);
}

LIBBGP_TEST(pattr_write_rejects_small_output_for_computed_lengths)
{
    uint8_t out[6];
    size_t out_len = 123u;
    libbgp_pattr_t *local_pref = libbgp_pattr_new(LIBBGP_PATTR_LOCAL_PREF);
    libbgp_pattr_t *as4_aggregator = libbgp_pattr_new(LIBBGP_PATTR_AS4_AGGREGATOR);

    LIBBGP_ASSERT(local_pref != NULL);
    LIBBGP_ASSERT(as4_aggregator != NULL);
    local_pref->data.local_pref.value = 100u;
    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_BUFFER, libbgp_pattr_write(local_pref, out, sizeof(out), &out_len));
    LIBBGP_ASSERT_EQ_U64(123u, out_len);

    out_len = 123u;
    as4_aggregator->data.aggregator.asn = 65537u;
    as4_aggregator->data.aggregator.router_id = 0xc6336401u;
    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_BUFFER, libbgp_pattr_write(as4_aggregator, out, sizeof(out), &out_len));
    LIBBGP_ASSERT_EQ_U64(123u, out_len);

    libbgp_pattr_unref(as4_aggregator);
    libbgp_pattr_unref(local_pref);
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
    libbgp_err_t err;
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
    err = libbgp_pattr_parse(attr, second_unknown, sizeof(second_unknown), NULL);
    libbgp_set_alloc(NULL);
    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_NOMEM, err);
    LIBBGP_ASSERT_EQ_U64(1u, fail_ctx.calls);
    LIBBGP_ASSERT_EQ_U64(99u, attr->type_code);
    LIBBGP_ASSERT(attr->data.unknown.value == old_value);
    LIBBGP_ASSERT_BYTES_EQ(old_copy, attr->data.unknown.value, sizeof(old_copy));

    attr->data.unknown.len = 1u;
    attr->data.unknown.value = NULL;
    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_BAD_LEN, libbgp_pattr_write(attr, tiny, sizeof(tiny), NULL));
    attr->data.unknown.value = old_value;
    attr->data.unknown.len = sizeof(old_copy);
    libbgp_pattr_unref(attr);
}

LIBBGP_TEST(pattr_header_flag_type_and_public_error_variants)
{
    const uint8_t extended_header_too_short[] = { LIBBGP_PATTR_FLAG_OPTIONAL | LIBBGP_PATTR_FLAG_EXTENDED_LENGTH, 99u, 0u };
    const uint8_t unknown_partial_without_transitive[] = { 0xa0u, 99u, 0u };
    const uint8_t known_optional_transitive_partial[] = {
        0xe0u, LIBBGP_PATTR_CODE_COMMUNITY, 4u, 0u, 0u, 0u, 1u
    };
    uint8_t out[16];
    libbgp_pattr_t invalid_attr;
    libbgp_pattr_t *attr = libbgp_pattr_new(LIBBGP_PATTR_UNKNOWN);

    LIBBGP_ASSERT(attr != NULL);
    LIBBGP_ASSERT_EQ_I64(LIBBGP_PATTR_UNKNOWN, libbgp_pattr_type_from_buf(extended_header_too_short, sizeof(extended_header_too_short)));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_BAD_LEN, libbgp_pattr_write(NULL, out, sizeof(out), NULL));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_BAD_LEN, libbgp_pattr_write(attr, NULL, sizeof(out), NULL));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_INVALID, libbgp_pattr_parse(attr, unknown_partial_without_transitive, sizeof(unknown_partial_without_transitive), NULL));
    assert_roundtrip(attr, known_optional_transitive_partial, sizeof(known_optional_transitive_partial));
    LIBBGP_ASSERT_EQ_U64(0xe0u, attr->flags);

    memset(&invalid_attr, 0, sizeof(invalid_attr));
    invalid_attr.type = (libbgp_pattr_type_t)99;
    invalid_attr.flags = 0x80u;
    invalid_attr.type_code = 99u;
    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_BAD_LEN, libbgp_pattr_write(&invalid_attr, out, sizeof(out), NULL));

    libbgp_pattr_unref(attr);
}

LIBBGP_TEST(pattr_as_path_write_rejects_invalid_public_segments)
{
    uint8_t out[1024];
    uint32_t asns[] = { 1u };
    libbgp_as_path_segment_t segment;
    libbgp_pattr_t *attr = libbgp_pattr_new(LIBBGP_PATTR_AS_PATH);

    LIBBGP_ASSERT(attr != NULL);
    segment.type = 0u;
    segment.asn_count = 1u;
    segment.asns = asns;
    attr->data.as_path.segment_count = 1u;
    attr->data.as_path.segments = &segment;
    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_BAD_LEN, libbgp_pattr_write(attr, out, sizeof(out), NULL));

    segment.type = 3u;
    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_BAD_LEN, libbgp_pattr_write(attr, out, sizeof(out), NULL));

    segment.type = 2u;
    segment.asn_count = 256u;
    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_BAD_LEN, libbgp_pattr_write(attr, out, sizeof(out), NULL));

    segment.asn_count = 1u;
    attr->data.as_path.segments = NULL;
    attr->data.as_path.segment_count = 0u;
    libbgp_pattr_unref(attr);
}

LIBBGP_TEST(pattr_mp_ipv6_boundary_lengths_and_public_write_edges)
{
    const uint8_t mp_reach_no_nlri[] = {
        LIBBGP_PATTR_FLAG_OPTIONAL, LIBBGP_PATTR_CODE_MP_REACH_NLRI, 21u,
        0u, 2u, 1u, 16u,
        0x20u, 0x01u, 0x0du, 0xb8u, 0u, 0u, 0u, 0u,
        0u, 0u, 0u, 0u, 0u, 0u, 0u, 1u,
        0u
    };
    const uint8_t mp_unreach_no_withdrawn[] = {
        LIBBGP_PATTR_FLAG_OPTIONAL, LIBBGP_PATTR_CODE_MP_UNREACH_NLRI, 3u,
        0u, 2u, 1u
    };
    const uint8_t mp_reach_prefix_bounds[] = {
        LIBBGP_PATTR_FLAG_OPTIONAL, LIBBGP_PATTR_CODE_MP_REACH_NLRI, 38u,
        0u, 2u, 1u, 16u,
        0x20u, 0x01u, 0x0du, 0xb8u, 0u, 0u, 0u, 0u,
        0u, 0u, 0u, 0u, 0u, 0u, 0u, 1u,
        0u,
        128u, 0x20u, 0x01u, 0x0du, 0xb8u, 0u, 0u, 0u, 0u,
        0u, 0u, 0u, 0u, 0u, 0u, 0u, 1u
    };
    const uint8_t mp_unreach_prefix_bounds[] = {
        LIBBGP_PATTR_FLAG_OPTIONAL, LIBBGP_PATTR_CODE_MP_UNREACH_NLRI, 20u,
        0u, 2u, 1u,
        128u, 0x20u, 0x01u, 0x0du, 0xb8u, 0u, 0u, 0u, 0u,
        0u, 0u, 0u, 0u, 0u, 0u, 0u, 1u
    };
    uint8_t out[128];
    libbgp_prefix6_t bad_prefix;
    libbgp_pattr_t *attr = libbgp_pattr_new(LIBBGP_PATTR_UNKNOWN);
    libbgp_pattr_t *bad_reach = libbgp_pattr_new(LIBBGP_PATTR_MP_REACH_IPV6);
    libbgp_pattr_t *bad_unreach = libbgp_pattr_new(LIBBGP_PATTR_MP_UNREACH_IPV6);

    LIBBGP_ASSERT(attr != NULL);
    LIBBGP_ASSERT(bad_reach != NULL);
    LIBBGP_ASSERT(bad_unreach != NULL);
    assert_roundtrip(attr, mp_reach_no_nlri, sizeof(mp_reach_no_nlri));
    LIBBGP_ASSERT_EQ_U64(0u, attr->data.mp_reach_ipv6.nlri_count);
    assert_roundtrip(attr, mp_unreach_no_withdrawn, sizeof(mp_unreach_no_withdrawn));
    LIBBGP_ASSERT_EQ_U64(0u, attr->data.mp_unreach_ipv6.withdrawn_count);
    assert_roundtrip(attr, mp_reach_prefix_bounds, sizeof(mp_reach_prefix_bounds));
    LIBBGP_ASSERT_EQ_U64(1u, attr->data.mp_reach_ipv6.nlri_count);
    LIBBGP_ASSERT_EQ_U64(128u, attr->data.mp_reach_ipv6.nlri[0].len);
    assert_roundtrip(attr, mp_unreach_prefix_bounds, sizeof(mp_unreach_prefix_bounds));
    LIBBGP_ASSERT_EQ_U64(1u, attr->data.mp_unreach_ipv6.withdrawn_count);
    LIBBGP_ASSERT_EQ_U64(128u, attr->data.mp_unreach_ipv6.withdrawn[0].len);

    memset(&bad_prefix, 0, sizeof(bad_prefix));
    bad_prefix.len = 129u;
    bad_reach->data.mp_reach_ipv6.nexthop_len = 16u;
    bad_reach->data.mp_reach_ipv6.nlri_count = 1u;
    bad_reach->data.mp_reach_ipv6.nlri = &bad_prefix;
    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_BAD_LEN, libbgp_pattr_write(bad_reach, out, sizeof(out), NULL));
    bad_reach->data.mp_reach_ipv6.nlri = NULL;
    bad_reach->data.mp_reach_ipv6.nlri_count = 0u;

    bad_unreach->data.mp_unreach_ipv6.withdrawn_count = 1u;
    bad_unreach->data.mp_unreach_ipv6.withdrawn = &bad_prefix;
    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_BAD_LEN, libbgp_pattr_write(bad_unreach, out, sizeof(out), NULL));
    bad_unreach->data.mp_unreach_ipv6.withdrawn = NULL;
    bad_unreach->data.mp_unreach_ipv6.withdrawn_count = 0u;

    libbgp_pattr_unref(bad_unreach);
    libbgp_pattr_unref(bad_reach);
    libbgp_pattr_unref(attr);
}

LIBBGP_TEST(pattr_unknown_write_boundary_lengths)
{
    uint8_t value[256];
    uint8_t out[260];
    size_t out_len = 0u;
    size_t i;
    libbgp_pattr_t *attr = libbgp_pattr_new(LIBBGP_PATTR_UNKNOWN);

    LIBBGP_ASSERT(attr != NULL);
    for (i = 0u; i < sizeof(value); i++) {
        value[i] = (uint8_t)i;
    }
    attr->flags = LIBBGP_PATTR_FLAG_OPTIONAL;
    attr->type_code = 199u;
    attr->data.unknown.value = value;

    attr->data.unknown.len = 255u;
    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_BUFFER, libbgp_pattr_write(attr, out, 257u, &out_len));
    LIBBGP_ASSERT_EQ_U64(0u, out_len);
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_pattr_write(attr, out, 258u, &out_len));
    LIBBGP_ASSERT_EQ_U64(258u, out_len);
    LIBBGP_ASSERT_EQ_U64(LIBBGP_PATTR_FLAG_OPTIONAL, out[0]);
    LIBBGP_ASSERT_EQ_U64(255u, out[2]);

    out_len = 0u;
    attr->data.unknown.len = 256u;
    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_BUFFER, libbgp_pattr_write(attr, out, 259u, &out_len));
    LIBBGP_ASSERT_EQ_U64(0u, out_len);
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_pattr_write(attr, out, sizeof(out), &out_len));
    LIBBGP_ASSERT_EQ_U64(260u, out_len);
    LIBBGP_ASSERT_EQ_U64(LIBBGP_PATTR_FLAG_OPTIONAL | LIBBGP_PATTR_FLAG_EXTENDED_LENGTH, out[0]);
    LIBBGP_ASSERT_EQ_U64(1u, out[2]);
    LIBBGP_ASSERT_EQ_U64(0u, out[3]);

    attr->data.unknown.value = NULL;
    attr->data.unknown.len = 0u;
    libbgp_pattr_unref(attr);
}

LIBBGP_TEST(pattr_parse_allocation_failures_preserve_existing_state)
{
    const uint8_t valid_unknown[] = { 0x80u, 99u, 2u, 0xaau, 0xbbu };
    const uint8_t community[] = {
        0xc0u, LIBBGP_PATTR_CODE_COMMUNITY, 4u, 0u, 0u, 0u, 1u
    };
    const uint8_t mp_reach[] = {
        LIBBGP_PATTR_FLAG_OPTIONAL, LIBBGP_PATTR_CODE_MP_REACH_NLRI, 26u,
        0u, 2u, 1u, 16u,
        0x20u, 0x01u, 0x0du, 0xb8u, 0u, 0u, 0u, 0u,
        0u, 0u, 0u, 0u, 0u, 0u, 0u, 1u,
        0u,
        32u, 0x20u, 0x01u, 0x0du, 0xb8u
    };
    const uint8_t mp_unreach[] = {
        LIBBGP_PATTR_FLAG_OPTIONAL, LIBBGP_PATTR_CODE_MP_UNREACH_NLRI, 8u,
        0u, 2u, 1u, 32u, 0x20u, 0x01u, 0x0du, 0xb8u
    };
    fail_after_alloc_ctx_t fail_ctx = { 0u, 1u };
    libbgp_alloc_t fail_alloc = fail_after_alloc_make(&fail_ctx);
    libbgp_err_t err;
    libbgp_pattr_t *attr = libbgp_pattr_new(LIBBGP_PATTR_UNKNOWN);
    libbgp_pattr_t *new_attr;

    LIBBGP_ASSERT(attr != NULL);
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_pattr_parse(attr, valid_unknown, sizeof(valid_unknown), NULL));

    libbgp_set_alloc(&fail_alloc);
    new_attr = libbgp_pattr_new(LIBBGP_PATTR_ORIGIN);
    libbgp_set_alloc(NULL);
    LIBBGP_ASSERT(new_attr == NULL);
    LIBBGP_ASSERT_EQ_U64(1u, fail_ctx.calls);

    fail_ctx.calls = 0u;
    libbgp_set_alloc(&fail_alloc);
    err = libbgp_pattr_parse(attr, community, sizeof(community), NULL);
    libbgp_set_alloc(NULL);
    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_NOMEM, err);
    LIBBGP_ASSERT_EQ_U64(1u, fail_ctx.calls);
    LIBBGP_ASSERT_EQ_U64(LIBBGP_PATTR_UNKNOWN, attr->type);
    LIBBGP_ASSERT_EQ_U64(99u, attr->type_code);

    fail_ctx.calls = 0u;
    libbgp_set_alloc(&fail_alloc);
    err = libbgp_pattr_parse(attr, mp_reach, sizeof(mp_reach), NULL);
    libbgp_set_alloc(NULL);
    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_NOMEM, err);
    LIBBGP_ASSERT_EQ_U64(1u, fail_ctx.calls);
    LIBBGP_ASSERT_EQ_U64(LIBBGP_PATTR_UNKNOWN, attr->type);
    LIBBGP_ASSERT_EQ_U64(99u, attr->type_code);

    fail_ctx.calls = 0u;
    libbgp_set_alloc(&fail_alloc);
    err = libbgp_pattr_parse(attr, mp_unreach, sizeof(mp_unreach), NULL);
    libbgp_set_alloc(NULL);
    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_NOMEM, err);
    LIBBGP_ASSERT_EQ_U64(1u, fail_ctx.calls);
    LIBBGP_ASSERT_EQ_U64(LIBBGP_PATTR_UNKNOWN, attr->type);
    LIBBGP_ASSERT_EQ_U64(99u, attr->type_code);

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
        { "pattr_parse_rejects_as_path_segment_count_overrun_variants", pattr_parse_rejects_as_path_segment_count_overrun_variants },
        { "pattr_parse_as_path_allocation_failure_cleans_partial_segments", pattr_parse_as_path_allocation_failure_cleans_partial_segments },
        { "pattr_write_rejects_type_code_and_as_width_mismatch", pattr_write_rejects_type_code_and_as_width_mismatch },
        { "pattr_wire_len_matches_write_and_rejects_invalid_write_state", pattr_wire_len_matches_write_and_rejects_invalid_write_state },
        { "pattr_parse_write_mp_reach_and_unreach_ipv6", pattr_parse_write_mp_reach_and_unreach_ipv6 },
        { "pattr_mp_unreach_many_prefixes", pattr_mp_unreach_many_prefixes },
        { "pattr_parse_mp_reach_ipv6_rejects_unsupported_nexthop_lengths", pattr_parse_mp_reach_ipv6_rejects_unsupported_nexthop_lengths },
        { "pattr_mp_reach_unsupported_afi_safi_falls_back_to_unknown_passthrough", pattr_mp_reach_unsupported_afi_safi_falls_back_to_unknown_passthrough },
        { "pattr_mp_unreach_unsupported_afi_safi_falls_back_to_unknown_passthrough", pattr_mp_unreach_unsupported_afi_safi_falls_back_to_unknown_passthrough },
        { "pattr_parse_write_mp_reach_ipv6_with_global_and_linklocal_nexthop", pattr_parse_write_mp_reach_ipv6_with_global_and_linklocal_nexthop },
        { "pattr_parse_write_unknown_extended_and_zero_length", pattr_parse_write_unknown_extended_and_zero_length },
        { "pattr_forwarded_unknown_optional_transitive_sets_partial", pattr_forwarded_unknown_optional_transitive_sets_partial },
        { "pattr_next_hop_parse_write_preserves_network_order_bytes", pattr_next_hop_parse_write_preserves_network_order_bytes },
        { "pattr_format_provides_debug_strings", pattr_format_provides_debug_strings },
        { "pattr_parse_rejects_invalid_fixed_attribute_lengths", pattr_parse_rejects_invalid_fixed_attribute_lengths },
        { "pattr_parse_rejects_malformed_mp_reach_and_unreach_lengths", pattr_parse_rejects_malformed_mp_reach_and_unreach_lengths },
        { "pattr_write_rejects_public_count_array_mismatches", pattr_write_rejects_public_count_array_mismatches },
        { "pattr_write_rejects_small_output_for_computed_lengths", pattr_write_rejects_small_output_for_computed_lengths },
        { "pattr_parse_write_error_edges_and_nomem_preserves_old_state", pattr_parse_write_error_edges_and_nomem_preserves_old_state },
        { "pattr_header_flag_type_and_public_error_variants", pattr_header_flag_type_and_public_error_variants },
        { "pattr_as_path_write_rejects_invalid_public_segments", pattr_as_path_write_rejects_invalid_public_segments },
        { "pattr_mp_ipv6_boundary_lengths_and_public_write_edges", pattr_mp_ipv6_boundary_lengths_and_public_write_edges },
        { "pattr_unknown_write_boundary_lengths", pattr_unknown_write_boundary_lengths },
        { "pattr_parse_allocation_failures_preserve_existing_state", pattr_parse_allocation_failures_preserve_existing_state }
    };

    return libbgp_run_tests("pattr", tests, LIBBGP_ARRAY_LEN(tests));
}
