#include "test_main.h"
#include "fixtures/alloc_tracker.h"

#include "libbgp/alloc.h"
#include "libbgp/capability.h"
#include "libbgp/types.h"

typedef struct fail_malloc_alloc_ctx {
    size_t malloc_calls;
    size_t free_calls;
} fail_malloc_alloc_ctx_t;

static void *fail_malloc_alloc_malloc(size_t size, void *ctx)
{
    fail_malloc_alloc_ctx_t *fail_ctx = (fail_malloc_alloc_ctx_t *)ctx;

    fail_ctx->malloc_calls++;
    (void)size;
    return NULL;
}

static void *fail_malloc_alloc_calloc(size_t nmemb, size_t size, void *ctx)
{
    (void)nmemb;
    (void)size;
    (void)ctx;
    return NULL;
}

static void *fail_malloc_alloc_realloc(void *ptr, size_t size, void *ctx)
{
    (void)ptr;
    (void)size;
    (void)ctx;
    return NULL;
}

static void fail_malloc_alloc_free(void *ptr, void *ctx)
{
    fail_malloc_alloc_ctx_t *fail_ctx = (fail_malloc_alloc_ctx_t *)ctx;

    fail_ctx->free_calls++;
    free(ptr);
}

static libbgp_alloc_t fail_malloc_alloc_make(fail_malloc_alloc_ctx_t *ctx)
{
    libbgp_alloc_t alloc;

    alloc.malloc = fail_malloc_alloc_malloc;
    alloc.calloc = fail_malloc_alloc_calloc;
    alloc.realloc = fail_malloc_alloc_realloc;
    alloc.free = fail_malloc_alloc_free;
    alloc.ctx = ctx;
    return alloc;
}

LIBBGP_TEST(capability_new_initializes_refcount_type_and_code)
{
    libbgp_capability_t *asn = libbgp_capability_new(LIBBGP_CAP_4B_ASN);
    libbgp_capability_t *mp = libbgp_capability_new(LIBBGP_CAP_MP_BGP);
    libbgp_capability_t *unknown = libbgp_capability_new(LIBBGP_CAP_UNKNOWN);

    LIBBGP_ASSERT(asn != NULL);
    LIBBGP_ASSERT_EQ_U64(1u, asn->refcount);
    LIBBGP_ASSERT_EQ_I64(LIBBGP_CAP_4B_ASN, asn->type);
    LIBBGP_ASSERT_EQ_U64(65u, asn->code);

    LIBBGP_ASSERT(mp != NULL);
    LIBBGP_ASSERT_EQ_U64(1u, mp->refcount);
    LIBBGP_ASSERT_EQ_I64(LIBBGP_CAP_MP_BGP, mp->type);
    LIBBGP_ASSERT_EQ_U64(1u, mp->code);

    LIBBGP_ASSERT(unknown != NULL);
    LIBBGP_ASSERT_EQ_U64(1u, unknown->refcount);
    LIBBGP_ASSERT_EQ_I64(LIBBGP_CAP_UNKNOWN, unknown->type);
    LIBBGP_ASSERT_EQ_U64(0u, unknown->code);
    LIBBGP_ASSERT(unknown->data.unknown.value == NULL);
    LIBBGP_ASSERT_EQ_U64(0u, unknown->data.unknown.len);

    LIBBGP_ASSERT(libbgp_capability_new((libbgp_cap_type_t)99) == NULL);

    libbgp_capability_unref(asn);
    libbgp_capability_unref(mp);
    libbgp_capability_unref(unknown);
}

LIBBGP_TEST(capability_ref_increments_and_unref_null_is_safe)
{
    libbgp_capability_t *cap = libbgp_capability_new(LIBBGP_CAP_UNKNOWN);

    LIBBGP_ASSERT(cap != NULL);
    LIBBGP_ASSERT(libbgp_capability_ref(NULL) == NULL);
    LIBBGP_ASSERT(libbgp_capability_ref(cap) == cap);
    LIBBGP_ASSERT_EQ_U64(2u, cap->refcount);

    libbgp_capability_unref(NULL);
    libbgp_capability_unref(cap);
    LIBBGP_ASSERT_EQ_U64(1u, cap->refcount);
    libbgp_capability_unref(cap);
}

LIBBGP_TEST(capability_ref_saturates_at_uint32_max)
{
    libbgp_capability_t *cap = libbgp_capability_new(LIBBGP_CAP_UNKNOWN);

    LIBBGP_ASSERT(cap != NULL);
    cap->refcount = UINT32_MAX;
    LIBBGP_ASSERT(libbgp_capability_ref(cap) == cap);
    LIBBGP_ASSERT_EQ_U64(UINT32_MAX, cap->refcount);

    cap->refcount = 1u;
    libbgp_capability_unref(cap);
}

LIBBGP_TEST(capability_parse_write_4b_asn_exact_bytes)
{
    const uint8_t in[] = { 65u, 4u, 0u, 1u, 0x02u, 0x03u };
    uint8_t out[6];
    size_t used = 0u;
    size_t out_len = 0u;
    libbgp_capability_t *cap = libbgp_capability_new(LIBBGP_CAP_UNKNOWN);

    LIBBGP_ASSERT(cap != NULL);
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_capability_parse(cap, in, sizeof(in), &used));
    LIBBGP_ASSERT_EQ_U64(sizeof(in), used);
    LIBBGP_ASSERT_EQ_U64(65u, cap->code);
    LIBBGP_ASSERT_EQ_I64(LIBBGP_CAP_4B_ASN, cap->type);
    LIBBGP_ASSERT_EQ_U64(0x00010203u, cap->data.asn_4b.asn);

    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_capability_write(cap, out, sizeof(out), &out_len));
    LIBBGP_ASSERT_EQ_U64(sizeof(in), out_len);
    LIBBGP_ASSERT_BYTES_EQ(in, out, sizeof(in));

    libbgp_capability_unref(cap);
}

LIBBGP_TEST(capability_parse_write_mp_bgp_exact_bytes)
{
    const uint8_t ipv4_in[] = { 1u, 4u, 0u, 1u, 0u, 1u };
    const uint8_t ipv6_in[] = { 1u, 4u, 0u, 2u, 0xffu, 1u };
    const uint8_t ipv6_out_exp[] = { 1u, 4u, 0u, 2u, 0u, 1u };
    uint8_t out[6];
    size_t used = 0u;
    size_t out_len = 0u;
    libbgp_capability_t *cap = libbgp_capability_new(LIBBGP_CAP_UNKNOWN);

    LIBBGP_ASSERT(cap != NULL);
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_capability_parse(cap, ipv4_in, sizeof(ipv4_in), &used));
    LIBBGP_ASSERT_EQ_U64(sizeof(ipv4_in), used);
    LIBBGP_ASSERT_EQ_U64(1u, cap->code);
    LIBBGP_ASSERT_EQ_I64(LIBBGP_CAP_MP_BGP, cap->type);
    LIBBGP_ASSERT_EQ_U64(LIBBGP_AFI_IPV4, cap->data.mp_bgp.afi);
    LIBBGP_ASSERT_EQ_U64(LIBBGP_SAFI_UNICAST, cap->data.mp_bgp.safi);
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_capability_write(cap, out, sizeof(out), &out_len));
    LIBBGP_ASSERT_EQ_U64(sizeof(ipv4_in), out_len);
    LIBBGP_ASSERT_BYTES_EQ(ipv4_in, out, sizeof(ipv4_in));

    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_capability_parse(cap, ipv6_in, sizeof(ipv6_in), &used));
    LIBBGP_ASSERT_EQ_U64(LIBBGP_AFI_IPV6, cap->data.mp_bgp.afi);
    LIBBGP_ASSERT_EQ_U64(LIBBGP_SAFI_UNICAST, cap->data.mp_bgp.safi);
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_capability_write(cap, out, sizeof(out), &out_len));
    LIBBGP_ASSERT_EQ_U64(sizeof(ipv6_out_exp), out_len);
    LIBBGP_ASSERT_BYTES_EQ(ipv6_out_exp, out, sizeof(ipv6_out_exp));

    libbgp_capability_unref(cap);
}

LIBBGP_TEST(capability_parse_write_unknown_passthrough_and_zero_length)
{
    const uint8_t unknown_in[] = { 200u, 3u, 0xaau, 0xbbu, 0xccu };
    const uint8_t zero_in[] = { 201u, 0u };
    uint8_t out[5];
    size_t used = 0u;
    size_t out_len = 0u;
    libbgp_capability_t *cap = libbgp_capability_new(LIBBGP_CAP_4B_ASN);

    LIBBGP_ASSERT(cap != NULL);
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_capability_parse(cap, unknown_in, sizeof(unknown_in), &used));
    LIBBGP_ASSERT_EQ_U64(sizeof(unknown_in), used);
    LIBBGP_ASSERT_EQ_U64(200u, cap->code);
    LIBBGP_ASSERT_EQ_I64(LIBBGP_CAP_UNKNOWN, cap->type);
    LIBBGP_ASSERT_EQ_U64(3u, cap->data.unknown.len);
    LIBBGP_ASSERT_BYTES_EQ(&unknown_in[2], cap->data.unknown.value, 3u);
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_capability_write(cap, out, sizeof(out), &out_len));
    LIBBGP_ASSERT_EQ_U64(sizeof(unknown_in), out_len);
    LIBBGP_ASSERT_BYTES_EQ(unknown_in, out, sizeof(unknown_in));

    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_capability_parse(cap, zero_in, sizeof(zero_in), &used));
    LIBBGP_ASSERT_EQ_U64(sizeof(zero_in), used);
    LIBBGP_ASSERT_EQ_U64(201u, cap->code);
    LIBBGP_ASSERT(cap->data.unknown.value == NULL);
    LIBBGP_ASSERT_EQ_U64(0u, cap->data.unknown.len);
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_capability_write(cap, out, sizeof(out), &out_len));
    LIBBGP_ASSERT_EQ_U64(sizeof(zero_in), out_len);
    LIBBGP_ASSERT_BYTES_EQ(zero_in, out, sizeof(zero_in));

    libbgp_capability_unref(cap);
}

LIBBGP_TEST(capability_parse_rejects_bad_lengths)
{
    const uint8_t short_header[] = { 65u };
    const uint8_t short_value[] = { 65u, 4u, 0u, 1u, 2u };
    const uint8_t asn_wrong_len[] = { 65u, 3u, 0u, 1u, 2u };
    const uint8_t mp_wrong_len[] = { 1u, 3u, 0u, 1u, 1u };
    const uint8_t valid[] = { 65u, 4u, 0u, 0u, 0u, 1u };
    size_t marker = 99u;
    libbgp_capability_t *cap = libbgp_capability_new(LIBBGP_CAP_UNKNOWN);

    LIBBGP_ASSERT(cap != NULL);
    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_BAD_LEN, libbgp_capability_parse(NULL, valid, sizeof(valid), &marker));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_BAD_LEN, libbgp_capability_parse(cap, NULL, sizeof(valid), &marker));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_BAD_LEN, libbgp_capability_parse(cap, short_header, sizeof(short_header), &marker));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_BAD_LEN, libbgp_capability_parse(cap, short_value, sizeof(short_value), &marker));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_BAD_LEN, libbgp_capability_parse(cap, asn_wrong_len, sizeof(asn_wrong_len), &marker));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_BAD_LEN, libbgp_capability_parse(cap, mp_wrong_len, sizeof(mp_wrong_len), &marker));
    LIBBGP_ASSERT_EQ_U64(99u, marker);

    libbgp_capability_unref(cap);
}

LIBBGP_TEST(capability_write_rejects_invalid_buffers_and_unknown_value)
{
    uint8_t out[5];
    size_t marker = 99u;
    libbgp_capability_t *cap = libbgp_capability_new(LIBBGP_CAP_4B_ASN);

    LIBBGP_ASSERT(cap != NULL);
    cap->data.asn_4b.asn = 1u;
    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_BAD_LEN, libbgp_capability_write(NULL, out, sizeof(out), &marker));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_BAD_LEN, libbgp_capability_write(cap, NULL, sizeof(out), &marker));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_BUFFER, libbgp_capability_write(cap, out, sizeof(out), &marker));
    LIBBGP_ASSERT_EQ_U64(99u, marker);

    cap->type = LIBBGP_CAP_UNKNOWN;
    cap->code = 202u;
    cap->data.unknown.value = NULL;
    cap->data.unknown.len = 1u;
    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_BAD_LEN, libbgp_capability_write(cap, out, sizeof(out), &marker));

    cap->data.unknown.len = 256u;
    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_BAD_LEN, libbgp_capability_write(cap, out, sizeof(out), &marker));

    cap->data.unknown.len = 0u;
    libbgp_capability_unref(cap);
}

LIBBGP_TEST(capability_unknown_parse_replaces_previous_unknown_value)
{
    const uint8_t first[] = { 210u, 2u, 1u, 2u };
    const uint8_t second[] = { 211u, 1u, 3u };
    libbgp_alloc_tracker_t tracker;
    libbgp_alloc_t alloc;
    libbgp_capability_t *cap;

    libbgp_alloc_tracker_init(&tracker);
    alloc = libbgp_alloc_tracker_make(&tracker);
    libbgp_set_alloc(&alloc);

    cap = libbgp_capability_new(LIBBGP_CAP_UNKNOWN);
    LIBBGP_ASSERT(cap != NULL);
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_capability_parse(cap, first, sizeof(first), NULL));
    LIBBGP_ASSERT_EQ_U64(1u, tracker.malloc_calls);
    LIBBGP_ASSERT_EQ_U64(1u, tracker.calloc_calls);
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_capability_parse(cap, second, sizeof(second), NULL));
    LIBBGP_ASSERT_EQ_U64(2u, tracker.malloc_calls);
    LIBBGP_ASSERT_EQ_U64(1u, tracker.free_calls);
    LIBBGP_ASSERT_EQ_U64(211u, cap->code);
    LIBBGP_ASSERT_EQ_U64(1u, cap->data.unknown.len);
    LIBBGP_ASSERT_BYTES_EQ(&second[2], cap->data.unknown.value, 1u);

    libbgp_capability_unref(cap);
    LIBBGP_ASSERT_EQ_U64(3u, tracker.free_calls);

    libbgp_set_alloc(NULL);
}

LIBBGP_TEST(capability_unknown_parse_nomem_preserves_existing_unknown)
{
    const uint8_t first[] = { 212u, 3u, 4u, 5u, 6u };
    const uint8_t second[] = { 213u, 2u, 7u, 8u };
    uint8_t expected_value[3];
    fail_malloc_alloc_ctx_t fail_ctx = { 0u, 0u };
    libbgp_alloc_t fail_alloc;
    libbgp_capability_t *cap = libbgp_capability_new(LIBBGP_CAP_UNKNOWN);
    uint8_t *old_value;

    LIBBGP_ASSERT(cap != NULL);
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_capability_parse(cap, first, sizeof(first), NULL));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_CAP_UNKNOWN, cap->type);
    LIBBGP_ASSERT_EQ_U64(212u, cap->code);
    LIBBGP_ASSERT_EQ_U64(3u, cap->data.unknown.len);
    LIBBGP_ASSERT(cap->data.unknown.value != NULL);
    old_value = cap->data.unknown.value;
    memcpy(expected_value, old_value, sizeof(expected_value));

    fail_alloc = fail_malloc_alloc_make(&fail_ctx);
    libbgp_set_alloc(&fail_alloc);
    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_NOMEM, libbgp_capability_parse(cap, second, sizeof(second), NULL));
    LIBBGP_ASSERT_EQ_U64(1u, fail_ctx.malloc_calls);
    LIBBGP_ASSERT_EQ_U64(0u, fail_ctx.free_calls);
    LIBBGP_ASSERT_EQ_I64(LIBBGP_CAP_UNKNOWN, cap->type);
    LIBBGP_ASSERT_EQ_U64(212u, cap->code);
    LIBBGP_ASSERT_EQ_U64(3u, cap->data.unknown.len);
    LIBBGP_ASSERT(cap->data.unknown.value == old_value);
    LIBBGP_ASSERT_BYTES_EQ(expected_value, cap->data.unknown.value, sizeof(expected_value));

    libbgp_set_alloc(NULL);
    libbgp_capability_unref(cap);
}

int main(void)
{
    const libbgp_test_case_t tests[] = {
        { "capability_new_initializes_refcount_type_and_code", capability_new_initializes_refcount_type_and_code },
        { "capability_ref_increments_and_unref_null_is_safe", capability_ref_increments_and_unref_null_is_safe },
        { "capability_ref_saturates_at_uint32_max", capability_ref_saturates_at_uint32_max },
        { "capability_parse_write_4b_asn_exact_bytes", capability_parse_write_4b_asn_exact_bytes },
        { "capability_parse_write_mp_bgp_exact_bytes", capability_parse_write_mp_bgp_exact_bytes },
        { "capability_parse_write_unknown_passthrough_and_zero_length", capability_parse_write_unknown_passthrough_and_zero_length },
        { "capability_parse_rejects_bad_lengths", capability_parse_rejects_bad_lengths },
        { "capability_write_rejects_invalid_buffers_and_unknown_value", capability_write_rejects_invalid_buffers_and_unknown_value },
        { "capability_unknown_parse_replaces_previous_unknown_value", capability_unknown_parse_replaces_previous_unknown_value },
        { "capability_unknown_parse_nomem_preserves_existing_unknown", capability_unknown_parse_nomem_preserves_existing_unknown }
    };

    return libbgp_run_tests("capability", tests, LIBBGP_ARRAY_LEN(tests));
}
