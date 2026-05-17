#include "test_main.h"

#include "fixtures/bgp_packets.h"

#include "libbgp/alloc.h"
#include "libbgp/open.h"
#include "libbgp/types.h"

typedef struct open_fail_realloc_ctx {
    size_t realloc_calls;
} open_fail_realloc_ctx_t;

static void *open_fail_realloc_malloc(size_t size, void *ctx)
{
    (void)ctx;
    return malloc(size);
}

static void *open_fail_realloc_calloc(size_t nmemb, size_t size, void *ctx)
{
    (void)ctx;
    return calloc(nmemb, size);
}

static void *open_fail_realloc_realloc(void *ptr, size_t size, void *ctx)
{
    open_fail_realloc_ctx_t *fail_ctx = (open_fail_realloc_ctx_t *)ctx;

    (void)ptr;
    (void)size;
    fail_ctx->realloc_calls++;
    return NULL;
}

static void open_fail_realloc_free(void *ptr, void *ctx)
{
    (void)ctx;
    free(ptr);
}

static libbgp_alloc_t open_fail_realloc_make(open_fail_realloc_ctx_t *ctx)
{
    libbgp_alloc_t alloc;

    alloc.malloc = open_fail_realloc_malloc;
    alloc.calloc = open_fail_realloc_calloc;
    alloc.realloc = open_fail_realloc_realloc;
    alloc.free = open_fail_realloc_free;
    alloc.ctx = ctx;
    return alloc;
}

LIBBGP_TEST(open_parse_write_two_byte_asn_fixture_body)
{
    const uint8_t *body = LIBBGP_FIXTURE_OPEN_AS2 + LIBBGP_BGP_HEADER_LEN;
    const size_t body_len = LIBBGP_FIXTURE_OPEN_AS2_LEN - LIBBGP_BGP_HEADER_LEN;
    uint8_t out[64];
    size_t used = 0u;
    size_t out_len = 0u;
    libbgp_open_msg_t msg;

    libbgp_open_init(&msg);
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_open_parse(&msg, body, body_len, &used));
    LIBBGP_ASSERT_EQ_U64(body_len, used);
    LIBBGP_ASSERT_EQ_U64(4u, msg.version);
    LIBBGP_ASSERT_EQ_U64(65000u, msg.my_asn);
    LIBBGP_ASSERT_EQ_U64(180u, msg.hold_time);
    LIBBGP_ASSERT_EQ_U64(0xc0000201u, msg.bgp_id);
    LIBBGP_ASSERT_EQ_U64(0u, msg.capability_count);
    LIBBGP_ASSERT_EQ_U64(65000u, libbgp_open_get_4b_asn(&msg));

    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_open_write(&msg, out, sizeof(out), &out_len));
    LIBBGP_ASSERT_EQ_U64(body_len, out_len);
    LIBBGP_ASSERT_BYTES_EQ(body, out, body_len);
    libbgp_open_destroy(&msg);
}

LIBBGP_TEST(open_parse_write_four_byte_asn_and_mpbgp_caps)
{
    const uint8_t body[] = {
        4u, 0x5bu, 0xa0u, 0u, 180u, 192u, 0u, 2u, 2u,
        14u,
        2u, 12u,
        65u, 4u, 0u, 1u, 0u, 1u,
        1u, 4u, 0u, 2u, 0u, 1u
    };
    uint8_t out[64];
    size_t used = 0u;
    size_t out_len = 0u;
    libbgp_open_msg_t msg;

    libbgp_open_init(&msg);
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_open_parse(&msg, body, sizeof(body), &used));
    LIBBGP_ASSERT_EQ_U64(sizeof(body), used);
    LIBBGP_ASSERT_EQ_U64(23456u, msg.my_asn);
    LIBBGP_ASSERT_EQ_U64(2u, msg.capability_count);
    LIBBGP_ASSERT_EQ_U64(65537u, libbgp_open_get_4b_asn(&msg));
    LIBBGP_ASSERT(libbgp_open_has_mpbgp(&msg, LIBBGP_AFI_IPV6, LIBBGP_SAFI_UNICAST));
    LIBBGP_ASSERT(!libbgp_open_has_mpbgp(&msg, LIBBGP_AFI_IPV4, LIBBGP_SAFI_UNICAST));

    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_open_write(&msg, out, sizeof(out), &out_len));
    LIBBGP_ASSERT_EQ_U64(sizeof(body), out_len);
    LIBBGP_ASSERT_BYTES_EQ(body, out, sizeof(body));
    libbgp_open_destroy(&msg);
}

LIBBGP_TEST(open_mpbgp_capability_requires_exact_afi_safi_rfc4760)
{
    const uint8_t body[] = {
        4u, 0x5bu, 0xa0u, 0u, 90u, 203u, 0u, 113u, 1u,
        8u,
        2u, 6u, 1u, 4u, 0u, 2u, 0u, 2u
    };
    size_t used = 0u;
    libbgp_open_msg_t msg;

    libbgp_open_init(&msg);
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_open_parse(&msg, body, sizeof(body), &used));
    LIBBGP_ASSERT_EQ_U64(sizeof(body), used);
    LIBBGP_ASSERT_EQ_U64(1u, msg.capability_count);
    LIBBGP_ASSERT(!libbgp_open_has_mpbgp(&msg, LIBBGP_AFI_IPV6, LIBBGP_SAFI_UNICAST));
    LIBBGP_ASSERT(!libbgp_open_has_mpbgp(&msg, LIBBGP_AFI_IPV4, LIBBGP_SAFI_UNICAST));
    libbgp_open_destroy(&msg);
}

LIBBGP_TEST(open_parse_accepts_unsupported_version_for_fsm_notification)
{
    const uint8_t body[] = { 3u, 0xfdu, 0xe8u, 0u, 90u, 203u, 0u, 113u, 1u, 0u };
    size_t used = 0u;
    libbgp_open_msg_t msg;

    libbgp_open_init(&msg);
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_open_parse(&msg, body, sizeof(body), &used));
    LIBBGP_ASSERT_EQ_U64(sizeof(body), used);
    LIBBGP_ASSERT_EQ_U64(3u, msg.version);
    LIBBGP_ASSERT_EQ_U64(65000u, msg.my_asn);
    LIBBGP_ASSERT_EQ_U64(90u, msg.hold_time);
    LIBBGP_ASSERT_EQ_U64(0xcb007101u, msg.bgp_id);
    libbgp_open_destroy(&msg);
}

LIBBGP_TEST(open_parse_multiple_capability_params_rfc5492)
{
    const uint8_t body[] = {
        4u, 0x5bu, 0xa0u, 0u, 90u, 203u, 0u, 113u, 1u,
        16u,
        2u, 6u, 65u, 4u, 0u, 1u, 0u, 1u,
        2u, 6u, 1u, 4u, 0u, 2u, 0u, 1u
    };
    uint8_t out[64];
    size_t used = 0u;
    size_t out_len = 0u;
    libbgp_open_msg_t msg;
    libbgp_open_msg_t reparsed;

    libbgp_open_init(&msg);
    libbgp_open_init(&reparsed);
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_open_parse(&msg, body, sizeof(body), &used));
    LIBBGP_ASSERT_EQ_U64(sizeof(body), used);
    LIBBGP_ASSERT_EQ_U64(2u, msg.capability_count);
    LIBBGP_ASSERT_EQ_U64(65537u, libbgp_open_get_4b_asn(&msg));
    LIBBGP_ASSERT(libbgp_open_has_mpbgp(&msg, LIBBGP_AFI_IPV6, LIBBGP_SAFI_UNICAST));

    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_open_write(&msg, out, sizeof(out), &out_len));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_open_parse(&reparsed, out, out_len, &used));
    LIBBGP_ASSERT_EQ_U64(out_len, used);
    LIBBGP_ASSERT_EQ_U64(2u, reparsed.capability_count);
    LIBBGP_ASSERT_EQ_U64(65537u, libbgp_open_get_4b_asn(&reparsed));
    LIBBGP_ASSERT(libbgp_open_has_mpbgp(&reparsed, LIBBGP_AFI_IPV6, LIBBGP_SAFI_UNICAST));
    libbgp_open_destroy(&reparsed);
    libbgp_open_destroy(&msg);
}

LIBBGP_TEST(open_add_capability_refs_and_write_emits_capability_param)
{
    const uint8_t expected[] = {
        4u, 0xfdu, 0xe8u, 0u, 90u, 203u, 0u, 113u, 1u,
        8u, 2u, 6u, 65u, 4u, 0u, 1u, 0u, 0u
    };
    uint8_t out[64];
    size_t out_len = 0u;
    libbgp_open_msg_t msg;
    libbgp_capability_t *cap = libbgp_capability_new(LIBBGP_CAP_4B_ASN);

    LIBBGP_ASSERT(cap != NULL);
    cap->data.asn_4b.asn = 65536u;
    libbgp_open_init(&msg);
    msg.version = 4u;
    msg.my_asn = 65000u;
    msg.hold_time = 90u;
    msg.bgp_id = 0xcb007101u;

    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_open_add_capability(&msg, cap));
    LIBBGP_ASSERT_EQ_U64(2u, cap->refcount);
    LIBBGP_ASSERT_EQ_U64(65536u, libbgp_open_get_4b_asn(&msg));
    libbgp_capability_unref(cap);
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_open_write(&msg, out, sizeof(out), &out_len));
    LIBBGP_ASSERT_EQ_U64(sizeof(expected), out_len);
    LIBBGP_ASSERT_BYTES_EQ(expected, out, sizeof(expected));
    libbgp_open_destroy(&msg);
}

LIBBGP_TEST(open_add_capability_rejects_null_inputs)
{
    libbgp_open_msg_t msg;
    libbgp_capability_t *cap = libbgp_capability_new(LIBBGP_CAP_4B_ASN);

    LIBBGP_ASSERT(cap != NULL);
    libbgp_open_init(&msg);

    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_BAD_LEN, libbgp_open_add_capability(NULL, cap));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_BAD_LEN, libbgp_open_add_capability(&msg, NULL));
    LIBBGP_ASSERT_EQ_U64(0u, msg.capability_count);
    LIBBGP_ASSERT(msg.capabilities == NULL);
    LIBBGP_ASSERT_EQ_U64(1u, cap->refcount);

    libbgp_capability_unref(cap);
    libbgp_open_destroy(&msg);
}

LIBBGP_TEST(open_init_destroy_null_and_lookup_null_are_safe)
{
    libbgp_open_init(NULL);
    libbgp_open_destroy(NULL);
    LIBBGP_ASSERT(!libbgp_open_has_4b_asn(NULL));
    LIBBGP_ASSERT_EQ_U64(0u, libbgp_open_get_4b_asn(NULL));
    LIBBGP_ASSERT(!libbgp_open_has_mpbgp(NULL, LIBBGP_AFI_IPV4, LIBBGP_SAFI_UNICAST));
}

LIBBGP_TEST(open_capability_lookup_skips_null_entries)
{
    libbgp_open_msg_t msg;

    libbgp_open_init(&msg);
    msg.my_asn = 65000u;
    msg.capability_count = 1u;
    msg.capabilities = (libbgp_capability_t **)calloc(1u, sizeof(msg.capabilities[0]));
    LIBBGP_ASSERT(msg.capabilities != NULL);

    LIBBGP_ASSERT(!libbgp_open_has_4b_asn(&msg));
    LIBBGP_ASSERT_EQ_U64(65000u, libbgp_open_get_4b_asn(&msg));
    LIBBGP_ASSERT(!libbgp_open_has_mpbgp(&msg, LIBBGP_AFI_IPV4, LIBBGP_SAFI_UNICAST));

    libbgp_open_destroy(&msg);
}

LIBBGP_TEST(open_add_capability_reports_nomem_without_ref_or_count_change)
{
    open_fail_realloc_ctx_t fail_ctx = { 0u };
    libbgp_alloc_t alloc = open_fail_realloc_make(&fail_ctx);
    libbgp_open_msg_t msg;
    libbgp_capability_t *cap = libbgp_capability_new(LIBBGP_CAP_4B_ASN);
    libbgp_err_t add_rc;
    size_t realloc_calls;
    size_t capability_count;
    bool capabilities_null;
    size_t refcount;

    LIBBGP_ASSERT(cap != NULL);
    libbgp_open_init(&msg);

    libbgp_set_alloc(&alloc);
    add_rc = libbgp_open_add_capability(&msg, cap);
    realloc_calls = fail_ctx.realloc_calls;
    capability_count = msg.capability_count;
    capabilities_null = msg.capabilities == NULL;
    refcount = cap->refcount;
    libbgp_set_alloc(NULL);

    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_NOMEM, add_rc);
    LIBBGP_ASSERT_EQ_U64(1u, realloc_calls);
    LIBBGP_ASSERT_EQ_U64(0u, capability_count);
    LIBBGP_ASSERT(capabilities_null);
    LIBBGP_ASSERT_EQ_U64(1u, refcount);

    libbgp_capability_unref(cap);
    libbgp_open_destroy(&msg);
}

LIBBGP_TEST(open_rejects_invalid_version_lengths_and_small_output)
{
    const uint8_t short_body[] = { 4u, 0u, 1u };
    const uint8_t bad_opt_len[] = { 4u, 0u, 1u, 0u, 90u, 1u, 2u, 3u, 4u, 2u, 99u };
    const uint8_t unknown_opt_param[] = { 4u, 0u, 1u, 0u, 90u, 1u, 2u, 3u, 4u, 3u, 99u, 1u, 0u };
    uint8_t out[9];
    size_t marker = 99u;
    libbgp_open_msg_t msg;

    libbgp_open_init(&msg);
    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_BAD_LEN, libbgp_open_parse(NULL, short_body, sizeof(short_body), &marker));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_BAD_LEN, libbgp_open_parse(&msg, NULL, sizeof(short_body), &marker));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_BAD_LEN, libbgp_open_parse(&msg, short_body, sizeof(short_body), &marker));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_BAD_LEN, libbgp_open_parse(&msg, bad_opt_len, sizeof(bad_opt_len), &marker));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_BAD_TYPE, libbgp_open_parse(&msg, unknown_opt_param, sizeof(unknown_opt_param), &marker));
    LIBBGP_ASSERT_EQ_U64(99u, marker);

    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_BAD_LEN, libbgp_open_write(NULL, out, sizeof(out), &marker));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_BAD_LEN, libbgp_open_write(&msg, NULL, sizeof(out), &marker));
    msg.version = 3u;
    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_BAD_LEN, libbgp_open_write(&msg, out, sizeof(out), &marker));
    msg.version = 4u;
    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_BUFFER, libbgp_open_write(&msg, out, sizeof(out), &marker));
    LIBBGP_ASSERT_EQ_U64(99u, marker);
    libbgp_open_destroy(&msg);
}

LIBBGP_TEST(open_parse_optional_param_exact_boundary_and_trailing_short_header)
{
    const uint8_t exact[] = {
        4u, 0xfdu, 0xe8u, 0u, 90u, 203u, 0u, 113u, 1u,
        8u, 2u, 6u, 65u, 4u, 0u, 1u, 0u, 0u
    };
    const uint8_t trailing_short_param[] = {
        4u, 0xfdu, 0xe8u, 0u, 90u, 203u, 0u, 113u, 1u,
        9u, 2u, 6u, 65u, 4u, 0u, 1u, 0u, 0u, 2u
    };
    size_t used = 99u;
    libbgp_open_msg_t msg;

    libbgp_open_init(&msg);
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_open_parse(&msg, exact, sizeof(exact), &used));
    LIBBGP_ASSERT_EQ_U64(sizeof(exact), used);
    LIBBGP_ASSERT_EQ_U64(1u, msg.capability_count);
    LIBBGP_ASSERT_EQ_U64(65536u, libbgp_open_get_4b_asn(&msg));
    libbgp_open_destroy(&msg);

    used = 99u;
    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_BAD_LEN, libbgp_open_parse(&msg, trailing_short_param, sizeof(trailing_short_param), &used));
    LIBBGP_ASSERT_EQ_U64(99u, used);
}

LIBBGP_TEST(open_parse_rejects_optional_parameter_overrun_rfc4271)
{
    const uint8_t param_overrun[] = {
        4u, 0xfdu, 0xe8u, 0u, 90u, 203u, 0u, 113u, 1u,
        3u, 2u, 2u, 65u
    };
    size_t used = 99u;
    libbgp_open_msg_t msg;

    libbgp_open_init(&msg);
    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_BAD_LEN,
        libbgp_open_parse(&msg, param_overrun, sizeof(param_overrun), &used));
    LIBBGP_ASSERT_EQ_U64(99u, used);
    LIBBGP_ASSERT_EQ_U64(0u, msg.capability_count);
    libbgp_open_destroy(&msg);
}

LIBBGP_TEST(open_parse_rejects_malformed_four_octet_asn_capability_rfc5492)
{
    const uint8_t malformed_as4_cap[] = {
        4u, 0xfdu, 0xe8u, 0u, 90u, 203u, 0u, 113u, 1u,
        5u, 2u, 3u, 65u, 1u, 0u
    };
    size_t used = 99u;
    libbgp_open_msg_t msg;

    libbgp_open_init(&msg);
    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_BAD_LEN,
        libbgp_open_parse(&msg, malformed_as4_cap, sizeof(malformed_as4_cap), &used));
    LIBBGP_ASSERT_EQ_U64(99u, used);
    LIBBGP_ASSERT_EQ_U64(0u, msg.capability_count);
    libbgp_open_destroy(&msg);
}

LIBBGP_TEST(open_write_exact_fixed_len_boundary_and_nullable_out_len)
{
    const uint8_t expected[] = { 4u, 0xfdu, 0xe8u, 0u, 90u, 203u, 0u, 113u, 1u, 0u };
    uint8_t out[sizeof(expected)];
    size_t out_len = 99u;
    libbgp_open_msg_t msg;

    libbgp_open_init(&msg);
    msg.version = 4u;
    msg.my_asn = 65000u;
    msg.hold_time = 90u;
    msg.bgp_id = 0xcb007101u;

    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_open_write(&msg, out, sizeof(out), &out_len));
    LIBBGP_ASSERT_EQ_U64(sizeof(expected), out_len);
    LIBBGP_ASSERT_BYTES_EQ(expected, out, sizeof(expected));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_open_write(&msg, out, sizeof(out), NULL));
    libbgp_open_destroy(&msg);
}

LIBBGP_TEST(open_write_rejects_capability_count_without_capability_array)
{
    uint8_t out[64];
    size_t out_len = 99u;
    libbgp_open_msg_t msg;

    libbgp_open_init(&msg);
    msg.version = 4u;
    msg.my_asn = 65000u;
    msg.hold_time = 90u;
    msg.bgp_id = 0xcb007101u;
    msg.capability_count = 1u;
    msg.capabilities = NULL;

    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_BAD_LEN, libbgp_open_write(&msg, out, sizeof(out), &out_len));
    LIBBGP_ASSERT_EQ_U64(99u, out_len);
    libbgp_open_destroy(&msg);
}

LIBBGP_TEST(open_write_rejects_oversized_capability_parameters_rfc4271_5492)
{
    uint8_t out[512];
    size_t out_len = 99u;
    libbgp_open_msg_t msg;
    libbgp_capability_t *cap1 = libbgp_capability_new(LIBBGP_CAP_UNKNOWN);
    libbgp_capability_t *cap2 = libbgp_capability_new(LIBBGP_CAP_UNKNOWN);
    uint8_t cap1_value[254];
    uint8_t cap2_value[2] = { 1u, 2u };

    LIBBGP_ASSERT(cap1 != NULL);
    LIBBGP_ASSERT(cap2 != NULL);
    memset(cap1_value, 0xa5u, sizeof(cap1_value));
    libbgp_open_init(&msg);
    msg.version = 4u;
    msg.my_asn = 65000u;
    msg.hold_time = 90u;
    msg.bgp_id = 0xcb007101u;

    cap1->code = 201u;
    cap1->data.unknown.len = sizeof(cap1_value);
    cap1->data.unknown.value = cap1_value;
    cap2->code = 202u;
    cap2->data.unknown.len = sizeof(cap2_value);
    cap2->data.unknown.value = cap2_value;
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_open_add_capability(&msg, cap1));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_open_add_capability(&msg, cap2));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_BAD_LEN, libbgp_open_write(&msg, out, sizeof(out), &out_len));
    LIBBGP_ASSERT_EQ_U64(99u, out_len);

    cap2->data.unknown.value = NULL;
    cap2->data.unknown.len = 0u;
    cap1->data.unknown.value = NULL;
    cap1->data.unknown.len = 0u;
    libbgp_capability_unref(cap2);
    libbgp_capability_unref(cap1);
    libbgp_open_destroy(&msg);
}

int main(void)
{
    const libbgp_test_case_t tests[] = {
        { "open_parse_write_two_byte_asn_fixture_body", open_parse_write_two_byte_asn_fixture_body },
        { "open_parse_write_four_byte_asn_and_mpbgp_caps", open_parse_write_four_byte_asn_and_mpbgp_caps },
        { "open_mpbgp_capability_requires_exact_afi_safi_rfc4760", open_mpbgp_capability_requires_exact_afi_safi_rfc4760 },
        { "open_parse_accepts_unsupported_version_for_fsm_notification", open_parse_accepts_unsupported_version_for_fsm_notification },
        { "open_parse_multiple_capability_params_rfc5492", open_parse_multiple_capability_params_rfc5492 },
        { "open_add_capability_refs_and_write_emits_capability_param", open_add_capability_refs_and_write_emits_capability_param },
        { "open_add_capability_rejects_null_inputs", open_add_capability_rejects_null_inputs },
        { "open_init_destroy_null_and_lookup_null_are_safe", open_init_destroy_null_and_lookup_null_are_safe },
        { "open_capability_lookup_skips_null_entries", open_capability_lookup_skips_null_entries },
        { "open_add_capability_reports_nomem_without_ref_or_count_change", open_add_capability_reports_nomem_without_ref_or_count_change },
        { "open_rejects_invalid_version_lengths_and_small_output", open_rejects_invalid_version_lengths_and_small_output },
        { "open_parse_optional_param_exact_boundary_and_trailing_short_header", open_parse_optional_param_exact_boundary_and_trailing_short_header },
        { "open_parse_rejects_optional_parameter_overrun_rfc4271", open_parse_rejects_optional_parameter_overrun_rfc4271 },
        { "open_parse_rejects_malformed_four_octet_asn_capability_rfc5492", open_parse_rejects_malformed_four_octet_asn_capability_rfc5492 },
        { "open_write_exact_fixed_len_boundary_and_nullable_out_len", open_write_exact_fixed_len_boundary_and_nullable_out_len },
        { "open_write_rejects_capability_count_without_capability_array", open_write_rejects_capability_count_without_capability_array },
        { "open_write_rejects_oversized_capability_parameters_rfc4271_5492", open_write_rejects_oversized_capability_parameters_rfc4271_5492 }
    };

    return libbgp_run_tests("open", tests, LIBBGP_ARRAY_LEN(tests));
}
