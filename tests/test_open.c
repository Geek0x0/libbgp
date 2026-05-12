#include "test_main.h"

#include "fixtures/bgp_packets.h"

#include "libbgp/open.h"
#include "libbgp/types.h"

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

int main(void)
{
    const libbgp_test_case_t tests[] = {
        { "open_parse_write_two_byte_asn_fixture_body", open_parse_write_two_byte_asn_fixture_body },
        { "open_parse_write_four_byte_asn_and_mpbgp_caps", open_parse_write_four_byte_asn_and_mpbgp_caps },
        { "open_parse_accepts_unsupported_version_for_fsm_notification", open_parse_accepts_unsupported_version_for_fsm_notification },
        { "open_add_capability_refs_and_write_emits_capability_param", open_add_capability_refs_and_write_emits_capability_param },
        { "open_rejects_invalid_version_lengths_and_small_output", open_rejects_invalid_version_lengths_and_small_output },
        { "open_parse_optional_param_exact_boundary_and_trailing_short_header", open_parse_optional_param_exact_boundary_and_trailing_short_header },
        { "open_write_exact_fixed_len_boundary_and_nullable_out_len", open_write_exact_fixed_len_boundary_and_nullable_out_len },
        { "open_write_rejects_capability_count_without_capability_array", open_write_rejects_capability_count_without_capability_array }
    };

    return libbgp_run_tests("open", tests, LIBBGP_ARRAY_LEN(tests));
}
