#include "test_main.h"

#include "fixtures/bgp_packets.h"

#include "libbgp/update.h"
#include "libbgp/types.h"

LIBBGP_TEST(update_parse_write_empty_fixture_body)
{
    const uint8_t *body = LIBBGP_FIXTURE_UPDATE_EMPTY + LIBBGP_BGP_HEADER_LEN;
    const size_t body_len = LIBBGP_FIXTURE_UPDATE_EMPTY_LEN - LIBBGP_BGP_HEADER_LEN;
    uint8_t out[16];
    size_t used = 0u;
    size_t out_len = 0u;
    libbgp_update_msg_t msg;

    libbgp_update_init(&msg);
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_update_parse(&msg, body, body_len, &used));
    LIBBGP_ASSERT_EQ_U64(body_len, used);
    LIBBGP_ASSERT_EQ_U64(0u, msg.withdrawn_count);
    LIBBGP_ASSERT_EQ_U64(0u, msg.attr_count);
    LIBBGP_ASSERT_EQ_U64(0u, msg.nlri_count);
    LIBBGP_ASSERT(libbgp_update_find_attr(&msg, LIBBGP_PATTR_ORIGIN) == NULL);

    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_update_write(&msg, out, sizeof(out), &out_len));
    LIBBGP_ASSERT_EQ_U64(body_len, out_len);
    LIBBGP_ASSERT_BYTES_EQ(body, out, body_len);
    libbgp_update_destroy(&msg);
}

LIBBGP_TEST(update_parse_write_with_withdrawn_attrs_and_nlri)
{
    const uint8_t body[] = {
        0u, 4u,
        24u, 198u, 51u, 100u,
        0u, 11u,
        0x40u, 1u, 1u, 0u,
        0x40u, 3u, 4u, 192u, 0u, 2u, 254u,
        24u, 203u, 0u, 113u
    };
    uint8_t out[64];
    size_t used = 0u;
    size_t out_len = 0u;
    libbgp_update_msg_t msg;
    libbgp_pattr_t *origin;
    libbgp_pattr_t *next_hop;

    libbgp_update_init(&msg);
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_update_parse(&msg, body, sizeof(body), &used));
    LIBBGP_ASSERT_EQ_U64(sizeof(body), used);
    LIBBGP_ASSERT_EQ_U64(1u, msg.withdrawn_count);
    LIBBGP_ASSERT_EQ_U64(2u, msg.attr_count);
    LIBBGP_ASSERT_EQ_U64(1u, msg.nlri_count);
    LIBBGP_ASSERT_EQ_U64(24u, msg.withdrawn[0].len);
    LIBBGP_ASSERT_EQ_U64(24u, msg.nlri[0].len);

    origin = libbgp_update_find_attr(&msg, LIBBGP_PATTR_ORIGIN);
    next_hop = libbgp_update_find_attr(&msg, LIBBGP_PATTR_NEXT_HOP);
    LIBBGP_ASSERT(origin != NULL);
    LIBBGP_ASSERT(next_hop != NULL);
    LIBBGP_ASSERT_EQ_U64(0u, origin->data.origin.origin);
    LIBBGP_ASSERT_EQ_U64(0xc00002feu, next_hop->data.next_hop.next_hop);

    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_update_write(&msg, out, sizeof(out), &out_len));
    LIBBGP_ASSERT_EQ_U64(sizeof(body), out_len);
    LIBBGP_ASSERT_BYTES_EQ(body, out, sizeof(body));
    libbgp_update_destroy(&msg);
}

LIBBGP_TEST(update_add_helpers_ref_attrs_and_write_fixture_body)
{
    const uint8_t *expected = LIBBGP_FIXTURE_UPDATE_IPV4 + LIBBGP_BGP_HEADER_LEN;
    const size_t expected_len = LIBBGP_FIXTURE_UPDATE_IPV4_LEN - LIBBGP_BGP_HEADER_LEN;
    uint8_t out[64];
    size_t out_len = 0u;
    libbgp_update_msg_t msg;
    libbgp_prefix4_t nlri;
    libbgp_pattr_t *origin = libbgp_pattr_new(LIBBGP_PATTR_ORIGIN);
    libbgp_pattr_t *as_path = libbgp_pattr_new(LIBBGP_PATTR_AS_PATH);
    libbgp_pattr_t *next_hop = libbgp_pattr_new(LIBBGP_PATTR_NEXT_HOP);
    uint32_t *asns;
    libbgp_as_path_segment_t *segment;

    LIBBGP_ASSERT(origin != NULL);
    LIBBGP_ASSERT(as_path != NULL);
    LIBBGP_ASSERT(next_hop != NULL);
    asns = (uint32_t *)malloc(sizeof(asns[0]));
    segment = (libbgp_as_path_segment_t *)calloc(1u, sizeof(segment[0]));
    LIBBGP_ASSERT(asns != NULL);
    LIBBGP_ASSERT(segment != NULL);
    asns[0] = 65000u;
    origin->data.origin.origin = 0u;
    segment->type = 2u;
    segment->asn_count = 1u;
    segment->asns = asns;
    as_path->data.as_path.segment_count = 1u;
    as_path->data.as_path.segments = segment;
    next_hop->data.next_hop.next_hop = 0xc00002feu;
    nlri.addr = 0x7100cbu;
    nlri.len = 24u;

    libbgp_update_init(&msg);
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_update_add_attr(&msg, origin));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_update_add_attr(&msg, as_path));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_update_add_attr(&msg, next_hop));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_update_add_nlri(&msg, &nlri));
    LIBBGP_ASSERT_EQ_U64(2u, origin->refcount);
    LIBBGP_ASSERT(libbgp_update_find_attr(&msg, LIBBGP_PATTR_NEXT_HOP) == next_hop);
    libbgp_pattr_unref(origin);
    libbgp_pattr_unref(as_path);
    libbgp_pattr_unref(next_hop);

    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_update_write(&msg, out, sizeof(out), &out_len));
    LIBBGP_ASSERT_EQ_U64(expected_len, out_len);
    LIBBGP_ASSERT_BYTES_EQ(expected, out, expected_len);
    libbgp_update_destroy(&msg);
}

LIBBGP_TEST(update_rejects_bad_lengths_and_small_output)
{
    const uint8_t short_len[] = { 0u };
    const uint8_t bad_withdrawn_len[] = { 0u, 4u, 24u, 192u, 0u };
    const uint8_t bad_attr_len[] = { 0u, 0u, 0u, 4u, 0x40u, 1u, 1u };
    uint8_t out[3];
    size_t marker = 99u;
    libbgp_update_msg_t msg;

    libbgp_update_init(&msg);
    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_BAD_LEN, libbgp_update_parse(NULL, short_len, sizeof(short_len), &marker));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_BAD_LEN, libbgp_update_parse(&msg, NULL, sizeof(short_len), &marker));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_BAD_LEN, libbgp_update_parse(&msg, short_len, sizeof(short_len), &marker));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_BAD_LEN, libbgp_update_parse(&msg, bad_withdrawn_len, sizeof(bad_withdrawn_len), &marker));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_BAD_LEN, libbgp_update_parse(&msg, bad_attr_len, sizeof(bad_attr_len), &marker));
    LIBBGP_ASSERT_EQ_U64(99u, marker);

    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_BAD_LEN, libbgp_update_write(NULL, out, sizeof(out), &marker));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_BAD_LEN, libbgp_update_write(&msg, NULL, sizeof(out), &marker));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_BUFFER, libbgp_update_write(&msg, out, sizeof(out), &marker));
    LIBBGP_ASSERT_EQ_U64(99u, marker);
    libbgp_update_destroy(&msg);
}

int main(void)
{
    const libbgp_test_case_t tests[] = {
        { "update_parse_write_empty_fixture_body", update_parse_write_empty_fixture_body },
        { "update_parse_write_with_withdrawn_attrs_and_nlri", update_parse_write_with_withdrawn_attrs_and_nlri },
        { "update_add_helpers_ref_attrs_and_write_fixture_body", update_add_helpers_ref_attrs_and_write_fixture_body },
        { "update_rejects_bad_lengths_and_small_output", update_rejects_bad_lengths_and_small_output }
    };

    return libbgp_run_tests("update", tests, LIBBGP_ARRAY_LEN(tests));
}
