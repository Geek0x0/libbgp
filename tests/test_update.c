#include "test_main.h"

#include "fixtures/bgp_packets.h"

#include "libbgp/update.h"
#include "libbgp/types.h"

static libbgp_pattr_t *make_as_path_attr(libbgp_pattr_type_t type, bool is_4b, const uint32_t *asns, size_t count)
{
    libbgp_pattr_t *attr = libbgp_pattr_new(type);

    LIBBGP_ASSERT(attr != NULL);
    attr->data.as_path.segment_count = 1u;
    attr->data.as_path.is_4b = is_4b;
    attr->data.as_path.segments = (libbgp_as_path_segment_t *)calloc(1u, sizeof(attr->data.as_path.segments[0]));
    LIBBGP_ASSERT(attr->data.as_path.segments != NULL);
    attr->data.as_path.segments[0].type = 2u;
    attr->data.as_path.segments[0].asn_count = count;
    if (count != 0u) {
        attr->data.as_path.segments[0].asns = (uint32_t *)calloc(count, sizeof(attr->data.as_path.segments[0].asns[0]));
        LIBBGP_ASSERT(attr->data.as_path.segments[0].asns != NULL);
        memcpy(attr->data.as_path.segments[0].asns, asns, count * sizeof(asns[0]));
    }
    return attr;
}

static libbgp_pattr_t *make_aggregator_attr(libbgp_pattr_type_t type, uint32_t asn, uint32_t router_id, bool is_4b)
{
    libbgp_pattr_t *attr = libbgp_pattr_new(type);

    LIBBGP_ASSERT(attr != NULL);
    attr->data.aggregator.asn = asn;
    attr->data.aggregator.router_id = router_id;
    attr->data.aggregator.is_4b = is_4b;
    return attr;
}

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
        0u, 18u,
        0x40u, 1u, 1u, 0u,
        0x40u, 2u, 4u, 2u, 1u, 0xfdu, 0xe8u,
        0x40u, 3u, 4u, 192u, 0u, 2u, 254u,
        24u, 203u, 0u, 113u
    };
    uint8_t out[64];
    size_t used = 0u;
    size_t out_len = 0u;
    libbgp_update_msg_t msg;
    libbgp_pattr_t *origin;
    libbgp_pattr_t *as_path;
    libbgp_pattr_t *next_hop;

    libbgp_update_init(&msg);
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_update_parse(&msg, body, sizeof(body), &used));
    LIBBGP_ASSERT_EQ_U64(sizeof(body), used);
    LIBBGP_ASSERT_EQ_U64(1u, msg.withdrawn_count);
    LIBBGP_ASSERT_EQ_U64(3u, msg.attr_count);
    LIBBGP_ASSERT_EQ_U64(1u, msg.nlri_count);
    LIBBGP_ASSERT_EQ_U64(24u, msg.withdrawn[0].len);
    LIBBGP_ASSERT_EQ_U64(24u, msg.nlri[0].len);

    origin = libbgp_update_find_attr(&msg, LIBBGP_PATTR_ORIGIN);
    as_path = libbgp_update_find_attr(&msg, LIBBGP_PATTR_AS_PATH);
    next_hop = libbgp_update_find_attr(&msg, LIBBGP_PATTR_NEXT_HOP);
    LIBBGP_ASSERT(origin != NULL);
    LIBBGP_ASSERT(as_path != NULL);
    LIBBGP_ASSERT(next_hop != NULL);
    LIBBGP_ASSERT_EQ_U64(0u, origin->data.origin.origin);
    LIBBGP_ASSERT_EQ_U64(65000u, as_path->data.as_path.segments[0].asns[0]);
    LIBBGP_ASSERT_EQ_U64(0xc00002feu, next_hop->data.next_hop.next_hop);

    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_update_write(&msg, out, sizeof(out), &out_len));
    LIBBGP_ASSERT_EQ_U64(sizeof(body), out_len);
    LIBBGP_ASSERT_BYTES_EQ(body, out, sizeof(body));
    libbgp_update_destroy(&msg);
}

LIBBGP_TEST(update_rejects_duplicate_attrs_and_missing_mandatory_attrs)
{
    const uint8_t missing_as_path_body[] = {
        0u, 0u,
        0u, 11u,
        0x40u, 1u, 1u, 0u,
        0x40u, 3u, 4u, 192u, 0u, 2u, 254u,
        24u, 203u, 0u, 113u
    };
    uint8_t out[64];
    size_t marker = 99u;
    libbgp_prefix4_t nlri;
    libbgp_update_msg_t msg;
    libbgp_pattr_t *origin = libbgp_pattr_new(LIBBGP_PATTR_ORIGIN);
    libbgp_pattr_t *duplicate_origin = libbgp_pattr_new(LIBBGP_PATTR_ORIGIN);

    LIBBGP_ASSERT(origin != NULL);
    LIBBGP_ASSERT(duplicate_origin != NULL);
    libbgp_update_init(&msg);
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_update_add_attr(&msg, origin));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_EXISTS, libbgp_update_add_attr(&msg, duplicate_origin));
    LIBBGP_ASSERT_EQ_U64(1u, msg.attr_count);
    libbgp_update_destroy(&msg);

    libbgp_update_init(&msg);
    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_INVALID,
        libbgp_update_parse(&msg, missing_as_path_body, sizeof(missing_as_path_body), &marker));
    LIBBGP_ASSERT_EQ_U64(99u, marker);
    nlri.addr = 0x7100cbu;
    nlri.len = 24u;
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_update_add_nlri(&msg, &nlri));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_INVALID, libbgp_update_validate(&msg));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_INVALID, libbgp_update_write(&msg, out, sizeof(out), &marker));

    libbgp_pattr_unref(duplicate_origin);
    libbgp_pattr_unref(origin);
    libbgp_update_destroy(&msg);
}

LIBBGP_TEST(update_parse_as4_reads_four_octet_as_path_and_aggregator)
{
    const uint8_t body[] = {
        0u, 0u,
        0u, 24u,
        0x40u, 2u, 10u, 2u, 2u,
        0u, 0u, 0xfdu, 0xe8u,
        0u, 1u, 0u, 2u,
        0xc0u, 7u, 8u, 0u, 1u, 0u, 1u, 198u, 51u, 100u, 1u
    };
    uint8_t out[64];
    size_t used = 0u;
    size_t out_len = 0u;
    libbgp_update_msg_t msg;
    libbgp_pattr_t *as_path;
    libbgp_pattr_t *aggregator;

    libbgp_update_init(&msg);
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_update_parse_as4(&msg, body, sizeof(body), true, &used));
    LIBBGP_ASSERT_EQ_U64(sizeof(body), used);
    as_path = libbgp_update_find_attr(&msg, LIBBGP_PATTR_AS_PATH);
    aggregator = libbgp_update_find_attr(&msg, LIBBGP_PATTR_AGGREGATOR);
    LIBBGP_ASSERT(as_path != NULL);
    LIBBGP_ASSERT(aggregator != NULL);
    LIBBGP_ASSERT(as_path->data.as_path.is_4b);
    LIBBGP_ASSERT_EQ_U64(65538u, as_path->data.as_path.segments[0].asns[1]);
    LIBBGP_ASSERT(aggregator->data.aggregator.is_4b);
    LIBBGP_ASSERT_EQ_U64(65537u, aggregator->data.aggregator.asn);
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_update_write(&msg, out, sizeof(out), &out_len));
    LIBBGP_ASSERT_EQ_U64(sizeof(body), out_len);
    LIBBGP_ASSERT_BYTES_EQ(body, out, sizeof(body));
    libbgp_update_destroy(&msg);
}

LIBBGP_TEST(update_as4_helpers_restore_downgrade_prepend_and_aggregator)
{
    uint32_t asns[] = { 65000u, 65537u };
    libbgp_update_msg_t msg;
    libbgp_pattr_t *as_path = make_as_path_attr(LIBBGP_PATTR_AS_PATH, true, asns, LIBBGP_ARRAY_LEN(asns));
    libbgp_pattr_t *aggregator = make_aggregator_attr(LIBBGP_PATTR_AGGREGATOR, 65537u, 0xc6336401u, true);
    libbgp_pattr_t *found;

    libbgp_update_init(&msg);
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_update_add_attr(&msg, as_path));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_update_add_attr(&msg, aggregator));

    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_update_downgrade_as_path(&msg));
    found = libbgp_update_find_attr(&msg, LIBBGP_PATTR_AS_PATH);
    LIBBGP_ASSERT(found != NULL);
    LIBBGP_ASSERT(!found->data.as_path.is_4b);
    LIBBGP_ASSERT_EQ_U64(LIBBGP_AS_TRANS, found->data.as_path.segments[0].asns[1]);
    found = libbgp_update_find_attr(&msg, LIBBGP_PATTR_AS4_PATH);
    LIBBGP_ASSERT(found != NULL);
    LIBBGP_ASSERT(found->data.as_path.is_4b);
    LIBBGP_ASSERT_EQ_U64(65537u, found->data.as_path.segments[0].asns[1]);

    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_update_restore_as_path(&msg));
    found = libbgp_update_find_attr(&msg, LIBBGP_PATTR_AS_PATH);
    LIBBGP_ASSERT(found != NULL);
    LIBBGP_ASSERT(found->data.as_path.is_4b);
    LIBBGP_ASSERT_EQ_U64(65537u, found->data.as_path.segments[0].asns[1]);
    LIBBGP_ASSERT(libbgp_update_find_attr(&msg, LIBBGP_PATTR_AS4_PATH) == NULL);

    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_update_prepend_asn(&msg, 65538u, true));
    found = libbgp_update_find_attr(&msg, LIBBGP_PATTR_AS_PATH);
    LIBBGP_ASSERT(found != NULL);
    LIBBGP_ASSERT_EQ_U64(3u, found->data.as_path.segments[0].asn_count);
    LIBBGP_ASSERT_EQ_U64(65538u, found->data.as_path.segments[0].asns[0]);

    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_update_downgrade_aggregator(&msg));
    found = libbgp_update_find_attr(&msg, LIBBGP_PATTR_AGGREGATOR);
    LIBBGP_ASSERT(found != NULL);
    LIBBGP_ASSERT(!found->data.aggregator.is_4b);
    LIBBGP_ASSERT_EQ_U64(LIBBGP_AS_TRANS, found->data.aggregator.asn);
    found = libbgp_update_find_attr(&msg, LIBBGP_PATTR_AS4_AGGREGATOR);
    LIBBGP_ASSERT(found != NULL);
    LIBBGP_ASSERT_EQ_U64(65537u, found->data.aggregator.asn);

    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_update_restore_aggregator(&msg));
    found = libbgp_update_find_attr(&msg, LIBBGP_PATTR_AGGREGATOR);
    LIBBGP_ASSERT(found != NULL);
    LIBBGP_ASSERT(found->data.aggregator.is_4b);
    LIBBGP_ASSERT_EQ_U64(65537u, found->data.aggregator.asn);

    libbgp_pattr_unref(aggregator);
    libbgp_pattr_unref(as_path);
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
        { "update_rejects_duplicate_attrs_and_missing_mandatory_attrs", update_rejects_duplicate_attrs_and_missing_mandatory_attrs },
        { "update_parse_as4_reads_four_octet_as_path_and_aggregator", update_parse_as4_reads_four_octet_as_path_and_aggregator },
        { "update_as4_helpers_restore_downgrade_prepend_and_aggregator", update_as4_helpers_restore_downgrade_prepend_and_aggregator },
        { "update_add_helpers_ref_attrs_and_write_fixture_body", update_add_helpers_ref_attrs_and_write_fixture_body },
        { "update_rejects_bad_lengths_and_small_output", update_rejects_bad_lengths_and_small_output }
    };

    return libbgp_run_tests("update", tests, LIBBGP_ARRAY_LEN(tests));
}
