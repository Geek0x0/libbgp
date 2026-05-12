#include "test_main.h"

#include "fixtures/bgp_packets.h"

#include "libbgp/sink.h"
#include "libbgp/types.h"

LIBBGP_TEST(sink_feed_keepalive_and_pop)
{
    libbgp_sink_t sink;
    libbgp_packet_t pkt;

    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_sink_init(&sink));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_sink_feed(&sink, LIBBGP_FIXTURE_KEEPALIVE, LIBBGP_FIXTURE_KEEPALIVE_LEN));
    LIBBGP_ASSERT_EQ_U64(1u, libbgp_sink_packet_count(&sink));
    LIBBGP_ASSERT_EQ_U64(0u, libbgp_sink_buffered_len(&sink));

    libbgp_packet_init(&pkt);
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_sink_pop(&sink, &pkt));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_PACKET_KEEPALIVE, pkt.type);
    LIBBGP_ASSERT_EQ_U64(0u, libbgp_sink_packet_count(&sink));
    libbgp_packet_destroy(&pkt);
    libbgp_sink_destroy(&sink);
}

LIBBGP_TEST(sink_reassembles_fragmented_packet)
{
    libbgp_sink_t sink;
    libbgp_packet_t pkt;

    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_sink_init(&sink));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_sink_feed(&sink, LIBBGP_FIXTURE_KEEPALIVE, 10u));
    LIBBGP_ASSERT_EQ_U64(0u, libbgp_sink_packet_count(&sink));
    LIBBGP_ASSERT_EQ_U64(10u, libbgp_sink_buffered_len(&sink));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_sink_feed(&sink, LIBBGP_FIXTURE_KEEPALIVE + 10u, LIBBGP_FIXTURE_KEEPALIVE_LEN - 10u));
    LIBBGP_ASSERT_EQ_U64(1u, libbgp_sink_packet_count(&sink));

    libbgp_packet_init(&pkt);
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_sink_pop(&sink, &pkt));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_PACKET_KEEPALIVE, pkt.type);
    libbgp_packet_destroy(&pkt);
    libbgp_sink_destroy(&sink);
}

LIBBGP_TEST(sink_pops_multiple_packets_in_order)
{
    uint8_t two[LIBBGP_FIXTURE_KEEPALIVE_LEN + LIBBGP_FIXTURE_NOTIFICATION_CEASE_LEN];
    libbgp_sink_t sink;
    libbgp_packet_t pkt;

    memcpy(two, LIBBGP_FIXTURE_KEEPALIVE, LIBBGP_FIXTURE_KEEPALIVE_LEN);
    memcpy(two + LIBBGP_FIXTURE_KEEPALIVE_LEN, LIBBGP_FIXTURE_NOTIFICATION_CEASE, LIBBGP_FIXTURE_NOTIFICATION_CEASE_LEN);

    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_sink_init(&sink));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_sink_feed(&sink, two, sizeof(two)));
    LIBBGP_ASSERT_EQ_U64(2u, libbgp_sink_packet_count(&sink));

    libbgp_packet_init(&pkt);
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_sink_pop(&sink, &pkt));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_PACKET_KEEPALIVE, pkt.type);
    libbgp_packet_destroy(&pkt);
    libbgp_packet_init(&pkt);
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_sink_pop(&sink, &pkt));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_PACKET_NOTIFICATION, pkt.type);
    libbgp_packet_destroy(&pkt);
    libbgp_sink_destroy(&sink);
}

LIBBGP_TEST(sink_partial_header_reports_buffered_len)
{
    libbgp_sink_t sink;

    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_sink_init(&sink));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_sink_feed(&sink, LIBBGP_FIXTURE_KEEPALIVE, 18u));
    LIBBGP_ASSERT_EQ_U64(18u, libbgp_sink_buffered_len(&sink));
    LIBBGP_ASSERT_EQ_U64(0u, libbgp_sink_packet_count(&sink));
    libbgp_sink_destroy(&sink);
}

LIBBGP_TEST(sink_rejects_bad_length_and_clears_buffer)
{
    uint8_t bad[LIBBGP_FIXTURE_KEEPALIVE_LEN];
    libbgp_sink_t sink;

    memcpy(bad, LIBBGP_FIXTURE_KEEPALIVE, sizeof(bad));
    bad[16] = 0u;
    bad[17] = 18u;

    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_sink_init(&sink));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_BAD_LEN, libbgp_sink_feed(&sink, bad, sizeof(bad)));
    LIBBGP_ASSERT_EQ_U64(0u, libbgp_sink_buffered_len(&sink));
    LIBBGP_ASSERT_EQ_U64(0u, libbgp_sink_packet_count(&sink));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_sink_feed(&sink, LIBBGP_FIXTURE_KEEPALIVE, LIBBGP_FIXTURE_KEEPALIVE_LEN));
    LIBBGP_ASSERT_EQ_U64(1u, libbgp_sink_packet_count(&sink));
    libbgp_sink_destroy(&sink);
}

LIBBGP_TEST(sink_rejects_bad_marker_and_clears_buffer)
{
    uint8_t bad[LIBBGP_FIXTURE_KEEPALIVE_LEN];
    libbgp_sink_t sink;

    memcpy(bad, LIBBGP_FIXTURE_KEEPALIVE, sizeof(bad));
    bad[7] = 0u;

    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_sink_init(&sink));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_BAD_LEN, libbgp_sink_feed(&sink, bad, sizeof(bad)));
    LIBBGP_ASSERT_EQ_U64(0u, libbgp_sink_buffered_len(&sink));
    LIBBGP_ASSERT_EQ_U64(0u, libbgp_sink_packet_count(&sink));
    libbgp_sink_destroy(&sink);
}

LIBBGP_TEST(sink_zero_length_null_feed_is_noop)
{
    libbgp_sink_t sink;

    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_sink_init(&sink));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_sink_feed(&sink, NULL, 0u));
    LIBBGP_ASSERT_EQ_U64(0u, libbgp_sink_buffered_len(&sink));
    LIBBGP_ASSERT_EQ_U64(0u, libbgp_sink_packet_count(&sink));
    libbgp_sink_destroy(&sink);
}

LIBBGP_TEST(sink_pop_empty_and_null_output_are_errors)
{
    libbgp_sink_t sink;
    libbgp_packet_t pkt;

    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_sink_init(&sink));
    libbgp_packet_init(&pkt);
    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_NOT_FOUND, libbgp_sink_pop(&sink, &pkt));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_INVALID, libbgp_sink_pop(&sink, NULL));
    LIBBGP_ASSERT_EQ_U64(0u, libbgp_sink_packet_count(&sink));
    libbgp_packet_destroy(&pkt);
    libbgp_sink_destroy(&sink);
}

LIBBGP_TEST(sink_drops_bad_complete_frame_and_recovers_on_next_valid_packet)
{
    const uint8_t bad_open[] = {
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0x00, 0x1c, 0x01,
        0x04, 0xfd, 0xe8, 0x00, 0x5a, 0xcb, 0x00, 0x71, 0x01
    };
    libbgp_sink_t sink;
    libbgp_packet_t pkt;

    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_sink_init(&sink));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_BAD_LEN, libbgp_sink_feed(&sink, bad_open, sizeof(bad_open)));
    LIBBGP_ASSERT_EQ_U64(0u, libbgp_sink_packet_count(&sink));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_sink_feed(&sink, LIBBGP_FIXTURE_KEEPALIVE, LIBBGP_FIXTURE_KEEPALIVE_LEN));
    LIBBGP_ASSERT_EQ_U64(1u, libbgp_sink_packet_count(&sink));

    libbgp_packet_init(&pkt);
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_sink_pop(&sink, &pkt));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_PACKET_KEEPALIVE, pkt.type);
    libbgp_packet_destroy(&pkt);
    libbgp_sink_destroy(&sink);
}

LIBBGP_TEST(sink_clear_discards_packets_and_buffer)
{
    libbgp_sink_t sink;

    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_sink_init(&sink));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_sink_feed(&sink, LIBBGP_FIXTURE_NOTIFICATION_CEASE, LIBBGP_FIXTURE_NOTIFICATION_CEASE_LEN));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_sink_feed(&sink, LIBBGP_FIXTURE_KEEPALIVE, 5u));
    LIBBGP_ASSERT_EQ_U64(1u, libbgp_sink_packet_count(&sink));
    LIBBGP_ASSERT_EQ_U64(5u, libbgp_sink_buffered_len(&sink));
    libbgp_sink_clear(&sink);
    LIBBGP_ASSERT_EQ_U64(0u, libbgp_sink_packet_count(&sink));
    LIBBGP_ASSERT_EQ_U64(0u, libbgp_sink_buffered_len(&sink));
    libbgp_sink_destroy(&sink);
}

LIBBGP_TEST(sink_pop_moves_dynamic_packet_into_zeroed_output)
{
    const uint8_t unknown[] = {
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0x00, 0x16, 0x63,
        0xde, 0xad, 0xbe
    };
    libbgp_sink_t sink;
    libbgp_packet_t pkt;

    memset(&pkt, 0, sizeof(pkt));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_sink_init(&sink));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_sink_feed(&sink, unknown, sizeof(unknown)));
    LIBBGP_ASSERT_EQ_U64(1u, libbgp_sink_packet_count(&sink));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_sink_pop(&sink, &pkt));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_PACKET_UNKNOWN, pkt.type);
    LIBBGP_ASSERT_EQ_U64(99u, pkt.raw_type);
    LIBBGP_ASSERT_EQ_U64(3u, pkt.raw_body_len);
    LIBBGP_ASSERT_BYTES_EQ(&unknown[19], pkt.raw_body, pkt.raw_body_len);
    LIBBGP_ASSERT_EQ_U64(0u, libbgp_sink_packet_count(&sink));
    libbgp_packet_destroy(&pkt);
    libbgp_sink_clear(&sink);
    libbgp_sink_destroy(&sink);
}

LIBBGP_TEST(sink_as4_context_parses_four_octet_as_path)
{
    const uint8_t update4b[] = {
        0xffu, 0xffu, 0xffu, 0xffu, 0xffu, 0xffu, 0xffu, 0xffu,
        0xffu, 0xffu, 0xffu, 0xffu, 0xffu, 0xffu, 0xffu, 0xffu,
        0x00u, 0x24u, 0x02u,
        0x00u, 0x00u,
        0x00u, 0x0du,
        0x40u, 0x02u, 0x0au, 0x02u, 0x02u,
        0x00u, 0x00u, 0xfdu, 0xe8u,
        0x00u, 0x01u, 0x00u, 0x02u
    };
    libbgp_sink_t sink;
    libbgp_packet_t pkt;
    libbgp_pattr_t *as_path;

    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_sink_init_as4(&sink, true));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_sink_feed(&sink, update4b, sizeof(update4b)));
    LIBBGP_ASSERT_EQ_U64(1u, libbgp_sink_packet_count(&sink));

    libbgp_packet_init(&pkt);
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_sink_pop(&sink, &pkt));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_PACKET_UPDATE, pkt.type);
    as_path = libbgp_update_find_attr(&pkt.data.update, LIBBGP_PATTR_AS_PATH);
    LIBBGP_ASSERT(as_path != NULL);
    LIBBGP_ASSERT(as_path->data.as_path.is_4b);
    LIBBGP_ASSERT_EQ_U64(65538u, as_path->data.as_path.segments[0].asns[1]);

    libbgp_packet_destroy(&pkt);
    libbgp_sink_destroy(&sink);
}

int main(void)
{
    const libbgp_test_case_t tests[] = {
        { "sink_feed_keepalive_and_pop", sink_feed_keepalive_and_pop },
        { "sink_reassembles_fragmented_packet", sink_reassembles_fragmented_packet },
        { "sink_pops_multiple_packets_in_order", sink_pops_multiple_packets_in_order },
        { "sink_partial_header_reports_buffered_len", sink_partial_header_reports_buffered_len },
        { "sink_rejects_bad_length_and_clears_buffer", sink_rejects_bad_length_and_clears_buffer },
        { "sink_rejects_bad_marker_and_clears_buffer", sink_rejects_bad_marker_and_clears_buffer },
        { "sink_zero_length_null_feed_is_noop", sink_zero_length_null_feed_is_noop },
        { "sink_pop_empty_and_null_output_are_errors", sink_pop_empty_and_null_output_are_errors },
        { "sink_drops_bad_complete_frame_and_recovers_on_next_valid_packet", sink_drops_bad_complete_frame_and_recovers_on_next_valid_packet },
        { "sink_clear_discards_packets_and_buffer", sink_clear_discards_packets_and_buffer },
        { "sink_pop_moves_dynamic_packet_into_zeroed_output", sink_pop_moves_dynamic_packet_into_zeroed_output },
        { "sink_as4_context_parses_four_octet_as_path", sink_as4_context_parses_four_octet_as_path }
    };

    return libbgp_run_tests("sink", tests, LIBBGP_ARRAY_LEN(tests));
}
