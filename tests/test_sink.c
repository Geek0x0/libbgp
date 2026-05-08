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

int main(void)
{
    const libbgp_test_case_t tests[] = {
        { "sink_feed_keepalive_and_pop", sink_feed_keepalive_and_pop },
        { "sink_reassembles_fragmented_packet", sink_reassembles_fragmented_packet },
        { "sink_pops_multiple_packets_in_order", sink_pops_multiple_packets_in_order },
        { "sink_partial_header_reports_buffered_len", sink_partial_header_reports_buffered_len },
        { "sink_rejects_bad_length_and_clears_buffer", sink_rejects_bad_length_and_clears_buffer },
        { "sink_clear_discards_packets_and_buffer", sink_clear_discards_packets_and_buffer }
    };

    return libbgp_run_tests("sink", tests, LIBBGP_ARRAY_LEN(tests));
}
