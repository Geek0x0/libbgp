#include "test_main.h"

#include "fixtures/bgp_packets.h"

#include "libbgp/keepalive.h"
#include "libbgp/packet.h"
#include "libbgp/types.h"

LIBBGP_TEST(keepalive_body_parse_write_and_packet_fixture)
{
    uint8_t out[LIBBGP_BGP_HEADER_LEN];
    size_t used = 99u;
    size_t out_len = 99u;
    libbgp_packet_t pkt;

    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_keepalive_parse(NULL, 0u, &used));
    LIBBGP_ASSERT_EQ_U64(0u, used);
    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_BAD_LEN, libbgp_keepalive_parse(NULL, 1u, &used));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_keepalive_write(NULL, 0u, &out_len));
    LIBBGP_ASSERT_EQ_U64(0u, out_len);

    libbgp_packet_init(&pkt);
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_packet_parse(&pkt, LIBBGP_FIXTURE_KEEPALIVE, LIBBGP_FIXTURE_KEEPALIVE_LEN, &used));
    LIBBGP_ASSERT_EQ_U64(LIBBGP_FIXTURE_KEEPALIVE_LEN, used);
    LIBBGP_ASSERT_EQ_I64(LIBBGP_PACKET_KEEPALIVE, pkt.type);
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_packet_write(&pkt, out, sizeof(out), &out_len));
    LIBBGP_ASSERT_EQ_U64(LIBBGP_FIXTURE_KEEPALIVE_LEN, out_len);
    LIBBGP_ASSERT_BYTES_EQ(LIBBGP_FIXTURE_KEEPALIVE, out, out_len);
    libbgp_packet_destroy(&pkt);
}

static void assert_packet_roundtrip(
    const uint8_t *wire,
    size_t wire_len,
    libbgp_packet_type_t type)
{
    uint8_t out[256];
    size_t used = 0u;
    size_t out_len = 0u;
    libbgp_packet_t pkt;

    libbgp_packet_init(&pkt);
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_packet_parse(&pkt, wire, wire_len, &used));
    LIBBGP_ASSERT_EQ_U64(wire_len, used);
    LIBBGP_ASSERT_EQ_I64(type, pkt.type);
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_packet_write(&pkt, out, sizeof(out), &out_len));
    LIBBGP_ASSERT_EQ_U64(wire_len, out_len);
    LIBBGP_ASSERT_BYTES_EQ(wire, out, wire_len);
    libbgp_packet_destroy(&pkt);
}

LIBBGP_TEST(packet_parse_write_known_fixtures)
{
    assert_packet_roundtrip(LIBBGP_FIXTURE_OPEN_AS2, LIBBGP_FIXTURE_OPEN_AS2_LEN, LIBBGP_PACKET_OPEN);
    assert_packet_roundtrip(LIBBGP_FIXTURE_OPEN_AS4, LIBBGP_FIXTURE_OPEN_AS4_LEN, LIBBGP_PACKET_OPEN);
    assert_packet_roundtrip(LIBBGP_FIXTURE_UPDATE_EMPTY, LIBBGP_FIXTURE_UPDATE_EMPTY_LEN, LIBBGP_PACKET_UPDATE);
    assert_packet_roundtrip(LIBBGP_FIXTURE_UPDATE_IPV4, LIBBGP_FIXTURE_UPDATE_IPV4_LEN, LIBBGP_PACKET_UPDATE);
    assert_packet_roundtrip(LIBBGP_FIXTURE_NOTIFICATION_CEASE, LIBBGP_FIXTURE_NOTIFICATION_CEASE_LEN, LIBBGP_PACKET_NOTIFICATION);
}

LIBBGP_TEST(packet_rejects_marker_length_and_keepalive_body)
{
    uint8_t bad_marker[LIBBGP_FIXTURE_KEEPALIVE_LEN];
    uint8_t bad_min_len[LIBBGP_FIXTURE_KEEPALIVE_LEN];
    uint8_t bad_max_len[LIBBGP_FIXTURE_KEEPALIVE_LEN];
    uint8_t bad_keepalive_len[LIBBGP_BGP_HEADER_LEN + 1u];
    size_t marker = 99u;
    libbgp_packet_t pkt;

    memcpy(bad_marker, LIBBGP_FIXTURE_KEEPALIVE, sizeof(bad_marker));
    bad_marker[0] = 0u;
    memcpy(bad_min_len, LIBBGP_FIXTURE_KEEPALIVE, sizeof(bad_min_len));
    bad_min_len[17] = 18u;
    memcpy(bad_max_len, LIBBGP_FIXTURE_KEEPALIVE, sizeof(bad_max_len));
    bad_max_len[16] = 0x10u;
    bad_max_len[17] = 0x01u;
    memset(bad_keepalive_len, 0xff, 16u);
    bad_keepalive_len[16] = 0u;
    bad_keepalive_len[17] = 20u;
    bad_keepalive_len[18] = 4u;
    bad_keepalive_len[19] = 0u;

    libbgp_packet_init(&pkt);
    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_BAD_LEN, libbgp_packet_parse(NULL, bad_marker, sizeof(bad_marker), &marker));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_BAD_LEN, libbgp_packet_parse(&pkt, NULL, sizeof(bad_marker), &marker));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_BAD_LEN, libbgp_packet_parse(&pkt, bad_marker, LIBBGP_BGP_HEADER_LEN - 1u, &marker));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_INVALID, libbgp_packet_parse(&pkt, bad_marker, sizeof(bad_marker), &marker));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_BAD_LEN, libbgp_packet_parse(&pkt, bad_min_len, sizeof(bad_min_len), &marker));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_BAD_LEN, libbgp_packet_parse(&pkt, bad_max_len, sizeof(bad_max_len), &marker));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_BAD_LEN, libbgp_packet_parse(&pkt, bad_keepalive_len, sizeof(bad_keepalive_len), &marker));
    LIBBGP_ASSERT_EQ_U64(99u, marker);
    libbgp_packet_destroy(&pkt);
}

LIBBGP_TEST(packet_unknown_type_preserves_raw_body_and_write_small_output)
{
    const uint8_t unknown[] = {
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0x00, 0x16, 0x63,
        0xde, 0xad, 0xbe
    };
    uint8_t out[sizeof(unknown)];
    uint8_t small[sizeof(unknown) - 1u];
    size_t used = 0u;
    size_t out_len = 99u;
    libbgp_packet_t pkt;

    libbgp_packet_init(&pkt);
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_packet_parse(&pkt, unknown, sizeof(unknown), &used));
    LIBBGP_ASSERT_EQ_U64(sizeof(unknown), used);
    LIBBGP_ASSERT_EQ_I64(LIBBGP_PACKET_UNKNOWN, pkt.type);
    LIBBGP_ASSERT_EQ_U64(99u, pkt.raw_type);
    LIBBGP_ASSERT_EQ_U64(3u, pkt.raw_body_len);
    LIBBGP_ASSERT_BYTES_EQ(&unknown[19], pkt.raw_body, pkt.raw_body_len);
    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_BUFFER, libbgp_packet_write(&pkt, small, sizeof(small), &out_len));
    LIBBGP_ASSERT_EQ_U64(99u, out_len);
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_packet_write(&pkt, out, sizeof(out), &out_len));
    LIBBGP_ASSERT_EQ_U64(sizeof(unknown), out_len);
    LIBBGP_ASSERT_BYTES_EQ(unknown, out, sizeof(unknown));
    libbgp_packet_destroy(&pkt);
}

int main(void)
{
    const libbgp_test_case_t tests[] = {
        { "keepalive_body_parse_write_and_packet_fixture", keepalive_body_parse_write_and_packet_fixture },
        { "packet_parse_write_known_fixtures", packet_parse_write_known_fixtures },
        { "packet_rejects_marker_length_and_keepalive_body", packet_rejects_marker_length_and_keepalive_body },
        { "packet_unknown_type_preserves_raw_body_and_write_small_output", packet_unknown_type_preserves_raw_body_and_write_small_output }
    };

    return libbgp_run_tests("packet", tests, LIBBGP_ARRAY_LEN(tests));
}
