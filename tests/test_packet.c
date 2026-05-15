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
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_keepalive_parse(NULL, 0u, NULL));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_BAD_LEN, libbgp_keepalive_parse(NULL, 1u, &used));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_keepalive_write(NULL, 0u, &out_len));
    LIBBGP_ASSERT_EQ_U64(0u, out_len);
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_keepalive_write(NULL, 0u, NULL));

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

LIBBGP_TEST(packet_write_keepalive_is_byte_for_byte_deterministic)
{
    uint8_t first[LIBBGP_BGP_HEADER_LEN];
    uint8_t second[LIBBGP_BGP_HEADER_LEN];
    size_t first_len = 0u;
    size_t second_len = 0u;
    size_t i;
    libbgp_packet_t pkt;

    memset(first, 0xa5, sizeof(first));
    memset(second, 0x5a, sizeof(second));
    libbgp_packet_init(&pkt);
    pkt.type = LIBBGP_PACKET_KEEPALIVE;

    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_packet_write(&pkt, first, sizeof(first), &first_len));
    LIBBGP_ASSERT_EQ_U64(LIBBGP_BGP_HEADER_LEN, first_len);
    for (i = 0u; i < LIBBGP_BGP_MARKER_LEN; i++) {
        LIBBGP_ASSERT_EQ_I64(0xff, first[i]);
    }
    LIBBGP_ASSERT_BYTES_EQ(LIBBGP_FIXTURE_KEEPALIVE, first, first_len);

    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_packet_write(&pkt, second, sizeof(second), &second_len));
    LIBBGP_ASSERT_EQ_U64(first_len, second_len);
    LIBBGP_ASSERT_BYTES_EQ(first, second, first_len);
    libbgp_packet_destroy(&pkt);
}

/* Regression: non-zero-body packet (OPEN) must be byte-for-byte deterministic regardless of
 * initial contents of the destination buffer. Ensures body is fully written into caller buffer
 * and header backfilled without leftover bytes. */
LIBBGP_TEST(packet_write_open_is_byte_for_byte_deterministic)
{
    uint8_t first[LIBBGP_FIXTURE_OPEN_AS2_LEN];
    uint8_t second[LIBBGP_FIXTURE_OPEN_AS2_LEN];
    size_t first_len = 0u;
    size_t second_len = 0u;
    libbgp_packet_t pkt;

    memset(first, 0xa5, sizeof(first));
    memset(second, 0x5a, sizeof(second));

    libbgp_packet_init(&pkt);
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_packet_parse(&pkt, LIBBGP_FIXTURE_OPEN_AS2, LIBBGP_FIXTURE_OPEN_AS2_LEN, NULL));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_PACKET_OPEN, pkt.type);

    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_packet_write(&pkt, first, sizeof(first), &first_len));
    LIBBGP_ASSERT_EQ_U64(LIBBGP_FIXTURE_OPEN_AS2_LEN, first_len);
    LIBBGP_ASSERT_BYTES_EQ(LIBBGP_FIXTURE_OPEN_AS2, first, first_len);

    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_packet_write(&pkt, second, sizeof(second), &second_len));
    LIBBGP_ASSERT_EQ_U64(first_len, second_len);
    LIBBGP_ASSERT_BYTES_EQ(first, second, first_len);
    libbgp_packet_destroy(&pkt);
}

/* Regression: when the caller provides a buffer smaller than the BGP header for a known
 * packet (e.g. OPEN), libbgp_packet_write must return LIBBGP_ERR_BUFFER and must not
 * mutate the caller's buffer. */
LIBBGP_TEST(packet_write_known_small_buffer_preserves_output_and_returns_buffer)
{
    uint8_t out[64];
    uint8_t expected[sizeof(out)];
    size_t out_len = 99u;
    libbgp_packet_t pkt;

    memset(out, 0x5au, sizeof(out));
    memcpy(expected, out, sizeof(expected));

    libbgp_packet_init(&pkt);
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_packet_parse(&pkt, LIBBGP_FIXTURE_OPEN_AS2, LIBBGP_FIXTURE_OPEN_AS2_LEN, NULL));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_PACKET_OPEN, pkt.type);

    /* Provide a buffer smaller than LIBBGP_BGP_HEADER_LEN to trigger the small-buffer path. */
    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_BUFFER, libbgp_packet_write(&pkt, out, LIBBGP_BGP_HEADER_LEN - 1u, &out_len));
    LIBBGP_ASSERT_BYTES_EQ(expected, out, sizeof(out));
    LIBBGP_ASSERT_EQ_U64(99u, out_len);

    libbgp_packet_destroy(&pkt);
}

LIBBGP_TEST(packet_parse_accepts_unsupported_open_version)
{
    const uint8_t open_v3[] = {
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0x00, 0x1d, 0x01,
        0x03, 0xfd, 0xe8, 0x00, 0x5a, 0xcb, 0x00, 0x71, 0x01, 0x00
    };
    size_t used = 0u;
    libbgp_packet_t pkt;

    libbgp_packet_init(&pkt);
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_packet_parse(&pkt, open_v3, sizeof(open_v3), &used));
    LIBBGP_ASSERT_EQ_U64(sizeof(open_v3), used);
    LIBBGP_ASSERT_EQ_U64(LIBBGP_PACKET_OPEN, pkt.type);
    LIBBGP_ASSERT_EQ_U64(3u, pkt.data.open.version);
    LIBBGP_ASSERT_EQ_U64(65000u, pkt.data.open.my_asn);
    LIBBGP_ASSERT_EQ_U64(90u, pkt.data.open.hold_time);
    LIBBGP_ASSERT_EQ_U64(0xcb007101u, pkt.data.open.bgp_id);
    libbgp_packet_destroy(&pkt);
}

LIBBGP_TEST(packet_parse_as4_uses_four_octet_update_context)
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
    uint8_t out[sizeof(update4b)];
    size_t used = 0u;
    size_t out_len = 0u;
    libbgp_packet_t pkt;
    libbgp_pattr_t *as_path;

    libbgp_packet_init(&pkt);
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_packet_parse_as4(&pkt, update4b, sizeof(update4b), true, &used));
    LIBBGP_ASSERT_EQ_U64(sizeof(update4b), used);
    LIBBGP_ASSERT_EQ_I64(LIBBGP_PACKET_UPDATE, pkt.type);
    as_path = libbgp_update_find_attr(&pkt.data.update, LIBBGP_PATTR_AS_PATH);
    LIBBGP_ASSERT(as_path != NULL);
    LIBBGP_ASSERT(as_path->data.as_path.is_4b);
    LIBBGP_ASSERT_EQ_U64(65538u, as_path->data.as_path.segments[0].asns[1]);
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_packet_write(&pkt, out, sizeof(out), &out_len));
    LIBBGP_ASSERT_EQ_U64(sizeof(update4b), out_len);
    LIBBGP_ASSERT_BYTES_EQ(update4b, out, sizeof(update4b));
    libbgp_packet_destroy(&pkt);
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
    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_BAD_LEN, libbgp_packet_parse(&pkt, bad_marker, sizeof(bad_marker), &marker));
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

LIBBGP_TEST(packet_write_unknown_requires_raw_body_when_length_nonzero)
{
    uint8_t out[64];
    uint8_t expected[sizeof(out)];
    size_t out_len = 99u;
    libbgp_packet_t pkt;

    memset(out, 0x5au, sizeof(out));
    memcpy(expected, out, sizeof(expected));
    libbgp_packet_init(&pkt);
    pkt.type = LIBBGP_PACKET_UNKNOWN;
    pkt.raw_type = 0x63u;
    pkt.raw_body = NULL;
    pkt.raw_body_len = 1u;

    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_BAD_LEN, libbgp_packet_write(&pkt, out, sizeof(out), &out_len));
    LIBBGP_ASSERT_BYTES_EQ(expected, out, sizeof(out));
    LIBBGP_ASSERT_EQ_U64(99u, out_len);
    pkt.raw_body_len = 0u;
    libbgp_packet_destroy(&pkt);
}

LIBBGP_TEST(packet_write_unknown_allows_zero_length_body)
{
    const uint8_t expected[] = {
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0x00, 0x13, 0x63
    };
    uint8_t out[sizeof(expected)];
    size_t out_len = 99u;
    libbgp_packet_t pkt;

    libbgp_packet_init(&pkt);
    pkt.type = LIBBGP_PACKET_UNKNOWN;
    pkt.raw_type = 0x63u;
    pkt.raw_body = NULL;
    pkt.raw_body_len = 0u;

    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_packet_write(&pkt, out, sizeof(out), &out_len));
    LIBBGP_ASSERT_EQ_U64(sizeof(expected), out_len);
    LIBBGP_ASSERT_BYTES_EQ(expected, out, sizeof(expected));
    libbgp_packet_destroy(&pkt);
}

LIBBGP_TEST(packet_parse_known_body_failure_preserves_existing_packet)
{
    const uint8_t unknown[] = {
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0x00, 0x16, 0x63,
        0xde, 0xad, 0xbe
    };
    const uint8_t bad_open[] = {
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0x00, 0x1c, 0x01,
        0x04, 0xfd, 0xe8, 0x00, 0x5a, 0xcb, 0x00, 0x71, 0x01
    };
    size_t used = 0u;
    libbgp_packet_t pkt;
    libbgp_packet_type_t saved_type;
    uint8_t saved_raw_type;
    uint8_t *saved_raw_body;
    size_t saved_raw_body_len;

    libbgp_packet_init(&pkt);
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_packet_parse(&pkt, unknown, sizeof(unknown), &used));
    LIBBGP_ASSERT_EQ_U64(sizeof(unknown), used);
    saved_type = pkt.type;
    saved_raw_type = pkt.raw_type;
    saved_raw_body = pkt.raw_body;
    saved_raw_body_len = pkt.raw_body_len;
    used = 99u;

    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_BAD_LEN, libbgp_packet_parse(&pkt, bad_open, sizeof(bad_open), &used));
    LIBBGP_ASSERT_EQ_I64(saved_type, pkt.type);
    LIBBGP_ASSERT_EQ_U64(saved_raw_type, pkt.raw_type);
    LIBBGP_ASSERT_EQ_U64(saved_raw_body_len, pkt.raw_body_len);
    LIBBGP_ASSERT(pkt.raw_body == saved_raw_body);
    LIBBGP_ASSERT_BYTES_EQ(&unknown[19], pkt.raw_body, pkt.raw_body_len);
    LIBBGP_ASSERT_EQ_U64(99u, used);
    libbgp_packet_destroy(&pkt);
}

LIBBGP_TEST(packet_write_oversized_unknown_leaves_output_unchanged)
{
    uint8_t body[LIBBGP_BGP_MAX_PACKET_LEN - LIBBGP_BGP_HEADER_LEN + 1u];
    uint8_t out[LIBBGP_BGP_MAX_PACKET_LEN + 1u];
    uint8_t expected[sizeof(out)];
    size_t out_len = 99u;
    libbgp_packet_t pkt;

    memset(body, 0xaau, sizeof(body));
    memset(out, 0x5au, sizeof(out));
    memcpy(expected, out, sizeof(expected));
    libbgp_packet_init(&pkt);
    pkt.type = LIBBGP_PACKET_UNKNOWN;
    pkt.raw_type = 200u;
    pkt.raw_body = body;
    pkt.raw_body_len = sizeof(body);

    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_BAD_LEN, libbgp_packet_write(&pkt, out, sizeof(out), &out_len));
    LIBBGP_ASSERT_BYTES_EQ(expected, out, sizeof(out));
    LIBBGP_ASSERT_EQ_U64(99u, out_len);

    pkt.raw_body = NULL;
    pkt.raw_body_len = 0u;
    libbgp_packet_destroy(&pkt);
}

LIBBGP_TEST(packet_write_known_body_failure_leaves_output_unchanged)
{
    uint8_t out[64];
    uint8_t expected[sizeof(out)];
    size_t out_len = 99u;
    libbgp_packet_t pkt;

    memset(out, 0x5au, sizeof(out));
    memcpy(expected, out, sizeof(expected));
    libbgp_packet_init(&pkt);
    pkt.type = LIBBGP_PACKET_OPEN;
    libbgp_open_init(&pkt.data.open);
    pkt.data.open.version = 3u;

    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_BAD_LEN, libbgp_packet_write(&pkt, out, sizeof(out), &out_len));
    LIBBGP_ASSERT_BYTES_EQ(expected, out, sizeof(out));
    LIBBGP_ASSERT_EQ_U64(99u, out_len);
    libbgp_packet_destroy(&pkt);
}

/* RFC 4271 Section 4: packet init/destroy with NULL is a no-op.
 * Covers src/packet.c lines 10, 20. */
LIBBGP_TEST(packet_init_destroy_null_is_noop)
{
    libbgp_packet_init(NULL);
    libbgp_packet_destroy(NULL);
}

/* RFC 4271 Section 4.5: parsing a notification body that is too short (len=1) triggers
 * body parse error via packet_parse_map_body_error NOTIFICATION/KEEPALIVE path.
 * Covers src/packet.c line 107. */
LIBBGP_TEST(packet_parse_short_notification_body_sets_header_error)
{
    const uint8_t short_notif[] = {
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0x00, 0x13, 0x03
    };
    libbgp_packet_t pkt;

    libbgp_packet_init(&pkt);
    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_BAD_LEN,
        libbgp_packet_parse(&pkt, short_notif, sizeof(short_notif), NULL));
    libbgp_packet_destroy(&pkt);
}

/* RFC 4271 Section 4: packet write with NULL out_len pointer covers line 309. */
LIBBGP_TEST(packet_write_null_out_len_still_writes)
{
    uint8_t out[LIBBGP_BGP_HEADER_LEN];
    libbgp_packet_t pkt;

    libbgp_packet_init(&pkt);
    pkt.type = LIBBGP_PACKET_KEEPALIVE;

    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_packet_write(&pkt, out, sizeof(out), NULL));
    LIBBGP_ASSERT_EQ_I64(0xff, out[0]);
    libbgp_packet_destroy(&pkt);
}

/* Covers parsing with NULL consumed pointer (line 200). */
LIBBGP_TEST(packet_parse_null_consumed)
{
    libbgp_packet_t pkt;

    libbgp_packet_init(&pkt);
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK,
        libbgp_packet_parse(&pkt, LIBBGP_FIXTURE_KEEPALIVE, LIBBGP_FIXTURE_KEEPALIVE_LEN, NULL));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_PACKET_KEEPALIVE, pkt.type);
    libbgp_packet_destroy(&pkt);
}

int main(void)
{
    const libbgp_test_case_t tests[] = {
        { "keepalive_body_parse_write_and_packet_fixture", keepalive_body_parse_write_and_packet_fixture },
        { "packet_parse_write_known_fixtures", packet_parse_write_known_fixtures },
        { "packet_write_keepalive_is_byte_for_byte_deterministic", packet_write_keepalive_is_byte_for_byte_deterministic },
        { "packet_write_open_is_byte_for_byte_deterministic", packet_write_open_is_byte_for_byte_deterministic },
        { "packet_write_known_small_buffer_preserves_output_and_returns_buffer", packet_write_known_small_buffer_preserves_output_and_returns_buffer },
        { "packet_parse_accepts_unsupported_open_version", packet_parse_accepts_unsupported_open_version },
        { "packet_parse_as4_uses_four_octet_update_context", packet_parse_as4_uses_four_octet_update_context },
        { "packet_rejects_marker_length_and_keepalive_body", packet_rejects_marker_length_and_keepalive_body },
        { "packet_unknown_type_preserves_raw_body_and_write_small_output", packet_unknown_type_preserves_raw_body_and_write_small_output },
        { "packet_write_unknown_requires_raw_body_when_length_nonzero", packet_write_unknown_requires_raw_body_when_length_nonzero },
        { "packet_write_unknown_allows_zero_length_body", packet_write_unknown_allows_zero_length_body },
        { "packet_parse_known_body_failure_preserves_existing_packet", packet_parse_known_body_failure_preserves_existing_packet },
        { "packet_write_oversized_unknown_leaves_output_unchanged", packet_write_oversized_unknown_leaves_output_unchanged },
        { "packet_write_known_body_failure_leaves_output_unchanged", packet_write_known_body_failure_leaves_output_unchanged },
        { "packet_init_destroy_null_is_noop", packet_init_destroy_null_is_noop },
        { "packet_parse_short_notification_body_sets_header_error", packet_parse_short_notification_body_sets_header_error },
        { "packet_write_null_out_len_still_writes", packet_write_null_out_len_still_writes },
        { "packet_parse_null_consumed", packet_parse_null_consumed }
    };

    return libbgp_run_tests("packet", tests, LIBBGP_ARRAY_LEN(tests));
}
