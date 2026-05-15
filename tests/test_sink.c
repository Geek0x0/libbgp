#include "test_main.h"

#include "fixtures/bgp_packets.h"

#include "libbgp/alloc.h"
#include "libbgp/sink.h"
#include "libbgp/types.h"

typedef struct sink_fail_alloc_ctx {
    size_t calloc_calls;
    size_t realloc_calls;
    size_t fail_calloc_after;
    size_t fail_realloc_after;
} sink_fail_alloc_ctx_t;

typedef struct sink_impl_prefix {
    uint8_t *buf;
    size_t buf_off;
    size_t buf_len;
    size_t buf_cap;
} sink_impl_prefix_t;

static sink_impl_prefix_t sink_impl_prefix_copy(const libbgp_sink_t *sink)
{
    sink_impl_prefix_t prefix;

    memset(&prefix, 0, sizeof(prefix));
    if (sink != NULL && sink->impl != NULL) {
        memcpy(&prefix, sink->impl, sizeof(prefix));
    }
    return prefix;
}

static void *sink_fail_alloc_malloc(size_t size, void *ctx)
{
    (void)ctx;
    return malloc(size);
}

static void *sink_fail_alloc_calloc(size_t nmemb, size_t size, void *ctx)
{
    sink_fail_alloc_ctx_t *fail_ctx = (sink_fail_alloc_ctx_t *)ctx;

    fail_ctx->calloc_calls++;
    if (fail_ctx->fail_calloc_after != 0u && fail_ctx->calloc_calls >= fail_ctx->fail_calloc_after) {
        return NULL;
    }
    return calloc(nmemb, size);
}

static void *sink_fail_alloc_realloc(void *ptr, size_t size, void *ctx)
{
    sink_fail_alloc_ctx_t *fail_ctx = (sink_fail_alloc_ctx_t *)ctx;

    fail_ctx->realloc_calls++;
    if (fail_ctx->fail_realloc_after != 0u && fail_ctx->realloc_calls >= fail_ctx->fail_realloc_after) {
        return NULL;
    }
    return realloc(ptr, size);
}

static void sink_fail_alloc_free(void *ptr, void *ctx)
{
    (void)ctx;
    free(ptr);
}

static libbgp_alloc_t sink_fail_alloc_make(sink_fail_alloc_ctx_t *ctx)
{
    libbgp_alloc_t alloc;

    alloc.malloc = sink_fail_alloc_malloc;
    alloc.calloc = sink_fail_alloc_calloc;
    alloc.realloc = sink_fail_alloc_realloc;
    alloc.free = sink_fail_alloc_free;
    alloc.ctx = ctx;
    return alloc;
}

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

LIBBGP_TEST(sink_rejects_partial_bad_marker_then_accepts_valid_frame)
{
    uint8_t bad_prefix[LIBBGP_BGP_HEADER_LEN - 1u];
    libbgp_sink_t sink;
    libbgp_packet_t pkt;

    memset(bad_prefix, 0xff, sizeof(bad_prefix));
    bad_prefix[7] = 0u;

    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_sink_init(&sink));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_sink_feed(&sink, bad_prefix, sizeof(bad_prefix)));
    LIBBGP_ASSERT_EQ_U64(sizeof(bad_prefix), libbgp_sink_buffered_len(&sink));
    LIBBGP_ASSERT_EQ_U64(0u, libbgp_sink_packet_count(&sink));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_BAD_LEN, libbgp_sink_feed(&sink, LIBBGP_FIXTURE_KEEPALIVE, LIBBGP_FIXTURE_KEEPALIVE_LEN));
    LIBBGP_ASSERT_EQ_U64(0u, libbgp_sink_buffered_len(&sink));
    LIBBGP_ASSERT_EQ_U64(0u, libbgp_sink_packet_count(&sink));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_sink_feed(&sink, LIBBGP_FIXTURE_KEEPALIVE, LIBBGP_FIXTURE_KEEPALIVE_LEN));
    LIBBGP_ASSERT_EQ_U64(1u, libbgp_sink_packet_count(&sink));

    libbgp_packet_init(&pkt);
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_sink_pop(&sink, &pkt));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_PACKET_KEEPALIVE, pkt.type);
    libbgp_packet_destroy(&pkt);
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

LIBBGP_TEST(sink_null_handles_are_safe)
{
    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_INVALID, libbgp_sink_init(NULL));
    libbgp_sink_destroy(NULL);
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_sink_feed(NULL, NULL, 0u));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_INVALID, libbgp_sink_feed(NULL, LIBBGP_FIXTURE_KEEPALIVE, 1u));
    LIBBGP_ASSERT_EQ_U64(0u, libbgp_sink_packet_count(NULL));
    LIBBGP_ASSERT_EQ_U64(0u, libbgp_sink_buffered_len(NULL));
    libbgp_sink_clear(NULL);
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

LIBBGP_TEST(sink_rejects_null_data_for_nonzero_len)
{
    libbgp_sink_t sink;

    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_sink_init(&sink));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_BAD_LEN, libbgp_sink_feed(&sink, NULL, 1u));
    LIBBGP_ASSERT_EQ_U64(0u, libbgp_sink_buffered_len(&sink));
    LIBBGP_ASSERT_EQ_U64(0u, libbgp_sink_packet_count(&sink));
    libbgp_sink_destroy(&sink);
}

LIBBGP_TEST(sink_feed_reports_nomem_when_buffer_realloc_fails)
{
    sink_fail_alloc_ctx_t fail_ctx = { 0u, 0u, 0u, 1u };
    libbgp_alloc_t alloc = sink_fail_alloc_make(&fail_ctx);
    libbgp_sink_t sink;
    libbgp_err_t init_rc;
    libbgp_err_t feed_rc = LIBBGP_ERR_INVALID;
    size_t realloc_calls;
    size_t buffered_len = 0u;
    size_t packet_count = 0u;

    libbgp_set_alloc(&alloc);
    init_rc = libbgp_sink_init(&sink);
    if (init_rc == LIBBGP_OK) {
        feed_rc = libbgp_sink_feed(&sink, LIBBGP_FIXTURE_KEEPALIVE, 1u);
        buffered_len = libbgp_sink_buffered_len(&sink);
        packet_count = libbgp_sink_packet_count(&sink);
    }
    realloc_calls = fail_ctx.realloc_calls;
    libbgp_set_alloc(NULL);
    if (init_rc == LIBBGP_OK) {
        libbgp_sink_destroy(&sink);
    }

    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, init_rc);
    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_NOMEM, feed_rc);
    LIBBGP_ASSERT_EQ_U64(1u, realloc_calls);
    LIBBGP_ASSERT_EQ_U64(0u, buffered_len);
    LIBBGP_ASSERT_EQ_U64(0u, packet_count);
}

LIBBGP_TEST(sink_feed_reports_nomem_when_packet_array_alloc_fails)
{
    sink_fail_alloc_ctx_t fail_ctx = { 0u, 0u, 2u, 0u };
    libbgp_alloc_t alloc = sink_fail_alloc_make(&fail_ctx);
    libbgp_sink_t sink;
    libbgp_err_t init_rc;
    libbgp_err_t feed_rc = LIBBGP_ERR_INVALID;
    size_t calloc_calls;
    size_t packet_count = 0u;
    size_t buffered_len = 0u;

    libbgp_set_alloc(&alloc);
    init_rc = libbgp_sink_init(&sink);
    if (init_rc == LIBBGP_OK) {
        feed_rc = libbgp_sink_feed(&sink, LIBBGP_FIXTURE_KEEPALIVE, LIBBGP_FIXTURE_KEEPALIVE_LEN);
        packet_count = libbgp_sink_packet_count(&sink);
        buffered_len = libbgp_sink_buffered_len(&sink);
    }
    calloc_calls = fail_ctx.calloc_calls;
    libbgp_set_alloc(NULL);
    if (init_rc == LIBBGP_OK) {
        libbgp_sink_destroy(&sink);
    }

    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, init_rc);
    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_NOMEM, feed_rc);
    LIBBGP_ASSERT_EQ_U64(2u, calloc_calls);
    LIBBGP_ASSERT_EQ_U64(0u, packet_count);
    LIBBGP_ASSERT_EQ_U64(LIBBGP_FIXTURE_KEEPALIVE_LEN, buffered_len);
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

static void sink_feed_keepalive_batch(size_t count)
{
    uint8_t *batch;
    libbgp_sink_t sink;
    libbgp_packet_t pkt;
    size_t i;

    batch = (uint8_t *)malloc(count * LIBBGP_FIXTURE_KEEPALIVE_LEN);
    LIBBGP_ASSERT(batch != NULL);
    for (i = 0u; i < count; i++) {
        memcpy(batch + (i * LIBBGP_FIXTURE_KEEPALIVE_LEN), LIBBGP_FIXTURE_KEEPALIVE, LIBBGP_FIXTURE_KEEPALIVE_LEN);
    }

    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_sink_init(&sink));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_sink_feed(&sink, batch, count * LIBBGP_FIXTURE_KEEPALIVE_LEN));
    LIBBGP_ASSERT_EQ_U64(count, libbgp_sink_packet_count(&sink));
    LIBBGP_ASSERT_EQ_U64(0u, libbgp_sink_buffered_len(&sink));

    for (i = 0u; i < count; i++) {
        libbgp_packet_init(&pkt);
        LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_sink_pop(&sink, &pkt));
        LIBBGP_ASSERT_EQ_I64(LIBBGP_PACKET_KEEPALIVE, pkt.type);
        libbgp_packet_destroy(&pkt);
    }
    LIBBGP_ASSERT_EQ_U64(0u, libbgp_sink_packet_count(&sink));

    libbgp_sink_destroy(&sink);
    free(batch);
}

LIBBGP_TEST(sink_feeds_and_pops_1k_keepalive_batch)
{
    sink_feed_keepalive_batch(1000u);
}

LIBBGP_TEST(sink_feeds_and_pops_10k_keepalive_batch)
{
    sink_feed_keepalive_batch(10000u);
}

LIBBGP_TEST(sink_reuses_packet_queue_slots_after_partial_pop)
{
    uint8_t batch[8u * LIBBGP_FIXTURE_KEEPALIVE_LEN];
    libbgp_sink_t sink;
    libbgp_packet_t pkt;
    size_t i;

    for (i = 0u; i < 8u; i++) {
        memcpy(batch + (i * LIBBGP_FIXTURE_KEEPALIVE_LEN), LIBBGP_FIXTURE_KEEPALIVE, LIBBGP_FIXTURE_KEEPALIVE_LEN);
    }

    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_sink_init(&sink));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_sink_feed(&sink, batch, 4u * LIBBGP_FIXTURE_KEEPALIVE_LEN));
    for (i = 0u; i < 3u; i++) {
        libbgp_packet_init(&pkt);
        LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_sink_pop(&sink, &pkt));
        LIBBGP_ASSERT_EQ_I64(LIBBGP_PACKET_KEEPALIVE, pkt.type);
        libbgp_packet_destroy(&pkt);
    }
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_sink_feed(&sink, batch + (4u * LIBBGP_FIXTURE_KEEPALIVE_LEN), 4u * LIBBGP_FIXTURE_KEEPALIVE_LEN));
    LIBBGP_ASSERT_EQ_U64(5u, libbgp_sink_packet_count(&sink));
    for (i = 0u; i < 5u; i++) {
        libbgp_packet_init(&pkt);
        LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_sink_pop(&sink, &pkt));
        LIBBGP_ASSERT_EQ_I64(LIBBGP_PACKET_KEEPALIVE, pkt.type);
        libbgp_packet_destroy(&pkt);
    }
    LIBBGP_ASSERT_EQ_U64(0u, libbgp_sink_packet_count(&sink));

    libbgp_sink_destroy(&sink);
}

/* Test that sink_compact_buf is triggered when tail space is exhausted.
 * Covers src/sink.c lines 61 and 80-82 (compact path in sink_reserve_buf). */
LIBBGP_TEST(sink_compacts_buffer_when_tail_space_exhausted)
{
    /* keepalive (19 bytes) + 5 bytes of a second keepalive = 24 bytes.
     * Initial buf_cap grows from 0 -> 19 -> 38 to fit 24 bytes.
     * After processing the first keepalive: buf_off=19, buf_len=5, buf_cap=38.
     * Tail space = 38 - 19 - 5 = 14.
     * Feed 15 bytes: needed=20, 15 > 14 (no tail room), 20 <= 38 (fits after compact).
     * This triggers sink_compact_buf via the sink_reserve_buf compact path. */
    uint8_t batch[24];
    uint8_t tail[15];
    libbgp_sink_t sink;
    libbgp_packet_t pkt;

    memcpy(batch, LIBBGP_FIXTURE_KEEPALIVE, LIBBGP_FIXTURE_KEEPALIVE_LEN);
    memcpy(batch + LIBBGP_FIXTURE_KEEPALIVE_LEN, LIBBGP_FIXTURE_KEEPALIVE, 5u);

    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_sink_init(&sink));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_sink_feed(&sink, batch, sizeof(batch)));
    LIBBGP_ASSERT_EQ_U64(1u, libbgp_sink_packet_count(&sink));
    LIBBGP_ASSERT_EQ_U64(5u, libbgp_sink_buffered_len(&sink));

    /* Pop the first keepalive to verify it was parsed correctly */
    libbgp_packet_init(&pkt);
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_sink_pop(&sink, &pkt));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_PACKET_KEEPALIVE, pkt.type);
    libbgp_packet_destroy(&pkt);

    /* Feed 15 bytes: remaining 14 bytes of keepalive (indices 5-18) + 1 extra byte.
     * This triggers the compact path because 15 > tail_space(14) but needed(20) <= buf_cap(38). */
    memcpy(tail, LIBBGP_FIXTURE_KEEPALIVE + 5u, LIBBGP_FIXTURE_KEEPALIVE_LEN - 5u);
    tail[LIBBGP_FIXTURE_KEEPALIVE_LEN - 5u] = 0xffu;
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK,
        libbgp_sink_feed(&sink, tail, sizeof(tail)));
    LIBBGP_ASSERT_EQ_U64(1u, libbgp_sink_packet_count(&sink));
    LIBBGP_ASSERT_EQ_U64(1u, libbgp_sink_buffered_len(&sink));

    libbgp_packet_init(&pkt);
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_sink_pop(&sink, &pkt));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_PACKET_KEEPALIVE, pkt.type);
    libbgp_packet_destroy(&pkt);
    libbgp_sink_destroy(&sink);
}

LIBBGP_TEST(sink_delays_compact_when_growth_is_needed_before_half_offset)
{
    uint8_t first[100];
    uint8_t more[80];
    sink_impl_prefix_t prefix;
    libbgp_sink_t sink;

    memcpy(first, LIBBGP_FIXTURE_KEEPALIVE, LIBBGP_FIXTURE_KEEPALIVE_LEN);
    memset(first + LIBBGP_FIXTURE_KEEPALIVE_LEN, 0, sizeof(first) - LIBBGP_FIXTURE_KEEPALIVE_LEN);
    memset(first + LIBBGP_FIXTURE_KEEPALIVE_LEN, 0xff, LIBBGP_BGP_MARKER_LEN);
    first[LIBBGP_FIXTURE_KEEPALIVE_LEN + 16u] = 0x10u;
    first[LIBBGP_FIXTURE_KEEPALIVE_LEN + 17u] = 0x00u;
    first[LIBBGP_FIXTURE_KEEPALIVE_LEN + 18u] = 0x63u;
    memset(more, 0xa5, sizeof(more));

    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_sink_init(&sink));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_sink_feed(&sink, first, sizeof(first)));

    prefix = sink_impl_prefix_copy(&sink);
    LIBBGP_ASSERT_EQ_U64(LIBBGP_FIXTURE_KEEPALIVE_LEN, prefix.buf_off);
    LIBBGP_ASSERT_EQ_U64(sizeof(first) - LIBBGP_FIXTURE_KEEPALIVE_LEN, prefix.buf_len);
    LIBBGP_ASSERT(prefix.buf_off < prefix.buf_cap / 2u);

    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_sink_feed(&sink, more, sizeof(more)));

    prefix = sink_impl_prefix_copy(&sink);
    LIBBGP_ASSERT_EQ_U64(LIBBGP_FIXTURE_KEEPALIVE_LEN, prefix.buf_off);
    LIBBGP_ASSERT_EQ_U64((sizeof(first) - LIBBGP_FIXTURE_KEEPALIVE_LEN) + sizeof(more), prefix.buf_len);
    LIBBGP_ASSERT_EQ_U64(1u, libbgp_sink_packet_count(&sink));
    LIBBGP_ASSERT_EQ_U64(prefix.buf_len, libbgp_sink_buffered_len(&sink));

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
        { "sink_rejects_partial_bad_marker_then_accepts_valid_frame", sink_rejects_partial_bad_marker_then_accepts_valid_frame },
        { "sink_zero_length_null_feed_is_noop", sink_zero_length_null_feed_is_noop },
        { "sink_null_handles_are_safe", sink_null_handles_are_safe },
        { "sink_pop_empty_and_null_output_are_errors", sink_pop_empty_and_null_output_are_errors },
        { "sink_rejects_null_data_for_nonzero_len", sink_rejects_null_data_for_nonzero_len },
        { "sink_feed_reports_nomem_when_buffer_realloc_fails", sink_feed_reports_nomem_when_buffer_realloc_fails },
        { "sink_feed_reports_nomem_when_packet_array_alloc_fails", sink_feed_reports_nomem_when_packet_array_alloc_fails },
        { "sink_drops_bad_complete_frame_and_recovers_on_next_valid_packet", sink_drops_bad_complete_frame_and_recovers_on_next_valid_packet },
        { "sink_clear_discards_packets_and_buffer", sink_clear_discards_packets_and_buffer },
        { "sink_pop_moves_dynamic_packet_into_zeroed_output", sink_pop_moves_dynamic_packet_into_zeroed_output },
        { "sink_as4_context_parses_four_octet_as_path", sink_as4_context_parses_four_octet_as_path },
        { "sink_feeds_and_pops_1k_keepalive_batch", sink_feeds_and_pops_1k_keepalive_batch },
        { "sink_feeds_and_pops_10k_keepalive_batch", sink_feeds_and_pops_10k_keepalive_batch },
        { "sink_reuses_packet_queue_slots_after_partial_pop", sink_reuses_packet_queue_slots_after_partial_pop },
        { "sink_compacts_buffer_when_tail_space_exhausted", sink_compacts_buffer_when_tail_space_exhausted },
        { "sink_delays_compact_when_growth_is_needed_before_half_offset", sink_delays_compact_when_growth_is_needed_before_half_offset }
    };

    return libbgp_run_tests("sink", tests, LIBBGP_ARRAY_LEN(tests));
}
