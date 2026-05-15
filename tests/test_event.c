#include "test_main.h"

#include "libbgp/alloc.h"
#include "libbgp/event.h"
#include "../src/internal.h"

typedef struct callback_record {
    size_t calls;
    int order[8];
    size_t order_len;
    const libbgp_event_t *last_event;
    void *last_ctx;
} callback_record_t;

typedef struct callback_ctx {
    callback_record_t *record;
    int marker;
    bool reject_on_next_retain;
    unsigned int retain_calls;
} callback_ctx_t;

static int test_event_publish_count = 0;

static void test_event_publish_cb(const libbgp_event_t *event, void *ctx)
{
    (void)event;
    (void)ctx;
    test_event_publish_count++;
}

static void recording_cb(const libbgp_event_t *event, void *ctx)
{
    callback_ctx_t *cb_ctx = (callback_ctx_t *)ctx;

    cb_ctx->record->calls++;
    cb_ctx->record->last_event = event;
    cb_ctx->record->last_ctx = ctx;
    cb_ctx->record->order[cb_ctx->record->order_len++] = cb_ctx->marker;
}

typedef struct unsubscribe_during_publish_ctx {
    libbgp_event_bus_t *bus;
    uint64_t unsubscribe_id;
    callback_record_t *record;
    int marker;
} unsubscribe_during_publish_ctx_t;

typedef struct subscribe_during_publish_ctx {
    libbgp_event_bus_t *bus;
    callback_record_t *record;
    callback_ctx_t *added_ctx;
    int marker;
    bool did_subscribe;
} subscribe_during_publish_ctx_t;

static void unsubscribe_during_publish_cb(const libbgp_event_t *event, void *ctx)
{
    unsubscribe_during_publish_ctx_t *cb_ctx = (unsubscribe_during_publish_ctx_t *)ctx;

    (void)event;
    cb_ctx->record->calls++;
    cb_ctx->record->last_ctx = ctx;
    cb_ctx->record->order[cb_ctx->record->order_len++] = cb_ctx->marker;
    if (cb_ctx->unsubscribe_id != 0u) {
        LIBBGP_ASSERT_EQ_I64(LIBBGP_OK,
            libbgp_event_bus_unsubscribe(cb_ctx->bus, cb_ctx->unsubscribe_id));
        cb_ctx->unsubscribe_id = 0u;
    }
}

static void subscribe_during_publish_cb(const libbgp_event_t *event, void *ctx)
{
    subscribe_during_publish_ctx_t *cb_ctx = (subscribe_during_publish_ctx_t *)ctx;

    (void)event;
    cb_ctx->record->calls++;
    cb_ctx->record->last_ctx = ctx;
    cb_ctx->record->order[cb_ctx->record->order_len++] = cb_ctx->marker;
    if (!cb_ctx->did_subscribe) {
        LIBBGP_ASSERT_EQ_I64(LIBBGP_OK,
            libbgp_event_bus_subscribe(cb_ctx->bus, LIBBGP_EVENT_ROUTE_ADDED,
                recording_cb, cb_ctx->added_ctx, NULL));
        cb_ctx->did_subscribe = true;
    }
}

LIBBGP_TEST(event_subscribe_returns_ids_and_counts_subscribers)
{
    libbgp_event_bus_t bus;
    callback_record_t record;
    callback_ctx_t ctx;
    uint64_t id1 = 0u;
    uint64_t id2 = 0u;

    memset(&record, 0, sizeof(record));
    ctx.record = &record;
    ctx.marker = 1;
    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_BAD_LEN, libbgp_event_bus_init(NULL));
    LIBBGP_ASSERT_EQ_U64(0u, libbgp_event_bus_subscriber_count(NULL));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_event_bus_init(&bus));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_BAD_LEN,
        libbgp_event_bus_subscribe(NULL, LIBBGP_EVENT_ROUTE_ADDED, recording_cb, &ctx, &id1));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_BAD_LEN,
        libbgp_event_bus_subscribe(&bus, LIBBGP_EVENT_ROUTE_ADDED, NULL, &ctx, &id1));

    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK,
        libbgp_event_bus_subscribe(&bus, LIBBGP_EVENT_ROUTE_ADDED, recording_cb, &ctx, &id1));
    LIBBGP_ASSERT(id1 != 0u);
    LIBBGP_ASSERT_EQ_U64(1u, libbgp_event_bus_subscriber_count(&bus));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK,
        libbgp_event_bus_subscribe(&bus, LIBBGP_EVENT_ROUTE_ADDED, recording_cb, &ctx, &id2));
    LIBBGP_ASSERT(id2 > id1);
    LIBBGP_ASSERT_EQ_U64(2u, libbgp_event_bus_subscriber_count(&bus));
    libbgp_event_bus_destroy(&bus);
}

LIBBGP_TEST(event_publish_exact_type_invokes_callbacks_in_order)
{
    libbgp_event_bus_t bus;
    callback_record_t record;
    callback_ctx_t ctx1;
    callback_ctx_t ctx2;
    libbgp_event_t event;

    memset(&record, 0, sizeof(record));
    ctx1.record = &record;
    ctx1.marker = 11;
    ctx2.record = &record;
    ctx2.marker = 22;
    memset(&event, 0, sizeof(event));
    event.type = LIBBGP_EVENT_ROUTE_ADDED;
    event.user_data = &record;

    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_event_bus_init(&bus));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK,
        libbgp_event_bus_subscribe(&bus, LIBBGP_EVENT_ROUTE_ADDED, recording_cb, &ctx1, NULL));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK,
        libbgp_event_bus_subscribe(&bus, LIBBGP_EVENT_ROUTE_ADDED, recording_cb, &ctx2, NULL));

    LIBBGP_ASSERT_EQ_U64(2u, libbgp_event_bus_publish(&bus, &event));
    LIBBGP_ASSERT_EQ_U64(2u, record.calls);
    LIBBGP_ASSERT_EQ_I64(11, record.order[0]);
    LIBBGP_ASSERT_EQ_I64(22, record.order[1]);
    LIBBGP_ASSERT(record.last_event == &event);
    LIBBGP_ASSERT(record.last_ctx == &ctx2);
    libbgp_event_bus_destroy(&bus);
}

LIBBGP_TEST(event_publish_from_skips_publisher_subscription)
{
    libbgp_event_bus_t bus;
    callback_record_t record;
    callback_ctx_t ctx1;
    callback_ctx_t ctx2;
    libbgp_event_t event;
    uint64_t id1 = 0u;
    uint64_t id2 = 0u;

    memset(&record, 0, sizeof(record));
    ctx1.record = &record;
    ctx1.marker = 11;
    ctx2.record = &record;
    ctx2.marker = 22;
    memset(&event, 0, sizeof(event));
    event.type = LIBBGP_EVENT_ROUTE_ADDED;

    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_event_bus_init(&bus));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK,
        libbgp_event_bus_subscribe(&bus, LIBBGP_EVENT_ROUTE_ADDED, recording_cb, &ctx1, &id1));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK,
        libbgp_event_bus_subscribe(&bus, LIBBGP_EVENT_ROUTE_ADDED, recording_cb, &ctx2, &id2));

    LIBBGP_ASSERT_EQ_U64(1u, libbgp_event_bus_publish_from(&bus, id1, &event));
    LIBBGP_ASSERT_EQ_U64(1u, record.calls);
    LIBBGP_ASSERT_EQ_I64(22, record.order[0]);

    memset(&record, 0, sizeof(record));
    LIBBGP_ASSERT_EQ_U64(2u, libbgp_event_bus_publish_from(&bus, 0u, &event));
    LIBBGP_ASSERT_EQ_U64(2u, record.calls);
    LIBBGP_ASSERT_EQ_I64(11, record.order[0]);
    LIBBGP_ASSERT_EQ_I64(22, record.order[1]);

    libbgp_event_bus_destroy(&bus);
}

LIBBGP_TEST(event_publish_different_type_does_not_notify)
{
    libbgp_event_bus_t bus;
    callback_record_t record;
    callback_ctx_t ctx;
    libbgp_event_t event;

    memset(&record, 0, sizeof(record));
    ctx.record = &record;
    ctx.marker = 1;
    memset(&event, 0, sizeof(event));
    event.type = LIBBGP_EVENT_ROUTE_WITHDRAWN;

    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_event_bus_init(&bus));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK,
        libbgp_event_bus_subscribe(&bus, LIBBGP_EVENT_ROUTE_ADDED, recording_cb, &ctx, NULL));
    LIBBGP_ASSERT_EQ_U64(0u, libbgp_event_bus_publish(&bus, &event));
    LIBBGP_ASSERT_EQ_U64(0u, record.calls);
    libbgp_event_bus_destroy(&bus);
}

LIBBGP_TEST(event_custom_subscriber_only_receives_custom_events)
{
    libbgp_event_bus_t bus;
    callback_record_t record;
    callback_ctx_t ctx;
    libbgp_event_t event;

    memset(&record, 0, sizeof(record));
    ctx.record = &record;
    ctx.marker = 1;
    memset(&event, 0, sizeof(event));

    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_event_bus_init(&bus));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK,
        libbgp_event_bus_subscribe(&bus, LIBBGP_EVENT_CUSTOM, recording_cb, &ctx, NULL));
    event.type = LIBBGP_EVENT_ROUTE_ADDED;
    LIBBGP_ASSERT_EQ_U64(0u, libbgp_event_bus_publish(&bus, &event));
    event.type = LIBBGP_EVENT_CUSTOM;
    LIBBGP_ASSERT_EQ_U64(1u, libbgp_event_bus_publish(&bus, &event));
    LIBBGP_ASSERT_EQ_U64(1u, record.calls);
    libbgp_event_bus_destroy(&bus);
}

LIBBGP_TEST(event_publish_snapshot_still_invokes_unsubscribed_inflight_callback)
{
    libbgp_event_bus_t bus;
    callback_record_t record;
    unsubscribe_during_publish_ctx_t ctx_a;
    callback_ctx_t ctx_b;
    callback_ctx_t ctx_c;
    libbgp_event_t event;
    uint64_t id_b = 0u;

    memset(&record, 0, sizeof(record));
    ctx_a.bus = &bus;
    ctx_a.unsubscribe_id = 0u;
    ctx_a.record = &record;
    ctx_a.marker = 1;
    ctx_b.record = &record;
    ctx_b.marker = 2;
    ctx_c.record = &record;
    ctx_c.marker = 3;
    memset(&event, 0, sizeof(event));
    event.type = LIBBGP_EVENT_ROUTE_ADDED;

    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_event_bus_init(&bus));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK,
        libbgp_event_bus_subscribe(&bus, LIBBGP_EVENT_ROUTE_ADDED,
            unsubscribe_during_publish_cb, &ctx_a, NULL));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK,
        libbgp_event_bus_subscribe(&bus, LIBBGP_EVENT_ROUTE_ADDED, recording_cb, &ctx_b, &id_b));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK,
        libbgp_event_bus_subscribe(&bus, LIBBGP_EVENT_ROUTE_ADDED, recording_cb, &ctx_c, NULL));
    ctx_a.unsubscribe_id = id_b;

    LIBBGP_ASSERT_EQ_U64(3u, libbgp_event_bus_publish(&bus, &event));
    LIBBGP_ASSERT_EQ_U64(3u, record.calls);
    LIBBGP_ASSERT_EQ_I64(1, record.order[0]);
    LIBBGP_ASSERT_EQ_I64(2, record.order[1]);
    LIBBGP_ASSERT_EQ_I64(3, record.order[2]);
    LIBBGP_ASSERT_EQ_U64(2u, libbgp_event_bus_subscriber_count(&bus));

    memset(&record, 0, sizeof(record));
    LIBBGP_ASSERT_EQ_U64(2u, libbgp_event_bus_publish(&bus, &event));
    LIBBGP_ASSERT_EQ_U64(2u, record.calls);
    LIBBGP_ASSERT_EQ_I64(1, record.order[0]);
    LIBBGP_ASSERT_EQ_I64(3, record.order[1]);

    libbgp_event_bus_destroy(&bus);
}

LIBBGP_TEST(event_publish_snapshot_excludes_subscriber_added_during_publish_until_next_publish)
{
    libbgp_event_bus_t bus;
    callback_record_t record;
    subscribe_during_publish_ctx_t ctx_a;
    callback_ctx_t ctx_b;
    callback_ctx_t ctx_c;
    callback_ctx_t ctx_d;
    libbgp_event_t event;

    memset(&record, 0, sizeof(record));
    ctx_a.bus = &bus;
    ctx_a.record = &record;
    ctx_a.added_ctx = &ctx_d;
    ctx_a.marker = 1;
    ctx_a.did_subscribe = false;
    ctx_b.record = &record;
    ctx_b.marker = 2;
    ctx_c.record = &record;
    ctx_c.marker = 3;
    ctx_d.record = &record;
    ctx_d.marker = 4;
    memset(&event, 0, sizeof(event));
    event.type = LIBBGP_EVENT_ROUTE_ADDED;

    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_event_bus_init(&bus));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK,
        libbgp_event_bus_subscribe(&bus, LIBBGP_EVENT_ROUTE_ADDED,
            subscribe_during_publish_cb, &ctx_a, NULL));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK,
        libbgp_event_bus_subscribe(&bus, LIBBGP_EVENT_ROUTE_ADDED, recording_cb, &ctx_b, NULL));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK,
        libbgp_event_bus_subscribe(&bus, LIBBGP_EVENT_ROUTE_ADDED, recording_cb, &ctx_c, NULL));

    LIBBGP_ASSERT_EQ_U64(3u, libbgp_event_bus_publish(&bus, &event));
    LIBBGP_ASSERT_EQ_U64(3u, record.calls);
    LIBBGP_ASSERT_EQ_I64(1, record.order[0]);
    LIBBGP_ASSERT_EQ_I64(2, record.order[1]);
    LIBBGP_ASSERT_EQ_I64(3, record.order[2]);

    memset(&record, 0, sizeof(record));
    LIBBGP_ASSERT_EQ_U64(4u, libbgp_event_bus_publish(&bus, &event));
    LIBBGP_ASSERT_EQ_U64(4u, record.calls);
    LIBBGP_ASSERT_EQ_I64(1, record.order[0]);
    LIBBGP_ASSERT_EQ_I64(2, record.order[1]);
    LIBBGP_ASSERT_EQ_I64(3, record.order[2]);
    LIBBGP_ASSERT_EQ_I64(4, record.order[3]);

    libbgp_event_bus_destroy(&bus);
}

LIBBGP_TEST(event_unsubscribe_removes_subscriber_and_reports_absent_id)
{
    libbgp_event_bus_t bus;
    callback_record_t record;
    callback_ctx_t ctx1;
    callback_ctx_t ctx2;
    libbgp_event_t event;
    uint64_t id1 = 0u;
    uint64_t id2 = 0u;

    memset(&record, 0, sizeof(record));
    ctx1.record = &record;
    ctx1.marker = 1;
    ctx2.record = &record;
    ctx2.marker = 2;
    memset(&event, 0, sizeof(event));
    event.type = LIBBGP_EVENT_SESSION_UP;

    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_event_bus_init(&bus));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK,
        libbgp_event_bus_subscribe(&bus, LIBBGP_EVENT_SESSION_UP, recording_cb, &ctx1, &id1));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK,
        libbgp_event_bus_subscribe(&bus, LIBBGP_EVENT_SESSION_UP, recording_cb, &ctx2, &id2));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_event_bus_unsubscribe(&bus, id1));
    LIBBGP_ASSERT_EQ_U64(1u, libbgp_event_bus_subscriber_count(&bus));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_NOT_FOUND, libbgp_event_bus_unsubscribe(&bus, id1));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_BAD_LEN, libbgp_event_bus_unsubscribe(NULL, id2));
    LIBBGP_ASSERT_EQ_U64(1u, libbgp_event_bus_publish(&bus, &event));
    LIBBGP_ASSERT_EQ_I64(2, record.order[0]);
    libbgp_event_bus_destroy(&bus);
}

LIBBGP_TEST(event_publish_null_inputs_return_zero)
{
    libbgp_event_bus_t bus;
    libbgp_event_t event;

    memset(&event, 0, sizeof(event));
    event.type = LIBBGP_EVENT_SESSION_DOWN;
    LIBBGP_ASSERT_EQ_U64(0u, libbgp_event_bus_publish(NULL, &event));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_event_bus_init(&bus));
    LIBBGP_ASSERT_EQ_U64(0u, libbgp_event_bus_publish(&bus, NULL));
    libbgp_event_bus_destroy(&bus);
}

LIBBGP_TEST(event_operations_after_destroy_use_null_behavior)
{
    libbgp_event_bus_t bus;
    callback_record_t record;
    callback_ctx_t ctx;
    libbgp_event_t event;
    uint64_t id = 0u;

    memset(&record, 0, sizeof(record));
    ctx.record = &record;
    ctx.marker = 1;
    memset(&event, 0, sizeof(event));
    event.type = LIBBGP_EVENT_SESSION_DOWN;

    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_event_bus_init(&bus));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK,
        libbgp_event_bus_subscribe(&bus, LIBBGP_EVENT_SESSION_DOWN, recording_cb, &ctx, &id));
    libbgp_event_bus_destroy(&bus);

    LIBBGP_ASSERT_EQ_U64(0u, libbgp_event_bus_subscriber_count(&bus));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_BAD_LEN,
        libbgp_event_bus_subscribe(&bus, LIBBGP_EVENT_SESSION_DOWN, recording_cb, &ctx, NULL));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_BAD_LEN, libbgp_event_bus_unsubscribe(&bus, id));
    LIBBGP_ASSERT_EQ_U64(0u, libbgp_event_bus_publish(&bus, &event));
}

/* Test retain callback that rejects during subscribe.
 * Covers src/event.c line 173 (retain returns false). */
static bool reject_retain(void *ctx)
{
    (void)ctx;
    return false;
}

static int release_calls;

static void counting_release(void *ctx)
{
    (void)ctx;
    release_calls++;
}

static void *event_fail_realloc(void *ptr, size_t size, void *ctx)
{
    (void)ptr;
    (void)size;
    (void)ctx;
    return NULL;
}

static void *event_fail_calloc(size_t nmemb, size_t size, void *ctx)
{
    (void)nmemb;
    (void)size;
    (void)ctx;
    return NULL;
}

static size_t event_calloc_calls;

static void *event_counting_calloc(size_t nmemb, size_t size, void *ctx)
{
    (void)ctx;
    event_calloc_calls++;
    return calloc(nmemb, size);
}

LIBBGP_TEST(event_subscribe_retain_reject_returns_bad_len)
{
    libbgp_event_bus_t bus;
    callback_ctx_t ctx;
    uint64_t id = 0u;

    memset(&ctx, 0, sizeof(ctx));
    release_calls = 0;

    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_event_bus_init(&bus));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_BAD_LEN,
        bgp_event_bus_subscribe_retained(&bus, LIBBGP_EVENT_ROUTE_ADDED,
            recording_cb, &ctx, reject_retain, counting_release, &id));
    LIBBGP_ASSERT_EQ_U64(0u, id);
    LIBBGP_ASSERT_EQ_I64(0, release_calls);
    libbgp_event_bus_destroy(&bus);
}

/* Test subscribe to destroyed bus triggers release cleanup.
 * Covers src/event.c lines 177-178. */
LIBBGP_TEST(event_subscribe_retained_on_destroyed_bus_calls_release)
{
    libbgp_event_bus_t bus;
    callback_ctx_t ctx;
    uint64_t id = 0u;

    memset(&ctx, 0, sizeof(ctx));
    release_calls = 0;

    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_event_bus_init(&bus));
    libbgp_event_bus_destroy(&bus);

    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_BAD_LEN,
        bgp_event_bus_subscribe_retained(&bus, LIBBGP_EVENT_ROUTE_ADDED,
            recording_cb, &ctx, NULL, counting_release, &id));
    LIBBGP_ASSERT_EQ_U64(0u, id);
    LIBBGP_ASSERT_EQ_I64(1, release_calls);
}

/* Test allocation failure during subscribe triggers release cleanup.
 * Covers src/event.c lines 183-185. */
LIBBGP_TEST(event_subscribe_alloc_failure_calls_release)
{
    libbgp_alloc_t alloc;
    libbgp_event_bus_t bus;
    callback_ctx_t ctx;
    uint64_t id = 0u;
    int i;

    memset(&ctx, 0, sizeof(ctx));
    release_calls = 0;

    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_event_bus_init(&bus));

    /* Subscribe 4 to fill initial cap=4, then fail the growth realloc. */
    for (i = 0; i < 4; i++) {
        LIBBGP_ASSERT_EQ_I64(LIBBGP_OK,
            libbgp_event_bus_subscribe(&bus, LIBBGP_EVENT_ROUTE_ADDED,
                recording_cb, &ctx, NULL));
    }

    alloc = libbgp_default_alloc;
    alloc.realloc = event_fail_realloc;
    libbgp_set_alloc(&alloc);
    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_NOMEM,
        bgp_event_bus_subscribe_retained(&bus, LIBBGP_EVENT_ROUTE_ADDED,
            recording_cb, &ctx, NULL, counting_release, &id));
    LIBBGP_ASSERT_EQ_U64(0u, id);
    LIBBGP_ASSERT_EQ_I64(1, release_calls);

    libbgp_set_alloc(NULL);
    libbgp_event_bus_destroy(&bus);
}

LIBBGP_TEST(event_publish_small_snapshot_uses_stack_when_calloc_fails)
{
    libbgp_alloc_t alloc;
    libbgp_event_bus_t bus;
    libbgp_event_t event;
    int i;

    memset(&event, 0, sizeof(event));
    event.type = LIBBGP_EVENT_ROUTE_ADDED;
    test_event_publish_count = 0;

    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_event_bus_init(&bus));
    for (i = 0; i < 10; i++) {
        LIBBGP_ASSERT_EQ_I64(LIBBGP_OK,
            libbgp_event_bus_subscribe(&bus, LIBBGP_EVENT_ROUTE_ADDED,
                test_event_publish_cb, NULL, NULL));
    }

    alloc = libbgp_default_alloc;
    alloc.calloc = event_fail_calloc;
    libbgp_set_alloc(&alloc);
    LIBBGP_ASSERT_EQ_U64(10u, libbgp_event_bus_publish(&bus, &event));
    libbgp_set_alloc(NULL);
    LIBBGP_ASSERT_EQ_I64(10, test_event_publish_count);

    libbgp_event_bus_destroy(&bus);
}

LIBBGP_TEST(event_publish_large_snapshot_uses_heap_and_invokes_all_callbacks)
{
    libbgp_alloc_t alloc;
    libbgp_event_bus_t bus;
    libbgp_event_t event;
    int i;

    memset(&event, 0, sizeof(event));
    event.type = LIBBGP_EVENT_ROUTE_ADDED;
    test_event_publish_count = 0;
    event_calloc_calls = 0u;

    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_event_bus_init(&bus));
    for (i = 0; i < 100; i++) {
        LIBBGP_ASSERT_EQ_I64(LIBBGP_OK,
            libbgp_event_bus_subscribe(&bus, LIBBGP_EVENT_ROUTE_ADDED,
                test_event_publish_cb, NULL, NULL));
    }

    alloc = libbgp_default_alloc;
    alloc.calloc = event_counting_calloc;
    libbgp_set_alloc(&alloc);
    LIBBGP_ASSERT_EQ_U64(100u, libbgp_event_bus_publish(&bus, &event));
    libbgp_set_alloc(NULL);
    LIBBGP_ASSERT_EQ_I64(100, test_event_publish_count);
    LIBBGP_ASSERT_EQ_U64(1u, event_calloc_calls);

    libbgp_event_bus_destroy(&bus);
}

static bool selective_retain(void *ctx)
{
    callback_ctx_t *cb_ctx = (callback_ctx_t *)ctx;

    cb_ctx->retain_calls++;
    return !cb_ctx->reject_on_next_retain || cb_ctx->retain_calls == 1u;
}

static void noop_release(void *ctx)
{
    (void)ctx;
}

LIBBGP_TEST(event_publish_retain_reject_skips_subscriber)
{
    libbgp_event_bus_t bus;
    callback_record_t record;
    callback_ctx_t ctx1, ctx2;
    libbgp_event_t event;

    memset(&record, 0, sizeof(record));
    memset(&ctx1, 0, sizeof(ctx1));
    memset(&ctx2, 0, sizeof(ctx2));
    ctx1.record = &record;
    ctx1.marker = 11;
    ctx1.reject_on_next_retain = true;
    ctx2.record = &record;
    ctx2.marker = 22;
    memset(&event, 0, sizeof(event));
    event.type = LIBBGP_EVENT_ROUTE_ADDED;

    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_event_bus_init(&bus));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK,
        bgp_event_bus_subscribe_retained(&bus, LIBBGP_EVENT_ROUTE_ADDED,
            recording_cb, &ctx1, selective_retain, noop_release, NULL));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK,
        bgp_event_bus_subscribe_retained(&bus, LIBBGP_EVENT_ROUTE_ADDED,
            recording_cb, &ctx2, NULL, NULL, NULL));

    LIBBGP_ASSERT_EQ_U64(1u, libbgp_event_bus_publish(&bus, &event));
    LIBBGP_ASSERT_EQ_U64(1u, record.calls);
    LIBBGP_ASSERT_EQ_I64(22, record.order[0]);

    libbgp_event_bus_destroy(&bus);
}

int main(void)
{
    const libbgp_test_case_t tests[] = {
        { "event_subscribe_returns_ids_and_counts_subscribers", event_subscribe_returns_ids_and_counts_subscribers },
        { "event_publish_exact_type_invokes_callbacks_in_order", event_publish_exact_type_invokes_callbacks_in_order },
        { "event_publish_from_skips_publisher_subscription", event_publish_from_skips_publisher_subscription },
        { "event_publish_different_type_does_not_notify", event_publish_different_type_does_not_notify },
        { "event_custom_subscriber_only_receives_custom_events", event_custom_subscriber_only_receives_custom_events },
        { "event_publish_snapshot_still_invokes_unsubscribed_inflight_callback", event_publish_snapshot_still_invokes_unsubscribed_inflight_callback },
        { "event_publish_snapshot_excludes_subscriber_added_during_publish_until_next_publish", event_publish_snapshot_excludes_subscriber_added_during_publish_until_next_publish },
        { "event_unsubscribe_removes_subscriber_and_reports_absent_id", event_unsubscribe_removes_subscriber_and_reports_absent_id },
        { "event_publish_null_inputs_return_zero", event_publish_null_inputs_return_zero },
        { "event_operations_after_destroy_use_null_behavior", event_operations_after_destroy_use_null_behavior },
        { "event_subscribe_retain_reject_returns_bad_len", event_subscribe_retain_reject_returns_bad_len },
        { "event_subscribe_retained_on_destroyed_bus_calls_release", event_subscribe_retained_on_destroyed_bus_calls_release },
        { "event_subscribe_alloc_failure_calls_release", event_subscribe_alloc_failure_calls_release },
        { "event_publish_small_snapshot_uses_stack_when_calloc_fails", event_publish_small_snapshot_uses_stack_when_calloc_fails },
        { "event_publish_large_snapshot_uses_heap_and_invokes_all_callbacks", event_publish_large_snapshot_uses_heap_and_invokes_all_callbacks },
        { "event_publish_retain_reject_skips_subscriber", event_publish_retain_reject_skips_subscriber }
    };

    return libbgp_run_tests("event", tests, LIBBGP_ARRAY_LEN(tests));
}
