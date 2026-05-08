#include "test_main.h"

#include "libbgp/event.h"

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
} callback_ctx_t;

static void recording_cb(const libbgp_event_t *event, void *ctx)
{
    callback_ctx_t *cb_ctx = (callback_ctx_t *)ctx;

    cb_ctx->record->calls++;
    cb_ctx->record->last_event = event;
    cb_ctx->record->last_ctx = ctx;
    cb_ctx->record->order[cb_ctx->record->order_len++] = cb_ctx->marker;
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

int main(void)
{
    const libbgp_test_case_t tests[] = {
        { "event_subscribe_returns_ids_and_counts_subscribers", event_subscribe_returns_ids_and_counts_subscribers },
        { "event_publish_exact_type_invokes_callbacks_in_order", event_publish_exact_type_invokes_callbacks_in_order },
        { "event_publish_different_type_does_not_notify", event_publish_different_type_does_not_notify },
        { "event_custom_subscriber_only_receives_custom_events", event_custom_subscriber_only_receives_custom_events },
        { "event_unsubscribe_removes_subscriber_and_reports_absent_id", event_unsubscribe_removes_subscriber_and_reports_absent_id },
        { "event_publish_null_inputs_return_zero", event_publish_null_inputs_return_zero },
        { "event_operations_after_destroy_use_null_behavior", event_operations_after_destroy_use_null_behavior }
    };

    return libbgp_run_tests("event", tests, LIBBGP_ARRAY_LEN(tests));
}
