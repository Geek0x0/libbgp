#include <libbgp/libbgp.h>

#include <stdint.h>
#include <stdio.h>
#include <string.h>

typedef struct event_counter {
    const char *name;
    unsigned int calls;
} event_counter_t;

static uint32_t ip4(uint8_t a, uint8_t b, uint8_t c, uint8_t d)
{
    uint8_t bytes[4];
    uint32_t value;

    bytes[0] = a;
    bytes[1] = b;
    bytes[2] = c;
    bytes[3] = d;
    memcpy(&value, bytes, sizeof(value));
    return value;
}

static libbgp_prefix4_t p4(uint8_t a, uint8_t b, uint8_t c, uint8_t d, uint8_t len)
{
    libbgp_prefix4_t prefix;

    prefix.addr = ip4(a, b, c, d) & libbgp_cidr_to_mask(len);
    prefix.len = len;
    return prefix;
}

static void print_prefix4(const libbgp_prefix4_t *prefix)
{
    uint8_t bytes[4];

    memcpy(bytes, &prefix->addr, sizeof(bytes));
    printf("%u.%u.%u.%u/%u",
        (unsigned int)bytes[0],
        (unsigned int)bytes[1],
        (unsigned int)bytes[2],
        (unsigned int)bytes[3],
        (unsigned int)prefix->len);
}

static void count_event(const libbgp_event_t *event, void *ctx)
{
    event_counter_t *counter = (event_counter_t *)ctx;

    if (counter == NULL || event == NULL) {
        return;
    }
    counter->calls++;
    printf("%s saw event type=%u", counter->name, (unsigned int)event->type);
    if (event->prefix4 != NULL) {
        printf(" prefix=");
        print_prefix4(event->prefix4);
    }
    printf("\n");
}

int main(void)
{
    libbgp_event_bus_t bus;
    event_counter_t first = { "first", 0u };
    event_counter_t second = { "second", 0u };
    libbgp_prefix4_t prefix = p4(203u, 0u, 113u, 0u, 24u);
    libbgp_event_t event;
    uint64_t first_id = 0u;
    uint64_t second_id = 0u;
    size_t delivered;
    libbgp_err_t err;

    err = libbgp_event_bus_init(&bus);
    if (err != LIBBGP_OK) {
        fprintf(stderr, "event bus init failed: %s\n", libbgp_strerror(err));
        return 1;
    }
    err = libbgp_event_bus_subscribe(&bus, LIBBGP_EVENT_ROUTE_ADDED, count_event, &first, &first_id);
    if (err == LIBBGP_OK) {
        err = libbgp_event_bus_subscribe(&bus, LIBBGP_EVENT_ROUTE_ADDED, count_event, &second, &second_id);
    }
    if (err != LIBBGP_OK) {
        fprintf(stderr, "subscribe failed: %s\n", libbgp_strerror(err));
        libbgp_event_bus_destroy(&bus);
        return 1;
    }

    memset(&event, 0, sizeof(event));
    event.type = LIBBGP_EVENT_ROUTE_ADDED;
    event.source_router_id = ip4(192u, 0u, 2u, 10u);
    event.prefix4 = &prefix;

    delivered = libbgp_event_bus_publish(&bus, &event);
    err = libbgp_event_bus_unsubscribe(&bus, first_id);
    if (err != LIBBGP_OK) {
        fprintf(stderr, "unsubscribe failed: %s\n", libbgp_strerror(err));
        libbgp_event_bus_destroy(&bus);
        return 1;
    }
    delivered += libbgp_event_bus_publish(&bus, &event);

    printf("delivered=%zu first_calls=%u second_calls=%u subscribers=%zu\n",
        delivered,
        first.calls,
        second.calls,
        libbgp_event_bus_subscriber_count(&bus));
    (void)second_id;

    libbgp_event_bus_destroy(&bus);
    return 0;
}
