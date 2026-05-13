#define _POSIX_C_SOURCE 200809L

#include "libbgp/event.h"
#include "libbgp/packet.h"
#include "libbgp/prefix4.h"
#include "libbgp/rib4.h"
#include "libbgp/sink.h"
#include "libbgp/update.h"
#include "../src/rib_internal.h"
#include "../tests/fixtures/bgp_packets.h"

#include <errno.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define BENCH_KEEPALIVE_BYTES LIBBGP_FIXTURE_KEEPALIVE_LEN

static uint64_t bench_sink_value;

static uint64_t now_ns(void)
{
    struct timespec ts;

    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) {
        return 0u;
    }
    return ((uint64_t)ts.tv_sec * 1000000000ull) + (uint64_t)ts.tv_nsec;
}

static size_t env_size(const char *name, size_t fallback)
{
    const char *value = getenv(name);
    char *end = NULL;
    unsigned long parsed;

    if (value == NULL || value[0] == '\0') {
        return fallback;
    }
    errno = 0;
    parsed = strtoul(value, &end, 10);
    if (errno != 0 || end == value || *end != '\0' || parsed == 0ul) {
        return fallback;
    }
    return (size_t)parsed;
}

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
    libbgp_prefix4_t p;

    p.addr = ip4(a, b, c, d) & libbgp_cidr_to_mask(len);
    p.len = len;
    return p;
}

static libbgp_rib4_route_t route4(libbgp_prefix4_t prefix, uint32_t source, uint32_t local_pref)
{
    libbgp_rib4_route_t route;

    memset(&route, 0, sizeof(route));
    route.prefix = prefix;
    route.source_router_id = source;
    route.next_hop = ip4(192u, 0u, 2u, (uint8_t)(source & 0xffu));
    route.local_pref = local_pref;
    route.origin = 0u;
    return route;
}

static void print_result(const char *name, size_t ops, uint64_t elapsed_ns)
{
    double ms = (double)elapsed_ns / 1000000.0;
    double ns_per_op = ops == 0u ? 0.0 : (double)elapsed_ns / (double)ops;

    printf("%-24s %8zu ops %10.3f ms %10.1f ns/op\n", name, ops, ms, ns_per_op);
}

static int bench_rib_lookup(size_t routes, size_t lookups)
{
    libbgp_rib4_t rib;
    const libbgp_rib4_route_t *found = NULL;
    size_t i;
    uint64_t start;
    uint64_t elapsed;

    if (libbgp_rib4_init(&rib) != LIBBGP_OK) {
        return 1;
    }
    for (i = 0u; i < routes; i++) {
        libbgp_prefix4_t prefix = p4(10u, (uint8_t)(i >> 8), (uint8_t)i, 0u, 24u);
        if (libbgp_rib4_insert_local(&rib, &prefix, ip4(192u, 0u, 2u, 1u), 100) != LIBBGP_OK) {
            libbgp_rib4_destroy(&rib);
            return 1;
        }
    }

    start = now_ns();
    for (i = 0u; i < lookups; i++) {
        uint32_t dest = ip4(10u, (uint8_t)(i >> 8), (uint8_t)i, (uint8_t)(i | 1u));
        if (libbgp_rib4_lookup(&rib, dest, &found) == LIBBGP_OK && found != NULL) {
            bench_sink_value += found->local_pref;
        }
    }
    elapsed = now_ns() - start;
    print_result("rib lookup", lookups, elapsed);
    libbgp_rib4_destroy(&rib);
    return 0;
}

static bool count_best_route(const libbgp_rib4_route_t *route, void *ctx)
{
    size_t *count = (size_t *)ctx;

    if (route != NULL) {
        (*count)++;
        bench_sink_value += route->source_router_id;
    }
    return true;
}

static int bench_rib_foreach_best(size_t prefixes)
{
    libbgp_rib4_t rib;
    size_t i;
    size_t best_count = 0u;
    uint64_t start;
    uint64_t elapsed;

    if (libbgp_rib4_init(&rib) != LIBBGP_OK) {
        return 1;
    }
    for (i = 0u; i < prefixes; i++) {
        libbgp_prefix4_t prefix = p4(10u, (uint8_t)(i >> 8), (uint8_t)i, 0u, 24u);
        libbgp_rib4_route_t route_a = route4(prefix, 1u, 100u);
        libbgp_rib4_route_t route_b = route4(prefix, 2u, 200u);

        if (libbgp_rib4_insert(&rib, &route_a) != LIBBGP_OK ||
            libbgp_rib4_insert(&rib, &route_b) != LIBBGP_OK) {
            libbgp_rib4_destroy(&rib);
            return 1;
        }
    }

    start = now_ns();
    if (bgp_rib4_foreach_best_route(&rib, count_best_route, &best_count) != LIBBGP_OK) {
        libbgp_rib4_destroy(&rib);
        return 1;
    }
    elapsed = now_ns() - start;
    bench_sink_value += best_count;
    print_result("rib foreach best", prefixes, elapsed);
    libbgp_rib4_destroy(&rib);
    return 0;
}

static int bench_rib_discard(size_t routes)
{
    libbgp_rib4_t rib;
    size_t i;
    uint64_t start;
    uint64_t elapsed;

    if (libbgp_rib4_init(&rib) != LIBBGP_OK) {
        return 1;
    }
    for (i = 0u; i < routes; i++) {
        libbgp_prefix4_t prefix = p4(10u, (uint8_t)(i >> 8), (uint8_t)i, 0u, 24u);
        libbgp_rib4_route_t route = route4(prefix, 42u, 100u);

        if (libbgp_rib4_insert(&rib, &route) != LIBBGP_OK) {
            libbgp_rib4_destroy(&rib);
            return 1;
        }
    }

    start = now_ns();
    if (libbgp_rib4_discard(&rib, 42u) != LIBBGP_OK) {
        libbgp_rib4_destroy(&rib);
        return 1;
    }
    elapsed = now_ns() - start;
    bench_sink_value += libbgp_rib4_route_count(&rib);
    print_result("rib discard", routes, elapsed);
    libbgp_rib4_destroy(&rib);
    return 0;
}

static int bench_rib_insert(size_t routes)
{
    libbgp_rib4_t rib;
    size_t i;
    uint64_t start;
    uint64_t elapsed;

    if (libbgp_rib4_init(&rib) != LIBBGP_OK) {
        return 1;
    }

    start = now_ns();
    for (i = 0u; i < routes; i++) {
        libbgp_prefix4_t prefix = p4(
            (uint8_t)(10u + (i >> 16)),
            (uint8_t)(i >> 8),
            (uint8_t)i, 0u, 24u);
        if (libbgp_rib4_insert_local(&rib, &prefix, ip4(192u, 0u, 2u, 1u), 100) != LIBBGP_OK) {
            libbgp_rib4_destroy(&rib);
            return 1;
        }
    }
    elapsed = now_ns() - start;
    print_result("rib insert", routes, elapsed);
    libbgp_rib4_destroy(&rib);
    return 0;
}

static int bench_sink_batch(size_t packets)
{
    uint8_t *buf;
    libbgp_sink_t sink;
    libbgp_packet_t pkt;
    size_t byte_len;
    size_t i;
    uint64_t start;
    uint64_t elapsed;

    if (packets > SIZE_MAX / BENCH_KEEPALIVE_BYTES) {
        return 1;
    }
    byte_len = packets * BENCH_KEEPALIVE_BYTES;
    buf = (uint8_t *)malloc(byte_len);
    if (buf == NULL) {
        return 1;
    }
    for (i = 0u; i < packets; i++) {
        memcpy(buf + (i * BENCH_KEEPALIVE_BYTES), LIBBGP_FIXTURE_KEEPALIVE, BENCH_KEEPALIVE_BYTES);
    }

    if (libbgp_sink_init(&sink) != LIBBGP_OK) {
        free(buf);
        return 1;
    }
    start = now_ns();
    if (libbgp_sink_feed(&sink, buf, byte_len) != LIBBGP_OK) {
        libbgp_sink_destroy(&sink);
        free(buf);
        return 1;
    }
    libbgp_packet_init(&pkt);
    for (i = 0u; i < packets; i++) {
        if (libbgp_sink_pop(&sink, &pkt) != LIBBGP_OK) {
            libbgp_packet_destroy(&pkt);
            libbgp_sink_destroy(&sink);
            free(buf);
            return 1;
        }
        bench_sink_value += (uint64_t)pkt.type;
        libbgp_packet_destroy(&pkt);
        libbgp_packet_init(&pkt);
    }
    libbgp_packet_destroy(&pkt);
    elapsed = now_ns() - start;
    print_result("sink batch feed/pop", packets, elapsed);
    libbgp_sink_destroy(&sink);
    free(buf);
    return 0;
}

static int bench_update_parse_write(size_t iterations)
{
    const uint8_t *body = LIBBGP_FIXTURE_UPDATE_IPV4 + LIBBGP_BGP_HEADER_LEN;
    const size_t body_len = LIBBGP_FIXTURE_UPDATE_IPV4_LEN - LIBBGP_BGP_HEADER_LEN;
    uint8_t out[128];
    size_t i;
    uint64_t start;
    uint64_t elapsed;

    start = now_ns();
    for (i = 0u; i < iterations; i++) {
        libbgp_update_msg_t msg;
        size_t used = 0u;
        size_t out_len = 0u;

        libbgp_update_init(&msg);
        if (libbgp_update_parse(&msg, body, body_len, &used) != LIBBGP_OK ||
            libbgp_update_write(&msg, out, sizeof(out), &out_len) != LIBBGP_OK) {
            libbgp_update_destroy(&msg);
            return 1;
        }
        bench_sink_value += used + out_len;
        libbgp_update_destroy(&msg);
    }
    elapsed = now_ns() - start;
    print_result("update parse/write", iterations, elapsed);
    return 0;
}

static int bench_update_parse_large(size_t iterations)
{
    libbgp_update_msg_t update;
    libbgp_pattr_t *origin = NULL;
    libbgp_pattr_t *as_path = NULL;
    libbgp_pattr_t *next_hop = NULL;
    uint8_t buf[4096];
    size_t serialized_len = 0u;
    size_t i;
    uint64_t start;
    uint64_t elapsed;

    libbgp_update_init(&update);
    origin = libbgp_pattr_new(LIBBGP_PATTR_ORIGIN);
    as_path = libbgp_pattr_new(LIBBGP_PATTR_AS_PATH);
    next_hop = libbgp_pattr_new(LIBBGP_PATTR_NEXT_HOP);
    if (origin == NULL || as_path == NULL || next_hop == NULL) {
        libbgp_pattr_unref(origin);
        libbgp_pattr_unref(as_path);
        libbgp_pattr_unref(next_hop);
        libbgp_update_destroy(&update);
        return 1;
    }
    origin->data.origin.origin = 0u;
    as_path->data.as_path.is_4b = false;
    next_hop->data.next_hop.next_hop = ip4(192u, 0u, 2u, 1u);
    if (libbgp_update_add_attr(&update, origin) != LIBBGP_OK ||
        libbgp_update_add_attr(&update, as_path) != LIBBGP_OK ||
        libbgp_update_add_attr(&update, next_hop) != LIBBGP_OK) {
        libbgp_pattr_unref(origin);
        libbgp_pattr_unref(as_path);
        libbgp_pattr_unref(next_hop);
        libbgp_update_destroy(&update);
        return 1;
    }
    libbgp_pattr_unref(origin);
    libbgp_pattr_unref(as_path);
    libbgp_pattr_unref(next_hop);

    for (i = 0u; i < 50u; i++) {
        libbgp_prefix4_t prefix = p4(10u, (uint8_t)(i >> 8), (uint8_t)i, 0u, 24u);

        if (libbgp_update_add_nlri(&update, &prefix) != LIBBGP_OK) {
            libbgp_update_destroy(&update);
            return 1;
        }
    }
    if (libbgp_update_write(&update, buf, sizeof(buf), &serialized_len) != LIBBGP_OK) {
        libbgp_update_destroy(&update);
        return 1;
    }
    libbgp_update_destroy(&update);

    start = now_ns();
    for (i = 0u; i < iterations; i++) {
        libbgp_update_msg_t msg;
        size_t used = 0u;

        libbgp_update_init(&msg);
        if (libbgp_update_parse(&msg, buf, serialized_len, &used) != LIBBGP_OK) {
            libbgp_update_destroy(&msg);
            return 1;
        }
        bench_sink_value += msg.nlri_count;
        libbgp_update_destroy(&msg);
    }
    elapsed = now_ns() - start;
    print_result("update parse large", iterations, elapsed);
    return 0;
}

static void event_counter_cb(const libbgp_event_t *event, void *ctx)
{
    size_t *calls = (size_t *)ctx;

    if (event != NULL) {
        (*calls)++;
        bench_sink_value += (uint64_t)event->type;
    }
}

static int bench_event_publish(size_t subscribers, size_t publishes)
{
    libbgp_event_bus_t bus;
    libbgp_event_t event;
    size_t calls = 0u;
    size_t callback_ops;
    size_t i;
    uint64_t start;
    uint64_t elapsed;

    if (publishes != 0u && subscribers > SIZE_MAX / publishes) {
        return 1;
    }
    callback_ops = subscribers * publishes;
    if (libbgp_event_bus_init(&bus) != LIBBGP_OK) {
        return 1;
    }
    for (i = 0u; i < subscribers; i++) {
        if (libbgp_event_bus_subscribe(&bus, LIBBGP_EVENT_ROUTE_ADDED, event_counter_cb, &calls, NULL) != LIBBGP_OK) {
            libbgp_event_bus_destroy(&bus);
            return 1;
        }
    }
    memset(&event, 0, sizeof(event));
    event.type = LIBBGP_EVENT_ROUTE_ADDED;

    start = now_ns();
    for (i = 0u; i < publishes; i++) {
        bench_sink_value += libbgp_event_bus_publish(&bus, &event);
    }
    elapsed = now_ns() - start;
    bench_sink_value += calls;
    print_result("event publish", callback_ops, elapsed);
    libbgp_event_bus_destroy(&bus);
    return 0;
}

int main(void)
{
    size_t small = env_size("LIBBGP_BENCH_SMALL", 1000u);
    size_t large = env_size("LIBBGP_BENCH_LARGE", 10000u);
    size_t subscribers = env_size("LIBBGP_BENCH_SUBSCRIBERS", small);
    int rc = 0;

    printf("libbgp bench: small=%zu large=%zu subscribers=%zu\n", small, large, subscribers);
    rc |= bench_rib_lookup(small, large);
    rc |= bench_rib_foreach_best(small);
    rc |= bench_rib_discard(small);
    rc |= bench_sink_batch(large);
    rc |= bench_update_parse_write(large);
    rc |= bench_rib_insert(small);
    rc |= bench_update_parse_large(large);
    rc |= bench_event_publish(subscribers, small);
    printf("bench guard: %" PRIu64 "\n", bench_sink_value);
    return rc == 0 ? 0 : 1;
}
