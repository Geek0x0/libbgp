#define _POSIX_C_SOURCE 200809L

#include "libbgp/event.h"
#include "libbgp/filter.h"
#include "libbgp/fsm.h"
#include "libbgp/out_handler.h"
#include "libbgp/packet.h"
#include "libbgp/pattr.h"
#include "libbgp/prefix4.h"
#include "libbgp/prefix6.h"
#include "libbgp/rib4.h"
#include "libbgp/rib6.h"
#include "libbgp/sink.h"
#include "libbgp/update.h"
#include "libbgp/alloc.h"
#include "../src/hashmap.h"
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

static libbgp_prefix4_t bench_route_prefix4(size_t index);

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

static uint64_t bench_u64_hash(const void *key, void *ctx)
{
    (void)ctx;
    return *(const uint64_t *)key * 11400714819323198485ull;
}

static bool bench_u64_eq(const void *a, const void *b, void *ctx)
{
    (void)ctx;
    return *(const uint64_t *)a == *(const uint64_t *)b;
}

static void bench_u64_free(void *key, void *value, void *ctx)
{
    (void)value;
    (void)ctx;
    libbgp_free(key);
}

static void print_result(const char *name, size_t ops, uint64_t elapsed_ns)
{
    double ms = (double)elapsed_ns / 1000000.0;
    double ns_per_op = ops == 0u ? 0.0 : (double)elapsed_ns / (double)ops;

    printf("%-24s %8zu ops %10.3f ms %10.1f ns/op\n", name, ops, ms, ns_per_op);
}

static libbgp_io_result_t bench_discard_send(void *ctx, const uint8_t *buf, size_t len)
{
    (void)ctx;
    (void)buf;
    bench_sink_value += len;
    return (libbgp_io_result_t)len;
}

static libbgp_pattr_t *bench_origin_attr(uint8_t origin_value)
{
    libbgp_pattr_t *attr = libbgp_pattr_new(LIBBGP_PATTR_ORIGIN);

    if (attr != NULL) {
        attr->data.origin.origin = origin_value;
    }
    return attr;
}

static libbgp_pattr_t *bench_next_hop_attr(uint32_t next_hop)
{
    libbgp_pattr_t *attr = libbgp_pattr_new(LIBBGP_PATTR_NEXT_HOP);

    if (attr != NULL) {
        attr->data.next_hop.next_hop = next_hop;
    }
    return attr;
}

static libbgp_pattr_t *bench_local_pref_attr(uint32_t local_pref)
{
    libbgp_pattr_t *attr = libbgp_pattr_new(LIBBGP_PATTR_LOCAL_PREF);

    if (attr != NULL) {
        attr->data.local_pref.value = local_pref;
    }
    return attr;
}

static libbgp_pattr_t *bench_as_path_attr(uint32_t asn)
{
    libbgp_pattr_t *attr = libbgp_pattr_new(LIBBGP_PATTR_AS_PATH);
    libbgp_as_path_segment_t *segment;
    uint32_t *asns;

    if (attr == NULL) {
        return NULL;
    }
    segment = (libbgp_as_path_segment_t *)calloc(1u, sizeof(*segment));
    asns = (uint32_t *)calloc(1u, sizeof(*asns));
    if (segment == NULL || asns == NULL) {
        free(segment);
        free(asns);
        libbgp_pattr_unref(attr);
        return NULL;
    }
    asns[0] = asn;
    segment->type = 2u;
    segment->asn_count = 1u;
    segment->asns = asns;
    attr->data.as_path.segments = segment;
    attr->data.as_path.segment_count = 1u;
    attr->data.as_path.is_4b = true;
    return attr;
}

static int bench_update_add_attr_owned(libbgp_update_msg_t *update, libbgp_pattr_t *attr)
{
    libbgp_err_t err;

    if (attr == NULL) {
        return 1;
    }
    err = libbgp_update_add_attr(update, attr);
    libbgp_pattr_unref(attr);
    return err == LIBBGP_OK ? 0 : 1;
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

static int bench_rib_lookup_scoped(size_t n_sources, size_t routes_per_source, size_t lookups)
{
    libbgp_rib4_t rib;
    uint64_t start, elapsed;
    size_t i, s;
    const libbgp_rib4_route_t *found = NULL;

    if (libbgp_rib4_init(&rib) != LIBBGP_OK) {
        return 1;
    }

    for (s = 0u; s < n_sources; s++) {
        uint32_t source = ip4(10u, 0u, (uint8_t)((s >> 8) & 0xffu), (uint8_t)(s & 0xffu));
        for (i = 0u; i < routes_per_source; i++) {
            libbgp_prefix4_t prefix = p4(
                (uint8_t)((i >> 8) & 0xffu),
                (uint8_t)(i & 0xffu), 0u, 0u, 16u);
            libbgp_rib4_route_t r = route4(prefix, source, 100u);
            if (libbgp_rib4_insert(&rib, &r) != LIBBGP_OK) {
                libbgp_rib4_destroy(&rib);
                return 1;
            }
        }
    }

    start = now_ns();
    for (i = 0u; i < lookups; i++) {
        uint32_t dest = ip4((uint8_t)((i >> 8) & 0xffu), (uint8_t)(i & 0xffu), 1u, 1u);
        uint32_t source = ip4(10u, 0u, 0u, 0u);
        found = NULL;
        if (libbgp_rib4_lookup_scoped(&rib, source, dest, &found) == LIBBGP_OK && found != NULL) {
            bench_sink_value += found->local_pref;
        }
    }
    elapsed = now_ns() - start;
    print_result("rib lookup_scoped", lookups, elapsed);

    libbgp_rib4_destroy(&rib);
    return 0;
}

static bool bench_count_iter(const libbgp_rib4_route_t *route, void *ctx)
{
    size_t *count = (size_t *)ctx;

    (void)route;
    (*count)++;
    return true;
}

static int bench_filter_apply(size_t rule_count)
{
    libbgp_filter_t filter;
    libbgp_rib4_route_t route;
    uint64_t start, elapsed;
    size_t i;
    size_t lookups = env_size("LIBBGP_BENCH_FILTER_LOOKUPS", 10000u);

    if (libbgp_filter_init(&filter) != LIBBGP_OK) {
        return 1;
    }
    for (i = 0u; i < rule_count; i++) {
        libbgp_filter_rule_t rule;

        memset(&rule, 0, sizeof(rule));
        rule.decision = LIBBGP_FILTER_PERMIT;
        rule.match_type = LIBBGP_FILTER_MATCH_PREFIX4;
        rule.match.prefix4 = p4(10u, (uint8_t)(i & 0xffu), 0u, 0u, 16u);
        if (libbgp_filter_add_rule(&filter, &rule) != LIBBGP_OK) {
            libbgp_filter_destroy(&filter);
            return 1;
        }
    }

    memset(&route, 0, sizeof(route));
    route.prefix = p4(192u, 168u, 0u, 0u, 16u);

    start = now_ns();
    for (i = 0u; i < lookups; i++) {
        bench_sink_value += (uint64_t)libbgp_filter_apply_route(&filter, &route, LIBBGP_FILTER_DENY);
    }
    elapsed = now_ns() - start;
    print_result("filter apply", lookups, elapsed);

    libbgp_filter_destroy(&filter);
    return 0;
}

static int bench_rib_foreach_best(size_t prefix_count, size_t paths_per_prefix)
{
    libbgp_rib4_t rib;
    uint64_t start, elapsed;
    size_t i, p;
    size_t count = 0u;

    if (libbgp_rib4_init(&rib) != LIBBGP_OK) {
        return 1;
    }

    for (i = 0u; i < prefix_count; i++) {
        libbgp_prefix4_t prefix = p4(
            (uint8_t)((i >> 8) & 0xffu),
            (uint8_t)(i & 0xffu), 0u, 0u, 16u);
        for (p = 0u; p < paths_per_prefix; p++) {
            uint32_t source = ip4(10u, 0u, (uint8_t)((p >> 8) & 0xffu), (uint8_t)(p & 0xffu));
            libbgp_rib4_route_t r = route4(prefix, source, 100u);
            if (libbgp_rib4_insert(&rib, &r) != LIBBGP_OK) {
                libbgp_rib4_destroy(&rib);
                return 1;
            }
        }
    }

    start = now_ns();
    if (bgp_rib4_foreach_best_route(&rib, bench_count_iter, &count) != LIBBGP_OK) {
        libbgp_rib4_destroy(&rib);
        return 1;
    }
    elapsed = now_ns() - start;
    if (count != prefix_count) {
        libbgp_rib4_destroy(&rib);
        return 1;
    }
    bench_sink_value += count;
    print_result("rib foreach_best", count, elapsed);
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

static int bench_rib_discard_collect(size_t routes_per_source)
{
    libbgp_rib4_t rib;
    uint64_t start, elapsed;
    uint32_t source = ip4(10u, 0u, 0u, 1u);
    uint32_t source2 = ip4(10u, 0u, 0u, 2u);
    bgp_rib4_discard_result_t result;
    size_t i;

    if (libbgp_rib4_init(&rib) != LIBBGP_OK) {
        return 1;
    }

    for (i = 0u; i < routes_per_source; i++) {
        libbgp_prefix4_t prefix = p4(
            (uint8_t)((i >> 8) & 0xffu),
            (uint8_t)(i & 0xffu), 0u, 0u, 16u);
        libbgp_rib4_route_t r = route4(prefix, source, 100u);
        libbgp_rib4_route_t r2 = route4(prefix, source2, 90u);
        if (libbgp_rib4_insert(&rib, &r) != LIBBGP_OK ||
            libbgp_rib4_insert(&rib, &r2) != LIBBGP_OK) {
            libbgp_rib4_destroy(&rib);
            return 1;
        }
    }

    memset(&result, 0, sizeof(result));
    start = now_ns();
    if (bgp_rib4_discard_collect(&rib, source, &result) != LIBBGP_OK) {
        bgp_rib4_discard_result_destroy(&result);
        libbgp_rib4_destroy(&rib);
        return 1;
    }
    elapsed = now_ns() - start;
    print_result("rib discard_collect", routes_per_source, elapsed);

    bgp_rib4_discard_result_destroy(&result);
    libbgp_rib4_destroy(&rib);
    return 0;
}

static int bench_fsm_apply_update(size_t prefixes_per_update)
{
    const size_t max_prefixes_per_update = 900u;
    struct libbgp_fsm_config config;
    libbgp_fsm_t fsm;
    libbgp_out_handler_t out_handler;
    libbgp_io_ops_t ops;
    libbgp_rib4_t rib;
    libbgp_packet_t open;
    libbgp_packet_t keepalive;
    libbgp_packet_t direct;
    libbgp_packet_t parsed;
    uint8_t raw[LIBBGP_BGP_MAX_PACKET_LEN];
    size_t raw_len = 0u;
    size_t consumed = 0u;
    size_t cycles = env_size("LIBBGP_BENCH_FSM_UPDATES", 1000u);
    size_t i;
    uint64_t start;
    uint64_t elapsed;
    int rc = 1;

    if (prefixes_per_update == 0u) {
        return 1;
    }
    if (prefixes_per_update > max_prefixes_per_update) {
        printf("fsm update import: clamping prefixes_per_update from %zu to %zu\n",
               prefixes_per_update,
               max_prefixes_per_update);
        prefixes_per_update = max_prefixes_per_update;
    }

    memset(&config, 0, sizeof(config));
    config.local_asn = 65000u;
    config.local_bgp_id = ip4(192u, 0u, 2u, 1u);
    config.hold_time = 45u;
    config.keepalive_time = 0u;
    config.enable_4byte_asn = true;
    config.enable_mpbgp_ipv6 = false;

    libbgp_packet_init(&open);
    libbgp_packet_init(&keepalive);
    libbgp_packet_init(&direct);
    libbgp_packet_init(&parsed);
    memset(&ops, 0, sizeof(ops));
    ops.send_fn = bench_discard_send;

    if (libbgp_rib4_init(&rib) != LIBBGP_OK) {
        goto done_packets;
    }
    if (libbgp_out_handler_init(&out_handler) != LIBBGP_OK) {
        goto done_rib;
    }
    libbgp_out_handler_set_ops(&out_handler, &ops);
    if (libbgp_fsm_init(&fsm, &config) != LIBBGP_OK) {
        goto done_out;
    }
    libbgp_fsm_set_out_handler(&fsm, &out_handler);
    libbgp_fsm_set_rib4(&fsm, &rib);

    open.type = LIBBGP_PACKET_OPEN;
    libbgp_open_init(&open.data.open);
    open.data.open.version = 4u;
    open.data.open.my_asn = 65010u;
    open.data.open.hold_time = 45u;
    open.data.open.bgp_id = ip4(198u, 51u, 100u, 10u);
    keepalive.type = LIBBGP_PACKET_KEEPALIVE;

    if (libbgp_fsm_start(&fsm) != LIBBGP_OK ||
        libbgp_fsm_on_packet(&fsm, &open) != LIBBGP_OK ||
        libbgp_fsm_on_packet(&fsm, &keepalive) != LIBBGP_OK ||
        libbgp_fsm_state(&fsm) != LIBBGP_FSM_ESTABLISHED) {
        goto done_fsm;
    }

    direct.type = LIBBGP_PACKET_UPDATE;
    libbgp_update_init(&direct.data.update);
    if (bench_update_add_attr_owned(&direct.data.update, bench_origin_attr(0u)) != 0 ||
        bench_update_add_attr_owned(&direct.data.update, bench_as_path_attr(65010u)) != 0 ||
        bench_update_add_attr_owned(&direct.data.update, bench_next_hop_attr(ip4(192u, 0u, 2u, 254u))) != 0 ||
        bench_update_add_attr_owned(&direct.data.update, bench_local_pref_attr(200u)) != 0) {
        goto done_fsm;
    }
    for (i = 0u; i < prefixes_per_update; i++) {
        libbgp_prefix4_t prefix = bench_route_prefix4(i);

        if (libbgp_update_add_nlri(&direct.data.update, &prefix) != LIBBGP_OK) {
            goto done_fsm;
        }
    }
    if (libbgp_packet_write(&direct, raw, sizeof(raw), &raw_len) != LIBBGP_OK ||
        libbgp_packet_parse_as4(&parsed, raw, raw_len, true, &consumed) != LIBBGP_OK ||
        consumed != raw_len ||
        parsed.type != LIBBGP_PACKET_UPDATE) {
        goto done_fsm;
    }

    start = now_ns();
    for (i = 0u; i < cycles; i++) {
        if (libbgp_fsm_on_packet(&fsm, &parsed) != LIBBGP_OK) {
            goto done_fsm;
        }
    }
    elapsed = now_ns() - start;
    printf("fsm update import @ %-5zu %8zu ops %10.3f ms %10.1f ns/prefix\n",
           prefixes_per_update,
           cycles * prefixes_per_update,
           (double)elapsed / 1000000.0,
           (double)elapsed / (double)(cycles * prefixes_per_update));
    bench_sink_value += libbgp_rib4_route_count(&rib);
    rc = 0;

done_fsm:
    libbgp_fsm_destroy(&fsm);
done_out:
    libbgp_out_handler_destroy(&out_handler);
done_rib:
    libbgp_rib4_destroy(&rib);
done_packets:
    libbgp_packet_destroy(&parsed);
    libbgp_packet_destroy(&direct);
    libbgp_packet_destroy(&keepalive);
    libbgp_packet_destroy(&open);
    return rc;
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

/* ========== 性能分析基准测试 ========== */

/* 计算统计数据的辅助函数 */
static void compute_stats(uint64_t *times, size_t count,
                         uint64_t *min, uint64_t *max, uint64_t *avg,
                         uint64_t *p50, uint64_t *p99)
{
    if (count == 0) return;
    
    uint64_t sum = 0;
    *min = times[0];
    *max = times[0];
    
    for (size_t i = 0; i < count; i++) {
        sum += times[i];
        if (times[i] < *min) *min = times[i];
        if (times[i] > *max) *max = times[i];
    }
    
    *avg = sum / count;
    
    /* 简单排序计算百分位数 */
    for (size_t i = 0; i < count; i++) {
        for (size_t j = i + 1; j < count; j++) {
            if (times[j] < times[i]) {
                uint64_t tmp = times[i];
                times[i] = times[j];
                times[j] = tmp;
            }
        }
    }
    
    *p50 = times[count / 2];
    *p99 = times[(count * 99) / 100];
}

/* PRNG 用于生成伪随机地址 */
static uint32_t prng_next(uint32_t *seed)
{
    *seed = *seed * 1103515245 + 12345;
    return (*seed >> 16) & 0x7fff;
}

static uint32_t generate_random_ipv4(uint32_t *seed)
{
    uint32_t a = prng_next(seed);
    uint32_t b = prng_next(seed);
    uint32_t c = prng_next(seed);
    uint32_t d = prng_next(seed);
    return (a << 24) | (b << 16) | (c << 8) | d;
}

static libbgp_prefix4_t bench_route_prefix4(size_t index)
{
    return p4(
        (uint8_t)(10u + (index >> 16)),
        (uint8_t)(index >> 8),
        (uint8_t)index,
        0u,
        24u);
}

static libbgp_prefix6_t bench_route_prefix6(size_t index)
{
    libbgp_prefix6_t prefix;

    memset(&prefix, 0, sizeof(prefix));
    prefix.addr[0] = 0x20u;
    prefix.addr[1] = 0x01u;
    prefix.addr[2] = 0x0du;
    prefix.addr[3] = 0xb8u;
    prefix.addr[6] = (uint8_t)(index >> 8);
    prefix.addr[7] = (uint8_t)index;
    prefix.len = 64u;
    return prefix;
}

static void bench_dest6(size_t index, uint8_t out[16])
{
    libbgp_prefix6_t prefix = bench_route_prefix6(index);

    memcpy(out, prefix.addr, sizeof(prefix.addr));
    out[15] = (uint8_t)(index | 1u);
}

/* 详细的RIB lookup延迟分析 - 可配置规模 */
static int bench_rib_lookup_detailed(size_t num_routes)
{
    libbgp_rib4_t rib;
    const libbgp_rib4_route_t *found = NULL;
    uint64_t *timings;
    size_t lookups = num_routes < 1000 ? 5000 : (num_routes < 10000 ? 2000 : 500);
    uint32_t seed = 12345;
    size_t i;
    uint64_t start;
    
    uint64_t min_ns, max_ns, avg_ns, p50_ns, p99_ns;
    double ms_total;
    
    if (libbgp_rib4_init(&rib) != LIBBGP_OK) {
        fprintf(stderr, "ERROR: rib4_init failed\n");
        return 1;
    }
    
    /* 插入路由 */
    printf("\n--- Inserting %zu routes ---\n", num_routes);
    fflush(stdout);
    for (i = 0u; i < num_routes; i++) {
        libbgp_prefix4_t prefix = bench_route_prefix4(i);
        
        if (libbgp_rib4_insert_local(&rib, &prefix, ip4(192u, 0u, 2u, 1u), 100) != LIBBGP_OK) {
            fprintf(stderr, "ERROR: rib4_insert_local failed at index %zu\n", i);
            libbgp_rib4_destroy(&rib);
            return 1;
        }
    }
    
    timings = (uint64_t *)malloc(lookups * sizeof(uint64_t));
    if (timings == NULL) {
        fprintf(stderr, "ERROR: malloc timings failed\n");
        libbgp_rib4_destroy(&rib);
        return 1;
    }
    
    /* 执行lookups并计时 */
    printf("--- Performing %zu lookups ---\n", lookups);
    fflush(stdout);
    seed = 67890;
    for (i = 0u; i < lookups; i++) {
        uint32_t query_addr = generate_random_ipv4(&seed);
        
        start = now_ns();
        libbgp_rib4_lookup(&rib, query_addr, &found);
        timings[i] = now_ns() - start;
    }
    
    compute_stats(timings, lookups, &min_ns, &max_ns, &avg_ns, &p50_ns, &p99_ns);
    
    ms_total = (double)(avg_ns * lookups) / 1000000.0;
    printf("rib lookup @ %zu routes: %llu/%llu/%llu (min/avg/max) ns, "
           "p50=%llu p99=%llu (%.1f ms total for %zu ops)\n",
           num_routes,
           (unsigned long long)min_ns,
           (unsigned long long)avg_ns,
           (unsigned long long)max_ns,
           (unsigned long long)p50_ns,
           (unsigned long long)p99_ns,
           ms_total, lookups);
    fflush(stdout);
    
    free(timings);
    libbgp_rib4_destroy(&rib);
    bench_sink_value += min_ns;
    return 0;
}

static int bench_rib6_lookup_detailed(size_t num_routes, size_t lookups)
{
    libbgp_rib6_t rib;
    const libbgp_rib6_route_t *found = NULL;
    static const uint8_t next_hop[16] = { 0x20u, 0x01u, 0x0du, 0xb8u, 0xffu, 0xffu };
    uint8_t (*dests)[16];
    size_t i;
    uint64_t start;
    uint64_t elapsed;

    if (num_routes == 0u || libbgp_rib6_init(&rib) != LIBBGP_OK) {
        return 1;
    }
    if (lookups > SIZE_MAX / sizeof(*dests)) {
        libbgp_rib6_destroy(&rib);
        return 1;
    }
    dests = (uint8_t (*)[16])malloc(lookups * sizeof(*dests));
    if (dests == NULL) {
        libbgp_rib6_destroy(&rib);
        return 1;
    }
    for (i = 0u; i < num_routes; i++) {
        libbgp_prefix6_t prefix = bench_route_prefix6(i);

        if (libbgp_rib6_insert_local(&rib, &prefix, next_hop, 100) != LIBBGP_OK) {
            free(dests);
            libbgp_rib6_destroy(&rib);
            return 1;
        }
    }
    for (i = 0u; i < lookups; i++) {
        bench_dest6(i % num_routes, dests[i]);
    }

    start = now_ns();
    for (i = 0u; i < lookups; i++) {
        if (libbgp_rib6_lookup(&rib, dests[i], &found) == LIBBGP_OK && found != NULL) {
            bench_sink_value += found->local_pref;
        }
    }
    elapsed = now_ns() - start;
    printf("rib6 lookup @ %-8zu %8zu ops %10.3f ms %10.1f ns/op\n",
           num_routes,
           lookups,
           (double)elapsed / 1000000.0,
           lookups == 0u ? 0.0 : (double)elapsed / (double)lookups);
    free(dests);
    libbgp_rib6_destroy(&rib);
    return 0;
}

static int bench_rib4_maintenance_after_radix(size_t routes)
{
    libbgp_rib4_t rib;
    size_t i;
    uint64_t start;
    uint64_t insert_elapsed;
    uint64_t discard_elapsed;

    if (routes == 0u || libbgp_rib4_init(&rib) != LIBBGP_OK) {
        return 1;
    }

    start = now_ns();
    for (i = 0u; i < routes; i++) {
        libbgp_prefix4_t prefix = bench_route_prefix4(i);
        libbgp_rib4_route_t route = route4(prefix, 42u, 100u);

        if (libbgp_rib4_insert(&rib, &route) != LIBBGP_OK) {
            libbgp_rib4_destroy(&rib);
            return 1;
        }
    }
    insert_elapsed = now_ns() - start;

    start = now_ns();
    if (libbgp_rib4_discard(&rib, 42u) != LIBBGP_OK) {
        libbgp_rib4_destroy(&rib);
        return 1;
    }
    discard_elapsed = now_ns() - start;
    bench_sink_value += libbgp_rib4_route_count(&rib);

    printf("rib4 insert @ %-8zu %8zu ops %10.3f ms %10.1f ns/op\n",
           routes,
           routes,
           (double)insert_elapsed / 1000000.0,
           (double)insert_elapsed / (double)routes);
    printf("rib4 discard @ %-7zu %8zu ops %10.3f ms %10.1f ns/op\n",
           routes,
           routes,
           (double)discard_elapsed / 1000000.0,
           (double)discard_elapsed / (double)routes);

    libbgp_rib4_destroy(&rib);
    return 0;
}

/* HashMap性能分析 - 插入扩容跟踪 */
static int bench_hashmap_load_factor(void)
{
    printf("\n--- HashMap Load Factor Analysis ---\n");
    printf("Testing insert performance and resize patterns\n");
    printf("Threshold: 75%% load factor\n\n");
    fflush(stdout);
    
    libbgp_rib4_t rib;
    uint64_t *insert_times;
    uint64_t start;
    size_t i, num_inserts = 2000;
    
    if (libbgp_rib4_init(&rib) != LIBBGP_OK) {
        return 1;
    }
    
    insert_times = (uint64_t *)malloc(num_inserts * sizeof(uint64_t));
    if (insert_times == NULL) {
        libbgp_rib4_destroy(&rib);
        return 1;
    }
    
    uint64_t min_time = UINT64_MAX, max_time = 0, sum_time = 0;
    uint64_t resize_penalties = 0;
    
    for (i = 0u; i < num_inserts; i++) {
        libbgp_prefix4_t prefix = bench_route_prefix4(i);
        
        start = now_ns();
        if (libbgp_rib4_insert_local(&rib, &prefix, ip4(192u, 0u, 2u, 1u), 100) != LIBBGP_OK) {
            free(insert_times);
            libbgp_rib4_destroy(&rib);
            return 1;
        }
        insert_times[i] = now_ns() - start;
        
        sum_time += insert_times[i];
        if (insert_times[i] < min_time) min_time = insert_times[i];
        if (insert_times[i] > max_time) max_time = insert_times[i];
        
        if (insert_times[i] > 10000) {
            resize_penalties++;
        }
    }
    
    printf("Insert operations:\n");
    printf("  Total ops:     %zu\n", num_inserts);
    printf("  Min latency:   %llu ns\n", (unsigned long long)min_time);
    printf("  Max latency:   %llu ns (resize penalty)\n", (unsigned long long)max_time);
    printf("  Avg latency:   %llu ns\n", (unsigned long long)(sum_time / num_inserts));
    printf("  Resize events: %zu (>10us latency)\n", resize_penalties);
    printf("  Total time:    %.2f ms\n\n", (double)sum_time / 1000000.0);
    
    free(insert_times);
    libbgp_rib4_destroy(&rib);
    bench_sink_value += min_time;
    return 0;
}

static int cmp_u64(const void *a, const void *b)
{
    uint64_t x = *(const uint64_t *)a;
    uint64_t y = *(const uint64_t *)b;
    return (x > y) - (x < y);
}

static int bench_hashmap_batch_insert(size_t count, bool use_reserve)
{
    bgp_hashmap_t map;
    uint64_t elapsed;
    size_t i;
    char name[64];
    uint64_t *samples;

    if (bgp_hashmap_init(&map, bench_u64_hash, bench_u64_eq, bench_u64_free, NULL) != LIBBGP_OK) {
        return 1;
    }
    if (use_reserve && bgp_hashmap_reserve(&map, count) != LIBBGP_OK) {
        bgp_hashmap_destroy(&map);
        return 1;
    }

    samples = (uint64_t *)libbgp_malloc(count * sizeof(*samples));
    if (samples == NULL) {
        bgp_hashmap_destroy(&map);
        return 1;
    }

    for (i = 0u; i < count; i++) {
        uint64_t start = now_ns();
        uint64_t *key = (uint64_t *)libbgp_malloc(sizeof(*key));

        if (key == NULL) {
            libbgp_free(samples);
            bgp_hashmap_destroy(&map);
            return 1;
        }
        *key = (uint64_t)i;
        if (bgp_hashmap_insert(&map, key, NULL) != LIBBGP_OK) {
            libbgp_free(key);
            libbgp_free(samples);
            bgp_hashmap_destroy(&map);
            return 1;
        }
        samples[i] = now_ns() - start;
    }

    elapsed = 0u;
    for (i = 0u; i < count; i++) {
        elapsed += samples[i];
    }

    qsort(samples, count, sizeof(*samples), cmp_u64);
    uint64_t p99 = samples[(size_t)(count * 0.99)];

    snprintf(name, sizeof(name), "hashmap insert %s", use_reserve ? "reserved" : "default");
    print_result(name, count, elapsed);
    printf("%-24s            %10s %10" PRIu64 " ns/op\n", "", "p99:", p99);
    bench_sink_value += bgp_hashmap_len(&map);

    libbgp_free(samples);
    bgp_hashmap_destroy(&map);
    return 0;
}

static int bench_sink_pop_packets(libbgp_sink_t *sink, libbgp_packet_t *pkt, size_t count)
{
    size_t i;

    for (i = 0u; i < count; i++) {
        if (libbgp_sink_pop(sink, pkt) != LIBBGP_OK) {
            return 1;
        }
        bench_sink_value += (uint64_t)pkt->type;
        libbgp_packet_destroy(pkt);
        libbgp_packet_init(pkt);
    }
    return 0;
}

static int bench_sink_fragmented_feed(size_t cycles)
{
    enum {
        KEEPALIVE_SPLIT = 10u,
        FIRST_FRAGMENT = LIBBGP_BGP_HEADER_LEN + KEEPALIVE_SPLIT,
        SECOND_FRAGMENT = (LIBBGP_BGP_HEADER_LEN - KEEPALIVE_SPLIT) + (2u * LIBBGP_BGP_HEADER_LEN)
    };
    uint8_t first[FIRST_FRAGMENT];
    uint8_t second[SECOND_FRAGMENT];
    libbgp_sink_t sink;
    libbgp_packet_t pkt;
    size_t i;
    uint64_t start;
    uint64_t elapsed;
    size_t packets;

    if (cycles > SIZE_MAX / 4u) {
        return 1;
    }
    packets = cycles * 4u;

    memcpy(first, LIBBGP_FIXTURE_KEEPALIVE, BENCH_KEEPALIVE_BYTES);
    memcpy(first + BENCH_KEEPALIVE_BYTES, LIBBGP_FIXTURE_KEEPALIVE, 10u);
    memcpy(second, LIBBGP_FIXTURE_KEEPALIVE + 10u, BENCH_KEEPALIVE_BYTES - 10u);
    memcpy(second + (BENCH_KEEPALIVE_BYTES - 10u), LIBBGP_FIXTURE_KEEPALIVE, BENCH_KEEPALIVE_BYTES);
    memcpy(
        second + (BENCH_KEEPALIVE_BYTES - 10u) + BENCH_KEEPALIVE_BYTES,
        LIBBGP_FIXTURE_KEEPALIVE,
        BENCH_KEEPALIVE_BYTES);

    if (libbgp_sink_init(&sink) != LIBBGP_OK) {
        return 1;
    }
    libbgp_packet_init(&pkt);

    if (libbgp_sink_feed(&sink, first, sizeof(first)) != LIBBGP_OK ||
        bench_sink_pop_packets(&sink, &pkt, 1u) != 0 ||
        libbgp_sink_feed(&sink, second, sizeof(second)) != LIBBGP_OK ||
        bench_sink_pop_packets(&sink, &pkt, 3u) != 0) {
        libbgp_packet_destroy(&pkt);
        libbgp_sink_destroy(&sink);
        return 1;
    }

    start = now_ns();
    for (i = 0u; i < cycles; i++) {
        if (libbgp_sink_feed(&sink, first, sizeof(first)) != LIBBGP_OK ||
            bench_sink_pop_packets(&sink, &pkt, 1u) != 0) {
            libbgp_packet_destroy(&pkt);
            libbgp_sink_destroy(&sink);
            return 1;
        }

        if (libbgp_sink_feed(&sink, second, sizeof(second)) != LIBBGP_OK ||
            bench_sink_pop_packets(&sink, &pkt, 3u) != 0) {
            libbgp_packet_destroy(&pkt);
            libbgp_sink_destroy(&sink);
            return 1;
        }
    }
    elapsed = now_ns() - start;

    print_result("sink fragmented memmove", packets, elapsed);
    libbgp_packet_destroy(&pkt);
    libbgp_sink_destroy(&sink);
    return 0;
}

static int bench_sink_feed_chunks(size_t chunk_size)
{
    libbgp_sink_t sink;
    uint64_t start;
    uint64_t elapsed;
    size_t total_fed = 0u;
    size_t packets_parsed = 0u;
    size_t iterations = 1000u;
    size_t i;
    char name[64];

    if (chunk_size == 0u) {
        return 1;
    }
    if (libbgp_sink_init(&sink) != LIBBGP_OK) {
        return 1;
    }

    start = now_ns();
    for (i = 0u; i < iterations; i++) {
        size_t offset = 0u;

        while (offset < BENCH_KEEPALIVE_BYTES) {
            size_t feed_len = chunk_size;

            if (offset + feed_len > BENCH_KEEPALIVE_BYTES) {
                feed_len = BENCH_KEEPALIVE_BYTES - offset;
            }
            if (libbgp_sink_feed(&sink, LIBBGP_FIXTURE_KEEPALIVE + offset, feed_len) != LIBBGP_OK) {
                libbgp_sink_destroy(&sink);
                return 1;
            }
            offset += feed_len;
            total_fed += feed_len;
        }
        {
            libbgp_packet_t pkt;

            libbgp_packet_init(&pkt);
            if (libbgp_sink_pop(&sink, &pkt) != LIBBGP_OK) {
                libbgp_packet_destroy(&pkt);
                libbgp_sink_destroy(&sink);
                return 1;
            }
            packets_parsed++;
            bench_sink_value += (uint64_t)pkt.type;
            libbgp_packet_destroy(&pkt);
        }
    }
    elapsed = now_ns() - start;

    snprintf(name, sizeof(name), "sink feed chunk=%zu", chunk_size);
    print_result(name, iterations, elapsed);
    bench_sink_value += total_fed + packets_parsed;

    libbgp_sink_destroy(&sink);
    return 0;
}

/* Sink缓冲区吞吐量分析 */
static int bench_sink_throughput_analysis(void)
{
    printf("\n--- Sink Buffer Throughput Analysis ---\n");
    
    libbgp_sink_t sink;
    uint64_t *timings;
    uint64_t start, total_bytes = 0;
    uint64_t min_ns, max_ns, avg_ns, p50_ns, p99_ns;
    size_t i, num_packets = 5000;
    
    if (libbgp_sink_init(&sink) != LIBBGP_OK) {
        return 1;
    }
    
    timings = (uint64_t *)malloc(num_packets * sizeof(uint64_t));
    if (timings == NULL) {
        libbgp_sink_destroy(&sink);
        return 1;
    }
    
    printf("Test: Small packets (keepalive-like)\n");
    fflush(stdout);
    for (i = 0u; i < num_packets; i++) {
        start = now_ns();
        if (libbgp_sink_feed(&sink, (const uint8_t *)LIBBGP_FIXTURE_KEEPALIVE,
                            LIBBGP_FIXTURE_KEEPALIVE_LEN) != LIBBGP_OK) {
            free(timings);
            libbgp_sink_destroy(&sink);
            return 1;
        }
        timings[i] = now_ns() - start;
        total_bytes += LIBBGP_FIXTURE_KEEPALIVE_LEN;
    }
    
    compute_stats(timings, num_packets, &min_ns, &max_ns, &avg_ns, &p50_ns, &p99_ns);
    
    double throughput_mbps = (double)total_bytes * 8.0 / (double)(avg_ns * num_packets) * 1000.0;
    printf("  Feed latency: %llu/%llu/%llu (min/avg/max) ns\n",
           (unsigned long long)min_ns, (unsigned long long)avg_ns, (unsigned long long)max_ns);
    printf("  P50: %llu ns, P99: %llu ns\n",
           (unsigned long long)p50_ns, (unsigned long long)p99_ns);
    printf("  Throughput: %.1f Mbps\n\n", throughput_mbps);
    fflush(stdout);
    
    free(timings);
    libbgp_sink_destroy(&sink);
    bench_sink_value += min_ns;
    return 0;
}

int main(void)
{
    size_t small = env_size("LIBBGP_BENCH_SMALL", 1000u);
    size_t large = env_size("LIBBGP_BENCH_LARGE", 10000u);
    size_t subscribers = env_size("LIBBGP_BENCH_SUBSCRIBERS", small);
    size_t hashmap_inserts = env_size("LIBBGP_BENCH_HASHMAP_INSERTS", large);
    int rc = 0;

    printf("libbgp bench: small=%zu large=%zu subscribers=%zu\n", small, large, subscribers);
    
    printf("\n========== Basic Benchmarks ==========\n");
    rc |= bench_rib_lookup(small, large);
    rc |= bench_rib_lookup_scoped(4u, env_size("BENCH_ROUTES", 2500u), env_size("BENCH_LOOKUPS", 10000u));
    rc |= bench_filter_apply(env_size("LIBBGP_BENCH_FILTER_RULES", small));
    rc |= bench_rib_foreach_best(env_size("BENCH_PREFIXES", 5000u), 4u);
    rc |= bench_rib_discard(small);
    rc |= bench_rib_discard_collect(env_size("BENCH_ROUTES", 10000u));
    rc |= bench_sink_batch(large);
    rc |= bench_update_parse_write(large);
    rc |= bench_rib_insert(small);
    rc |= bench_fsm_apply_update(1u);
    rc |= bench_fsm_apply_update(16u);
    rc |= bench_fsm_apply_update(env_size("LIBBGP_BENCH_FSM_PREFIXES", 256u));
    rc |= bench_update_parse_large(large);
    rc |= bench_event_publish(subscribers, small);
    
    printf("\n========== Detailed Performance Analysis ==========\n");
    rc |= bench_rib_lookup_detailed(1000);
    rc |= bench_rib_lookup_detailed(10000);
    rc |= bench_rib6_lookup_detailed(1000, small);
    rc |= bench_rib6_lookup_detailed(10000, small);
    rc |= bench_rib4_maintenance_after_radix(1000);
    rc |= bench_rib4_maintenance_after_radix(10000);
    rc |= bench_hashmap_load_factor();
    rc |= bench_hashmap_batch_insert(hashmap_inserts, false);
    rc |= bench_hashmap_batch_insert(hashmap_inserts, true);
    rc |= bench_sink_fragmented_feed(small);
    rc |= bench_sink_feed_chunks(1u);
    rc |= bench_sink_feed_chunks(10u);
    rc |= bench_sink_feed_chunks(19u);
    rc |= bench_sink_throughput_analysis();
    
    printf("bench guard: %" PRIu64 "\n", bench_sink_value);
    return rc == 0 ? 0 : 1;
}
