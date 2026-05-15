#include <libbgp/libbgp.h>

#include <stdint.h>
#include <stdio.h>
#include <string.h>

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

static libbgp_rib4_route_t route4(libbgp_prefix4_t prefix, uint32_t source_router_id)
{
    libbgp_rib4_route_t route;

    memset(&route, 0, sizeof(route));
    route.prefix = prefix;
    route.source_router_id = source_router_id;
    route.next_hop = ip4(198u, 51u, 100u, 1u);
    route.local_pref = 100u;
    route.origin = 0u;
    return route;
}

int main(void)
{
    libbgp_rib4_t rib;
    libbgp_packet_t withdraw;
    libbgp_packet_t parsed;
    libbgp_prefix4_t prefix = p4(203u, 0u, 113u, 0u, 24u);
    uint32_t source = ip4(192u, 0u, 2u, 10u);
    libbgp_rib4_route_t route = route4(prefix, source);
    const libbgp_rib4_route_t *found = NULL;
    uint8_t wire[128];
    size_t wire_len = 0u;
    size_t consumed = 0u;
    libbgp_err_t err;

    err = libbgp_rib4_init(&rib);
    if (err != LIBBGP_OK) {
        fprintf(stderr, "rib init failed: %s\n", libbgp_strerror(err));
        return 1;
    }
    err = libbgp_rib4_insert(&rib, &route);
    if (err == LIBBGP_OK) {
        err = libbgp_rib4_lookup(&rib, ip4(203u, 0u, 113u, 7u), &found);
    }
    if (err != LIBBGP_OK || found == NULL) {
        fprintf(stderr, "rib insert/lookup failed: %s\n", libbgp_strerror(err));
        libbgp_rib4_destroy(&rib);
        return 1;
    }

    libbgp_packet_init(&withdraw);
    libbgp_packet_init(&parsed);
    withdraw.type = LIBBGP_PACKET_UPDATE;
    libbgp_update_init(&withdraw.data.update);
    err = libbgp_update_add_withdrawn(&withdraw.data.update, &prefix);
    if (err == LIBBGP_OK) {
        err = libbgp_packet_write(&withdraw, wire, sizeof(wire), &wire_len);
    }
    if (err == LIBBGP_OK) {
        err = libbgp_packet_parse(&parsed, wire, wire_len, &consumed);
    }
    if (err == LIBBGP_OK && parsed.data.update.withdrawn_count > 0u) {
        err = libbgp_rib4_withdraw(&rib, source, &parsed.data.update.withdrawn[0]);
    }
    if (err != LIBBGP_OK) {
        fprintf(stderr, "withdraw failed: %s\n", libbgp_strerror(err));
        libbgp_packet_destroy(&parsed);
        libbgp_packet_destroy(&withdraw);
        libbgp_rib4_destroy(&rib);
        return 1;
    }

    found = NULL;
    err = libbgp_rib4_lookup(&rib, ip4(203u, 0u, 113u, 7u), &found);
    printf("withdraw UPDATE length=%zu consumed=%zu withdrawn=%zu\n",
        wire_len,
        consumed,
        parsed.data.update.withdrawn_count);
    printf("rib route count=%zu lookup_after_withdraw=%s err=%s\n",
        libbgp_rib4_route_count(&rib),
        found == NULL ? "miss" : "hit",
        libbgp_strerror(err));

    libbgp_packet_destroy(&parsed);
    libbgp_packet_destroy(&withdraw);
    libbgp_rib4_destroy(&rib);
    return 0;
}
