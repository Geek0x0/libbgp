#include <libbgp/libbgp.h>

#include <stdint.h>
#include <stdio.h>
#include <string.h>

static libbgp_prefix6_t p6_2001_db8(uint16_t subnet, uint8_t len)
{
    libbgp_prefix6_t prefix;
    uint8_t mask[16];
    size_t i;

    memset(&prefix, 0, sizeof(prefix));
    prefix.addr[0] = 0x20u;
    prefix.addr[1] = 0x01u;
    prefix.addr[2] = 0x0du;
    prefix.addr[3] = 0xb8u;
    prefix.addr[4] = (uint8_t)(subnet >> 8u);
    prefix.addr[5] = (uint8_t)subnet;
    prefix.len = len;
    libbgp_cidr6_to_mask(len, mask);
    for (i = 0u; i < sizeof(prefix.addr); i++) {
        prefix.addr[i] &= mask[i];
    }
    return prefix;
}

static void print_prefix6(const libbgp_prefix6_t *prefix)
{
    printf("%02x%02x:%02x%02x:%02x%02x::/%u",
        prefix->addr[0],
        prefix->addr[1],
        prefix->addr[2],
        prefix->addr[3],
        prefix->addr[4],
        prefix->addr[5],
        (unsigned int)prefix->len);
}

static libbgp_pattr_t *new_origin(uint8_t origin)
{
    libbgp_pattr_t *attr = libbgp_pattr_new(LIBBGP_PATTR_ORIGIN);

    if (attr != NULL) {
        attr->data.origin.origin = origin;
    }
    return attr;
}

static libbgp_pattr_t *new_as_path(uint32_t asn)
{
    libbgp_pattr_t *attr = libbgp_pattr_new(LIBBGP_PATTR_AS_PATH);
    libbgp_as_path_segment_t *segment;
    uint32_t *asns;

    if (attr == NULL) {
        return NULL;
    }
    segment = (libbgp_as_path_segment_t *)libbgp_calloc(1u, sizeof(*segment));
    asns = (uint32_t *)libbgp_calloc(1u, sizeof(*asns));
    if (segment == NULL || asns == NULL) {
        libbgp_free(segment);
        libbgp_free(asns);
        libbgp_pattr_unref(attr);
        return NULL;
    }
    asns[0] = asn;
    segment[0].type = 2u;
    segment[0].asn_count = 1u;
    segment[0].asns = asns;
    attr->data.as_path.segments = segment;
    attr->data.as_path.segment_count = 1u;
    return attr;
}

static libbgp_pattr_t *new_mp_reach6(const libbgp_prefix6_t *prefix, const uint8_t nexthop[16])
{
    libbgp_pattr_t *attr = libbgp_pattr_new(LIBBGP_PATTR_MP_REACH_IPV6);

    if (attr == NULL) {
        return NULL;
    }
    attr->data.mp_reach_ipv6.nlri =
        (libbgp_prefix6_t *)libbgp_calloc(1u, sizeof(*attr->data.mp_reach_ipv6.nlri));
    if (attr->data.mp_reach_ipv6.nlri == NULL) {
        libbgp_pattr_unref(attr);
        return NULL;
    }
    memcpy(attr->data.mp_reach_ipv6.nexthop, nexthop, 16u);
    attr->data.mp_reach_ipv6.nexthop_len = 16u;
    attr->data.mp_reach_ipv6.nlri[0] = *prefix;
    attr->data.mp_reach_ipv6.nlri_count = 1u;
    return attr;
}

static libbgp_err_t add_attr(libbgp_update_msg_t *update, libbgp_pattr_t *attr)
{
    libbgp_err_t err;

    if (attr == NULL) {
        return LIBBGP_ERR_NOMEM;
    }
    err = libbgp_update_add_attr(update, attr);
    libbgp_pattr_unref(attr);
    return err;
}

int main(void)
{
    static const uint8_t nexthop[16] = {
        0x20, 0x01, 0x0d, 0xb8, 0x00, 0xff, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01
    };
    libbgp_packet_t pkt;
    libbgp_packet_t parsed;
    libbgp_prefix6_t prefix = p6_2001_db8(0x1234u, 48u);
    uint8_t wire[512];
    size_t wire_len = 0u;
    size_t consumed = 0u;
    libbgp_pattr_t *mp;
    libbgp_err_t err;

    libbgp_packet_init(&pkt);
    libbgp_packet_init(&parsed);
    pkt.type = LIBBGP_PACKET_UPDATE;
    libbgp_update_init(&pkt.data.update);

    err = add_attr(&pkt.data.update, new_origin(0u));
    if (err == LIBBGP_OK) {
        err = add_attr(&pkt.data.update, new_as_path(64512u));
    }
    if (err == LIBBGP_OK) {
        err = add_attr(&pkt.data.update, new_mp_reach6(&prefix, nexthop));
    }
    if (err == LIBBGP_OK) {
        err = libbgp_packet_write(&pkt, wire, sizeof(wire), &wire_len);
    }
    if (err == LIBBGP_OK) {
        err = libbgp_packet_parse(&parsed, wire, wire_len, &consumed);
    }
    if (err != LIBBGP_OK) {
        fprintf(stderr, "IPv6 MP UPDATE failed: %s\n", libbgp_strerror(err));
        libbgp_packet_destroy(&parsed);
        libbgp_packet_destroy(&pkt);
        return 1;
    }

    mp = libbgp_update_find_attr(&parsed.data.update, LIBBGP_PATTR_MP_REACH_IPV6);
    printf("encoded IPv6 UPDATE length=%zu consumed=%zu attrs=%zu\n",
        wire_len,
        consumed,
        parsed.data.update.attr_count);
    if (mp != NULL && mp->data.mp_reach_ipv6.nlri_count > 0u) {
        printf("mp_reach nlri=");
        print_prefix6(&mp->data.mp_reach_ipv6.nlri[0]);
        printf(" nexthop_len=%zu\n", mp->data.mp_reach_ipv6.nexthop_len);
    }

    libbgp_packet_destroy(&parsed);
    libbgp_packet_destroy(&pkt);
    return 0;
}
