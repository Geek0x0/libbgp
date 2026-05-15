#include <libbgp/libbgp.h>

#include <stdbool.h>
#include <stdio.h>

static libbgp_err_t add_4byte_asn(libbgp_open_msg_t *open, uint32_t asn)
{
    libbgp_capability_t *cap = libbgp_capability_new(LIBBGP_CAP_4B_ASN);
    libbgp_err_t err;

    if (cap == NULL) {
        return LIBBGP_ERR_NOMEM;
    }
    cap->data.asn_4b.asn = asn;
    err = libbgp_open_add_capability(open, cap);
    libbgp_capability_unref(cap);
    return err;
}

static libbgp_err_t add_mp_bgp(libbgp_open_msg_t *open, uint16_t afi, uint8_t safi)
{
    libbgp_capability_t *cap = libbgp_capability_new(LIBBGP_CAP_MP_BGP);
    libbgp_err_t err;

    if (cap == NULL) {
        return LIBBGP_ERR_NOMEM;
    }
    cap->data.mp_bgp.afi = afi;
    cap->data.mp_bgp.safi = safi;
    err = libbgp_open_add_capability(open, cap);
    libbgp_capability_unref(cap);
    return err;
}

int main(void)
{
    libbgp_packet_t pkt;
    libbgp_packet_t parsed;
    uint8_t wire[256];
    size_t wire_len = 0u;
    size_t consumed = 0u;
    bool has_as4;
    bool has_mp6;
    libbgp_err_t err;

    libbgp_packet_init(&pkt);
    libbgp_packet_init(&parsed);
    pkt.type = LIBBGP_PACKET_OPEN;
    libbgp_open_init(&pkt.data.open);
    pkt.data.open.version = 4u;
    pkt.data.open.my_asn = (uint16_t)LIBBGP_AS_TRANS;
    pkt.data.open.hold_time = 90u;
    pkt.data.open.bgp_id = 0x0a000001u;

    err = add_4byte_asn(&pkt.data.open, 65551u);
    if (err == LIBBGP_OK) {
        err = add_mp_bgp(&pkt.data.open, LIBBGP_AFI_IPV6, LIBBGP_SAFI_UNICAST);
    }
    if (err != LIBBGP_OK) {
        fprintf(stderr, "add capability failed: %s\n", libbgp_strerror(err));
        libbgp_packet_destroy(&parsed);
        libbgp_packet_destroy(&pkt);
        return 1;
    }

    err = libbgp_packet_write(&pkt, wire, sizeof(wire), &wire_len);
    if (err == LIBBGP_OK) {
        err = libbgp_packet_parse(&parsed, wire, wire_len, &consumed);
    }
    if (err != LIBBGP_OK) {
        fprintf(stderr, "OPEN roundtrip failed: %s\n", libbgp_strerror(err));
        libbgp_packet_destroy(&parsed);
        libbgp_packet_destroy(&pkt);
        return 1;
    }

    has_as4 = libbgp_open_has_4b_asn(&parsed.data.open);
    has_mp6 = libbgp_open_has_mpbgp(&parsed.data.open, LIBBGP_AFI_IPV6, LIBBGP_SAFI_UNICAST);
    printf("encoded OPEN length=%zu consumed=%zu capabilities=%zu\n",
        wire_len,
        consumed,
        parsed.data.open.capability_count);
    printf("4byte_asn=%s value=%u mp_ipv6_unicast=%s\n",
        has_as4 ? "yes" : "no",
        has_as4 ? (unsigned int)libbgp_open_get_4b_asn(&parsed.data.open) : 0u,
        has_mp6 ? "yes" : "no");

    libbgp_packet_destroy(&parsed);
    libbgp_packet_destroy(&pkt);
    return 0;
}
