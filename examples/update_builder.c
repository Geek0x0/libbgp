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

static libbgp_pattr_t *new_origin(uint8_t origin)
{
    libbgp_pattr_t *attr = libbgp_pattr_new(LIBBGP_PATTR_ORIGIN);

    if (attr != NULL) {
        attr->data.origin.origin = origin;
    }
    return attr;
}

static libbgp_pattr_t *new_next_hop(uint32_t next_hop)
{
    libbgp_pattr_t *attr = libbgp_pattr_new(LIBBGP_PATTR_NEXT_HOP);

    if (attr != NULL) {
        attr->data.next_hop.next_hop = next_hop;
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
    attr->data.as_path.is_4b = false;
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
    libbgp_packet_t pkt;
    libbgp_packet_t parsed;
    libbgp_prefix4_t nlri = p4(203u, 0u, 113u, 0u, 24u);
    uint8_t wire[4096];
    size_t wire_len = 0u;
    size_t consumed = 0u;
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
        err = add_attr(&pkt.data.update, new_next_hop(ip4(192u, 0u, 2u, 1u)));
    }
    if (err == LIBBGP_OK) {
        err = libbgp_update_add_nlri(&pkt.data.update, &nlri);
    }
    if (err != LIBBGP_OK) {
        fprintf(stderr, "build update failed: %s\n", libbgp_strerror(err));
        libbgp_packet_destroy(&parsed);
        libbgp_packet_destroy(&pkt);
        return 1;
    }

    err = libbgp_packet_write(&pkt, wire, sizeof(wire), &wire_len);
    if (err != LIBBGP_OK) {
        fprintf(stderr, "encode update failed: %s\n", libbgp_strerror(err));
        libbgp_packet_destroy(&parsed);
        libbgp_packet_destroy(&pkt);
        return 1;
    }

    err = libbgp_packet_parse(&parsed, wire, wire_len, &consumed);
    if (err != LIBBGP_OK) {
        fprintf(stderr, "parse encoded update failed: %s\n", libbgp_strerror(err));
        libbgp_packet_destroy(&parsed);
        libbgp_packet_destroy(&pkt);
        return 1;
    }

    printf("encoded UPDATE length=%zu, parsed bytes=%zu\n", wire_len, consumed);
    printf("attrs=%zu, nlri=%zu\n",
        parsed.data.update.attr_count,
        parsed.data.update.nlri_count);

    libbgp_packet_destroy(&parsed);
    libbgp_packet_destroy(&pkt);
    return 0;
}
