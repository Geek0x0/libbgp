#include <libbgp/libbgp.h>

#include <stdio.h>
#include <string.h>

static const char *packet_type_name(libbgp_packet_type_t type)
{
    switch (type) {
    case LIBBGP_PACKET_OPEN:
        return "OPEN";
    case LIBBGP_PACKET_UPDATE:
        return "UPDATE";
    case LIBBGP_PACKET_NOTIFICATION:
        return "NOTIFICATION";
    case LIBBGP_PACKET_KEEPALIVE:
        return "KEEPALIVE";
    case LIBBGP_PACKET_UNKNOWN:
    default:
        return "UNKNOWN";
    }
}

int main(void)
{
    static const uint8_t keepalive[19] = {
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0x00, 0x13, 0x04
    };
    uint8_t out[64];
    libbgp_packet_t pkt;
    size_t consumed = 0u;
    size_t out_len = 0u;
    libbgp_err_t err;

    libbgp_packet_init(&pkt);
    err = libbgp_packet_parse(&pkt, keepalive, sizeof(keepalive), &consumed);
    if (err != LIBBGP_OK) {
        fprintf(stderr, "parse failed: %s\n", libbgp_strerror(err));
        libbgp_packet_destroy(&pkt);
        return 1;
    }

    err = libbgp_packet_write(&pkt, out, sizeof(out), &out_len);
    if (err != LIBBGP_OK) {
        fprintf(stderr, "write failed: %s\n", libbgp_strerror(err));
        libbgp_packet_destroy(&pkt);
        return 1;
    }

    printf("parsed %s packet, consumed=%zu, encoded=%zu\n",
        packet_type_name(pkt.type),
        consumed,
        out_len);
    printf("roundtrip=%s\n",
        out_len == sizeof(keepalive) && memcmp(out, keepalive, sizeof(keepalive)) == 0 ?
            "match" :
            "different");

    libbgp_packet_destroy(&pkt);
    return 0;
}
