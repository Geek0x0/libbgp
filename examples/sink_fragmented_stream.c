#include <libbgp/libbgp.h>

#include <stdio.h>

static const char *packet_type_name(libbgp_packet_type_t type)
{
    switch (type) {
    case LIBBGP_PACKET_KEEPALIVE:
        return "KEEPALIVE";
    case LIBBGP_PACKET_OPEN:
        return "OPEN";
    case LIBBGP_PACKET_UPDATE:
        return "UPDATE";
    case LIBBGP_PACKET_NOTIFICATION:
        return "NOTIFICATION";
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
    const size_t cuts[] = { 5u, 7u, 7u };
    libbgp_sink_t sink;
    libbgp_packet_t pkt;
    size_t offset = 0u;
    size_t i;
    libbgp_err_t err;

    err = libbgp_sink_init(&sink);
    if (err != LIBBGP_OK) {
        fprintf(stderr, "sink init failed: %s\n", libbgp_strerror(err));
        return 1;
    }

    for (i = 0u; i < sizeof(cuts) / sizeof(cuts[0]); i++) {
        err = libbgp_sink_feed(&sink, keepalive + offset, cuts[i]);
        if (err != LIBBGP_OK) {
            fprintf(stderr, "feed failed: %s\n", libbgp_strerror(err));
            libbgp_sink_destroy(&sink);
            return 1;
        }
        offset += cuts[i];
        printf("after fragment %zu: buffered=%zu queued=%zu\n",
            i + 1u,
            libbgp_sink_buffered_len(&sink),
            libbgp_sink_packet_count(&sink));
    }

    libbgp_packet_init(&pkt);
    err = libbgp_sink_pop(&sink, &pkt);
    if (err != LIBBGP_OK) {
        fprintf(stderr, "pop failed: %s\n", libbgp_strerror(err));
        libbgp_packet_destroy(&pkt);
        libbgp_sink_destroy(&sink);
        return 1;
    }

    printf("popped packet type=%s remaining=%zu\n",
        packet_type_name(pkt.type),
        libbgp_sink_packet_count(&sink));

    libbgp_packet_destroy(&pkt);
    libbgp_sink_destroy(&sink);
    return 0;
}
