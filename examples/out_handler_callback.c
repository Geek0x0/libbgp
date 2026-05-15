#include <libbgp/libbgp.h>

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

typedef struct capture_ctx {
    uint8_t bytes[128];
    size_t len;
    unsigned int calls;
} capture_ctx_t;

static libbgp_io_result_t capture_send(void *ctx, const uint8_t *buf, size_t len)
{
    capture_ctx_t *capture = (capture_ctx_t *)ctx;

    if (capture == NULL || buf == NULL || capture->len + len > sizeof(capture->bytes)) {
        return -1;
    }
    memcpy(capture->bytes + capture->len, buf, len);
    capture->len += len;
    capture->calls++;
    return (libbgp_io_result_t)len;
}

int main(void)
{
    libbgp_packet_t pkt;
    libbgp_out_handler_t out;
    libbgp_io_ops_t ops;
    capture_ctx_t capture;
    uint8_t wire[64];
    size_t wire_len = 0u;
    size_t sent = 0u;
    libbgp_err_t err;

    memset(&capture, 0, sizeof(capture));
    ops.send_fn = capture_send;
    ops.recv_fn = NULL;
    ops.ctx = &capture;

    libbgp_packet_init(&pkt);
    pkt.type = LIBBGP_PACKET_KEEPALIVE;
    err = libbgp_packet_write(&pkt, wire, sizeof(wire), &wire_len);
    if (err != LIBBGP_OK) {
        fprintf(stderr, "packet write failed: %s\n", libbgp_strerror(err));
        libbgp_packet_destroy(&pkt);
        return 1;
    }

    err = libbgp_out_handler_init(&out);
    if (err != LIBBGP_OK) {
        fprintf(stderr, "out handler init failed: %s\n", libbgp_strerror(err));
        libbgp_packet_destroy(&pkt);
        return 1;
    }
    libbgp_out_handler_set_ops(&out, &ops);

    err = libbgp_out_handler_send(&out, wire, wire_len, &sent);
    if (err != LIBBGP_OK) {
        fprintf(stderr, "send failed: %s\n", libbgp_strerror(err));
        libbgp_out_handler_destroy(&out);
        libbgp_packet_destroy(&pkt);
        return 1;
    }

    printf("callback calls=%u sent=%zu captured=%zu first_type=%u\n",
        capture.calls,
        sent,
        capture.len,
        capture.len >= LIBBGP_BGP_HEADER_LEN ? (unsigned int)capture.bytes[18] : 0u);

    libbgp_out_handler_destroy(&out);
    libbgp_packet_destroy(&pkt);
    return 0;
}
