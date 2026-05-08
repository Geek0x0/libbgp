#ifndef LIBBGP_SINK_H
#define LIBBGP_SINK_H

#include <stddef.h>
#include <stdint.h>

#include "libbgp/types.h"
#include "libbgp/packet.h"

struct libbgp_sink {
    void *impl;
};

LIBBGP_API libbgp_err_t libbgp_sink_init(libbgp_sink_t *sink);
LIBBGP_API void libbgp_sink_destroy(libbgp_sink_t *sink);
LIBBGP_API libbgp_err_t libbgp_sink_feed(libbgp_sink_t *sink, const uint8_t *data, size_t len);
LIBBGP_API size_t libbgp_sink_packet_count(const libbgp_sink_t *sink);
/*
 * Moves the oldest queued packet into out_packet. The caller owns the moved
 * packet and must destroy it with libbgp_packet_destroy(). If out_packet
 * already owns a packet, destroy it before calling to avoid leaking it.
 */
LIBBGP_API libbgp_err_t libbgp_sink_pop(libbgp_sink_t *sink, libbgp_packet_t *out_packet);
LIBBGP_API void libbgp_sink_clear(libbgp_sink_t *sink);
LIBBGP_API size_t libbgp_sink_buffered_len(const libbgp_sink_t *sink);

#endif
