#include "libbgp/sink.h"

#include <stdbool.h>
#include <string.h>

#include "internal.h"

#ifdef BGP_THREADSAFE
#include <pthread.h>

static pthread_mutex_t sink_acquire_lock = PTHREAD_MUTEX_INITIALIZER;

#define sink_acquire_global() pthread_mutex_lock(&sink_acquire_lock)
#define sink_release_global() pthread_mutex_unlock(&sink_acquire_lock)
#else
#define sink_acquire_global() ((void)0)
#define sink_release_global() ((void)0)
#endif

typedef struct sink_impl {
    uint8_t *buf;
    size_t buf_len;
    size_t buf_cap;
    libbgp_packet_t *packets;
    size_t packet_count;
    size_t packet_cap;
    bool use_4b_asn;
    bgp_lock_t lock;
} sink_impl_t;

static sink_impl_t *sink_impl_get(const libbgp_sink_t *sink)
{
    return sink == NULL ? NULL : (sink_impl_t *)sink->impl;
}

static sink_impl_t *sink_impl_lock(libbgp_sink_t *sink)
{
    sink_impl_t *impl;

    sink_acquire_global();
    impl = sink_impl_get(sink);
    if (impl != NULL) {
        bgp_lock(&impl->lock);
    }
    sink_release_global();
    return impl;
}

static sink_impl_t *sink_impl_lock_const(const libbgp_sink_t *sink)
{
    return sink_impl_lock((libbgp_sink_t *)sink);
}

static bool sink_reserve_buf(sink_impl_t *impl, size_t needed)
{
    uint8_t *buf;
    size_t new_cap;

    if (needed <= impl->buf_cap) {
        return true;
    }
    new_cap = impl->buf_cap == 0u ? LIBBGP_BGP_HEADER_LEN : impl->buf_cap * 2u;
    while (new_cap < needed) {
        if (new_cap > SIZE_MAX / 2u) {
            return false;
        }
        new_cap *= 2u;
    }
    buf = (uint8_t *)bgp_realloc(impl->buf, new_cap);
    if (buf == NULL) {
        return false;
    }
    impl->buf = buf;
    impl->buf_cap = new_cap;
    return true;
}

static bool sink_reserve_packets(sink_impl_t *impl, size_t needed)
{
    libbgp_packet_t *packets;
    size_t new_cap;
    size_t i;

    if (needed <= impl->packet_cap) {
        return true;
    }
    new_cap = impl->packet_cap == 0u ? 4u : impl->packet_cap * 2u;
    while (new_cap < needed) {
        if (new_cap > SIZE_MAX / 2u) {
            return false;
        }
        new_cap *= 2u;
    }
    if (new_cap > SIZE_MAX / sizeof(*impl->packets)) {
        return false;
    }
    packets = (libbgp_packet_t *)bgp_realloc(impl->packets, new_cap * sizeof(*impl->packets));
    if (packets == NULL) {
        return false;
    }
    for (i = impl->packet_cap; i < new_cap; i++) {
        libbgp_packet_init(&packets[i]);
    }
    impl->packets = packets;
    impl->packet_cap = new_cap;
    return true;
}

static bool sink_marker_valid(const uint8_t *buf)
{
    size_t i;

    for (i = 0u; i < LIBBGP_BGP_MARKER_LEN; i++) {
        if (buf[i] != 0xffu) {
            return false;
        }
    }
    return true;
}

static void sink_drop_buffer_prefix(sink_impl_t *impl, size_t len)
{
    if (len >= impl->buf_len) {
        impl->buf_len = 0u;
        return;
    }
    memmove(impl->buf, impl->buf + len, impl->buf_len - len);
    impl->buf_len -= len;
}

static void sink_clear_locked(sink_impl_t *impl)
{
    size_t i;

    for (i = 0u; i < impl->packet_count; i++) {
        libbgp_packet_destroy(&impl->packets[i]);
    }
    impl->packet_count = 0u;
    impl->buf_len = 0u;
}

static libbgp_err_t sink_process_locked(sink_impl_t *impl)
{
    libbgp_err_t err;
    size_t consumed;
    uint16_t wire_len;

    while (impl->buf_len >= LIBBGP_BGP_HEADER_LEN) {
        libbgp_packet_t pkt;

        if (!sink_marker_valid(impl->buf)) {
            impl->buf_len = 0u;
            return LIBBGP_ERR_BAD_LEN;
        }
        wire_len = bgp_get_be16(impl->buf + 16u);
        if (wire_len < LIBBGP_BGP_MIN_PACKET_LEN || wire_len > LIBBGP_BGP_MAX_PACKET_LEN) {
            impl->buf_len = 0u;
            return LIBBGP_ERR_BAD_LEN;
        }
        if (impl->buf_len < (size_t)wire_len) {
            return LIBBGP_OK;
        }
        if (!sink_reserve_packets(impl, impl->packet_count + 1u)) {
            return LIBBGP_ERR_NOMEM;
        }
        libbgp_packet_init(&pkt);
        consumed = 0u;
        err = libbgp_packet_parse_as4(&pkt, impl->buf, (size_t)wire_len, impl->use_4b_asn, &consumed);
        if (err != LIBBGP_OK) {
            libbgp_packet_destroy(&pkt);
            sink_drop_buffer_prefix(impl, (size_t)wire_len);
            return err;
        }
        if (consumed != (size_t)wire_len) {
            libbgp_packet_destroy(&pkt);
            sink_drop_buffer_prefix(impl, (size_t)wire_len);
            return LIBBGP_ERR_BAD_LEN;
        }
        libbgp_packet_destroy(&impl->packets[impl->packet_count]);
        impl->packets[impl->packet_count] = pkt;
        impl->packet_count++;
        sink_drop_buffer_prefix(impl, (size_t)wire_len);
    }
    return LIBBGP_OK;
}

libbgp_err_t libbgp_sink_init_as4(libbgp_sink_t *sink, bool use_4b_asn)
{
    sink_impl_t *impl;

    if (sink == NULL) {
        return LIBBGP_ERR_INVALID;
    }
    sink->impl = NULL;
    impl = (sink_impl_t *)bgp_calloc(1u, sizeof(*impl));
    if (impl == NULL) {
        return LIBBGP_ERR_NOMEM;
    }
    impl->use_4b_asn = use_4b_asn;
    bgp_lock_init(&impl->lock);
    sink_acquire_global();
    sink->impl = impl;
    sink_release_global();
    return LIBBGP_OK;
}

libbgp_err_t libbgp_sink_init(libbgp_sink_t *sink)
{
    return libbgp_sink_init_as4(sink, false);
}

void libbgp_sink_destroy(libbgp_sink_t *sink)
{
    sink_impl_t *impl;
    uint8_t *buf;
    libbgp_packet_t *packets;

    sink_acquire_global();
    impl = sink_impl_get(sink);
    if (impl == NULL) {
        sink_release_global();
        return;
    }
    bgp_lock(&impl->lock);
    sink->impl = NULL;
    sink_release_global();

    sink_clear_locked(impl);
    buf = impl->buf;
    packets = impl->packets;
    impl->buf = NULL;
    impl->packets = NULL;
    impl->buf_cap = 0u;
    impl->packet_cap = 0u;
    bgp_unlock(&impl->lock);
    bgp_lock_destroy(&impl->lock);
    bgp_free(buf);
    bgp_free(packets);
    bgp_free(impl);
}

libbgp_err_t libbgp_sink_feed(libbgp_sink_t *sink, const uint8_t *data, size_t len)
{
    sink_impl_t *impl;
    libbgp_err_t err;

    if (len == 0u) {
        return LIBBGP_OK;
    }
    if (data == NULL) {
        return LIBBGP_ERR_BAD_LEN;
    }
    impl = sink_impl_lock(sink);
    if (impl == NULL) {
        return LIBBGP_ERR_INVALID;
    }
    if (len > SIZE_MAX - impl->buf_len || !sink_reserve_buf(impl, impl->buf_len + len)) {
        bgp_unlock(&impl->lock);
        return LIBBGP_ERR_NOMEM;
    }
    memcpy(impl->buf + impl->buf_len, data, len);
    impl->buf_len += len;
    err = sink_process_locked(impl);
    bgp_unlock(&impl->lock);
    return err;
}

size_t libbgp_sink_packet_count(const libbgp_sink_t *sink)
{
    sink_impl_t *impl = sink_impl_lock_const(sink);
    size_t count;

    if (impl == NULL) {
        return 0u;
    }
    count = impl->packet_count;
    bgp_unlock(&impl->lock);
    return count;
}

libbgp_err_t libbgp_sink_pop(libbgp_sink_t *sink, libbgp_packet_t *out_packet)
{
    sink_impl_t *impl;
    size_t remaining;

    if (out_packet == NULL) {
        return LIBBGP_ERR_INVALID;
    }
    impl = sink_impl_lock(sink);
    if (impl == NULL) {
        return LIBBGP_ERR_INVALID;
    }
    if (impl->packet_count == 0u) {
        bgp_unlock(&impl->lock);
        return LIBBGP_ERR_NOT_FOUND;
    }
    *out_packet = impl->packets[0];
    memset(&impl->packets[0], 0, sizeof(impl->packets[0]));
    remaining = impl->packet_count - 1u;
    if (remaining != 0u) {
        memmove(&impl->packets[0], &impl->packets[1], remaining * sizeof(*impl->packets));
        memset(&impl->packets[remaining], 0, sizeof(*impl->packets));
    }
    impl->packet_count = remaining;
    bgp_unlock(&impl->lock);
    return LIBBGP_OK;
}

void libbgp_sink_clear(libbgp_sink_t *sink)
{
    sink_impl_t *impl = sink_impl_lock(sink);

    if (impl == NULL) {
        return;
    }
    sink_clear_locked(impl);
    bgp_unlock(&impl->lock);
}

size_t libbgp_sink_buffered_len(const libbgp_sink_t *sink)
{
    sink_impl_t *impl = sink_impl_lock_const(sink);
    size_t len;

    if (impl == NULL) {
        return 0u;
    }
    len = impl->buf_len;
    bgp_unlock(&impl->lock);
    return len;
}
