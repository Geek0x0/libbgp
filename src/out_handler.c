#include "libbgp/out_handler.h"

#include <stdbool.h>
#include <sys/socket.h>
#include <unistd.h>

#include "internal.h"

#ifdef BGP_THREADSAFE
#include <pthread.h>

static pthread_mutex_t out_handler_acquire_lock = PTHREAD_MUTEX_INITIALIZER;

#define out_handler_acquire_global() pthread_mutex_lock(&out_handler_acquire_lock)
#define out_handler_release_global() pthread_mutex_unlock(&out_handler_acquire_lock)
#else
#define out_handler_acquire_global() ((void)0)
#define out_handler_release_global() ((void)0)
#endif

typedef struct out_handler_impl {
    int fd;
    bool has_ops;
    libbgp_io_ops_t ops;
    bgp_lock_t lock;
} out_handler_impl_t;

static out_handler_impl_t *out_handler_impl_get(const libbgp_out_handler_t *handler)
{
    return handler == NULL ? NULL : (out_handler_impl_t *)handler->impl;
}

static out_handler_impl_t *out_handler_impl_lock(libbgp_out_handler_t *handler)
{
    out_handler_impl_t *impl;

    out_handler_acquire_global();
    impl = out_handler_impl_get(handler);
    if (impl != NULL) {
        bgp_lock(&impl->lock);
    }
    out_handler_release_global();
    return impl;
}

libbgp_err_t libbgp_out_handler_init(libbgp_out_handler_t *handler)
{
    out_handler_impl_t *impl;

    if (handler == NULL) {
        return LIBBGP_ERR_INVALID;
    }
    handler->impl = NULL;
    impl = (out_handler_impl_t *)bgp_calloc(1u, sizeof(*impl));
    if (impl == NULL) {
        return LIBBGP_ERR_NOMEM;
    }
    impl->fd = -1;
    bgp_lock_init(&impl->lock);
    out_handler_acquire_global();
    handler->impl = impl;
    out_handler_release_global();
    return LIBBGP_OK;
}

void libbgp_out_handler_destroy(libbgp_out_handler_t *handler)
{
    out_handler_impl_t *impl;

    out_handler_acquire_global();
    impl = out_handler_impl_get(handler);
    if (impl == NULL) {
        out_handler_release_global();
        return;
    }
    bgp_lock(&impl->lock);
    handler->impl = NULL;
    out_handler_release_global();
    bgp_unlock(&impl->lock);
    bgp_lock_destroy(&impl->lock);
    bgp_free(impl);
}

void libbgp_out_handler_set_ops(libbgp_out_handler_t *handler, const libbgp_io_ops_t *ops)
{
    out_handler_impl_t *impl = out_handler_impl_lock(handler);

    if (impl == NULL) {
        return;
    }
    if (ops == NULL) {
        impl->has_ops = false;
        impl->ops.send_fn = NULL;
        impl->ops.recv_fn = NULL;
        impl->ops.ctx = NULL;
    } else {
        impl->ops = *ops;
        impl->has_ops = true;
    }
    bgp_unlock(&impl->lock);
}

void libbgp_out_handler_set_fd(libbgp_out_handler_t *handler, int fd)
{
    out_handler_impl_t *impl = out_handler_impl_lock(handler);

    if (impl == NULL) {
        return;
    }
    impl->fd = fd;
    impl->has_ops = false;
    impl->ops.send_fn = NULL;
    impl->ops.recv_fn = NULL;
    impl->ops.ctx = NULL;
    bgp_unlock(&impl->lock);
}

libbgp_err_t libbgp_out_handler_send(libbgp_out_handler_t *handler, const uint8_t *buf, size_t len, size_t *sent)
{
    out_handler_impl_t *impl;
    ssize_t ret;

    if (len == 0u) {
        if (sent != NULL) {
            *sent = 0u;
        }
        return LIBBGP_OK;
    }
    if (buf == NULL) {
        return LIBBGP_ERR_BAD_LEN;
    }
    impl = out_handler_impl_lock(handler);
    if (impl == NULL) {
        return LIBBGP_ERR_INVALID;
    }
    if (impl->has_ops) {
        if (impl->ops.send_fn == NULL) {
            bgp_unlock(&impl->lock);
            return LIBBGP_ERR_INVALID;
        }
        ret = impl->ops.send_fn(impl->ops.ctx, buf, len);
    } else {
        if (impl->fd < 0) {
            bgp_unlock(&impl->lock);
            return LIBBGP_ERR_INVALID;
        }
        ret = send(impl->fd, buf, len, 0);
    }
    if (ret < 0) {
        bgp_unlock(&impl->lock);
        return LIBBGP_ERR_WRITE;
    }
    if (sent != NULL) {
        *sent = (size_t)ret;
    }
    bgp_unlock(&impl->lock);
    return LIBBGP_OK;
}

libbgp_err_t libbgp_out_handler_recv(libbgp_out_handler_t *handler, uint8_t *buf, size_t len, size_t *received)
{
    out_handler_impl_t *impl;
    ssize_t ret;

    if (len == 0u) {
        if (received != NULL) {
            *received = 0u;
        }
        return LIBBGP_OK;
    }
    if (buf == NULL) {
        return LIBBGP_ERR_BAD_LEN;
    }
    impl = out_handler_impl_lock(handler);
    if (impl == NULL) {
        return LIBBGP_ERR_INVALID;
    }
    if (impl->has_ops) {
        if (impl->ops.recv_fn == NULL) {
            bgp_unlock(&impl->lock);
            return LIBBGP_ERR_INVALID;
        }
        ret = impl->ops.recv_fn(impl->ops.ctx, buf, len);
    } else {
        if (impl->fd < 0) {
            bgp_unlock(&impl->lock);
            return LIBBGP_ERR_INVALID;
        }
        ret = recv(impl->fd, buf, len, 0);
    }
    if (ret < 0) {
        bgp_unlock(&impl->lock);
        return LIBBGP_ERR_PARSE;
    }
    if (received != NULL) {
        *received = (size_t)ret;
    }
    bgp_unlock(&impl->lock);
    return LIBBGP_OK;
}
