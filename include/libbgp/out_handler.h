#ifndef LIBBGP_OUT_HANDLER_H
#define LIBBGP_OUT_HANDLER_H

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

#include "libbgp/types.h"

typedef ssize_t (*libbgp_io_send_fn)(void *ctx, const uint8_t *buf, size_t len);
typedef ssize_t (*libbgp_io_recv_fn)(void *ctx, uint8_t *buf, size_t len);

typedef struct libbgp_io_ops {
    libbgp_io_send_fn send_fn;
    libbgp_io_recv_fn recv_fn;
    void *ctx;
} libbgp_io_ops_t;

struct libbgp_out_handler {
    void *impl;
};

LIBBGP_API libbgp_err_t libbgp_out_handler_init(libbgp_out_handler_t *handler);
LIBBGP_API void libbgp_out_handler_destroy(libbgp_out_handler_t *handler);
LIBBGP_API void libbgp_out_handler_set_ops(libbgp_out_handler_t *handler, const libbgp_io_ops_t *ops);
LIBBGP_API void libbgp_out_handler_set_fd(libbgp_out_handler_t *handler, int fd);
LIBBGP_API libbgp_err_t libbgp_out_handler_send(libbgp_out_handler_t *handler, const uint8_t *buf, size_t len, size_t *sent);
LIBBGP_API libbgp_err_t libbgp_out_handler_recv(libbgp_out_handler_t *handler, uint8_t *buf, size_t len, size_t *received);

#endif
