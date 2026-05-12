#include "test_main.h"

#include "libbgp/out_handler.h"
#include "libbgp/types.h"

typedef struct io_ctx {
    const uint8_t *expected_send;
    size_t send_len;
    uint8_t *recv_data;
    size_t recv_len;
    int send_called;
    int recv_called;
} io_ctx_t;

typedef struct reentrant_ctx {
    libbgp_out_handler_t *handler;
    int called;
} reentrant_ctx_t;

typedef struct short_io_ctx {
    void *expected_ctx;
    size_t return_len;
    int called;
} short_io_ctx_t;

static libbgp_io_result_t test_send(void *ctx, const uint8_t *buf, size_t len)
{
    io_ctx_t *io = (io_ctx_t *)ctx;

    io->send_called++;
    LIBBGP_ASSERT_EQ_U64((uintptr_t)io->expected_send, (uintptr_t)buf);
    LIBBGP_ASSERT_EQ_U64(io->send_len, len);
    return (libbgp_io_result_t)len;
}

static libbgp_io_result_t test_recv(void *ctx, uint8_t *buf, size_t len)
{
    io_ctx_t *io = (io_ctx_t *)ctx;
    size_t copy_len = io->recv_len < len ? io->recv_len : len;

    io->recv_called++;
    memcpy(buf, io->recv_data, copy_len);
    return (libbgp_io_result_t)copy_len;
}

static libbgp_io_result_t counting_send(void *ctx, const uint8_t *buf, size_t len)
{
    int *send_called = (int *)ctx;

    (void)buf;
    if (send_called != NULL) {
        (*send_called)++;
    }
    return (libbgp_io_result_t)len;
}

static libbgp_io_result_t negative_send(void *ctx, const uint8_t *buf, size_t len)
{
    (void)ctx;
    (void)buf;
    (void)len;
    return -1;
}

static libbgp_io_result_t counting_recv(void *ctx, uint8_t *buf, size_t len)
{
    int *recv_called = (int *)ctx;

    (void)buf;
    if (recv_called != NULL) {
        (*recv_called)++;
    }
    return (libbgp_io_result_t)len;
}

static libbgp_io_result_t negative_recv(void *ctx, uint8_t *buf, size_t len)
{
    (void)ctx;
    (void)buf;
    (void)len;
    return -1;
}

static libbgp_io_result_t reentrant_send(void *ctx, const uint8_t *buf, size_t len)
{
    reentrant_ctx_t *reentrant = (reentrant_ctx_t *)ctx;

    (void)buf;
    reentrant->called++;
    libbgp_out_handler_set_fd(reentrant->handler, -1);
    return (libbgp_io_result_t)len;
}

static libbgp_io_result_t short_send(void *ctx, const uint8_t *buf, size_t len)
{
    short_io_ctx_t *short_io = (short_io_ctx_t *)ctx;

    (void)buf;
    LIBBGP_ASSERT(ctx == short_io->expected_ctx);
    LIBBGP_ASSERT(short_io->return_len < len);
    short_io->called++;
    return (libbgp_io_result_t)short_io->return_len;
}

static libbgp_io_result_t short_recv(void *ctx, uint8_t *buf, size_t len)
{
    short_io_ctx_t *short_io = (short_io_ctx_t *)ctx;

    memset(buf, 0xabu, short_io->return_len);
    LIBBGP_ASSERT(ctx == short_io->expected_ctx);
    LIBBGP_ASSERT(short_io->return_len < len);
    short_io->called++;
    return (libbgp_io_result_t)short_io->return_len;
}

LIBBGP_TEST(out_handler_custom_callbacks)
{
    const uint8_t send_buf[] = { 1u, 2u, 3u };
    uint8_t recv_src[] = { 4u, 5u };
    uint8_t recv_buf[4] = { 0u };
    size_t count = 99u;
    io_ctx_t ctx;
    libbgp_io_ops_t ops;
    libbgp_out_handler_t handler;

    memset(&ctx, 0, sizeof(ctx));
    ctx.expected_send = send_buf;
    ctx.send_len = sizeof(send_buf);
    ctx.recv_data = recv_src;
    ctx.recv_len = sizeof(recv_src);
    ops.send_fn = test_send;
    ops.recv_fn = test_recv;
    ops.ctx = &ctx;

    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_out_handler_init(&handler));
    libbgp_out_handler_set_ops(&handler, &ops);
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_out_handler_send(&handler, send_buf, sizeof(send_buf), &count));
    LIBBGP_ASSERT_EQ_U64(sizeof(send_buf), count);
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_out_handler_recv(&handler, recv_buf, sizeof(recv_buf), &count));
    LIBBGP_ASSERT_EQ_U64(sizeof(recv_src), count);
    LIBBGP_ASSERT_BYTES_EQ(recv_src, recv_buf, sizeof(recv_src));
    LIBBGP_ASSERT_EQ_I64(1, ctx.send_called);
    LIBBGP_ASSERT_EQ_I64(1, ctx.recv_called);
    libbgp_out_handler_destroy(&handler);
}

LIBBGP_TEST(out_handler_set_ops_null_clears_custom_callbacks)
{
    const uint8_t send_buf[] = { 1u, 2u, 3u };
    uint8_t recv_src[] = { 4u, 5u };
    uint8_t recv_buf[4] = { 0u };
    size_t count = 99u;
    io_ctx_t ctx;
    libbgp_io_ops_t ops;
    libbgp_out_handler_t handler;

    memset(&ctx, 0, sizeof(ctx));
    ctx.expected_send = send_buf;
    ctx.send_len = sizeof(send_buf);
    ctx.recv_data = recv_src;
    ctx.recv_len = sizeof(recv_src);
    ops.send_fn = test_send;
    ops.recv_fn = test_recv;
    ops.ctx = &ctx;

    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_out_handler_init(&handler));
    libbgp_out_handler_set_ops(&handler, &ops);
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_out_handler_send(&handler, send_buf, sizeof(send_buf), &count));
    LIBBGP_ASSERT_EQ_U64(sizeof(send_buf), count);
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_out_handler_recv(&handler, recv_buf, sizeof(recv_buf), &count));
    LIBBGP_ASSERT_EQ_U64(sizeof(recv_src), count);
    LIBBGP_ASSERT_BYTES_EQ(recv_src, recv_buf, sizeof(recv_src));
    LIBBGP_ASSERT_EQ_I64(1, ctx.send_called);
    LIBBGP_ASSERT_EQ_I64(1, ctx.recv_called);

    libbgp_out_handler_set_ops(&handler, NULL);
    count = 99u;
    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_INVALID, libbgp_out_handler_send(&handler, send_buf, sizeof(send_buf), &count));
    LIBBGP_ASSERT_EQ_U64(99u, count);
    count = 99u;
    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_INVALID, libbgp_out_handler_recv(&handler, recv_buf, sizeof(recv_buf), &count));
    LIBBGP_ASSERT_EQ_U64(99u, count);
    LIBBGP_ASSERT_EQ_I64(1, ctx.send_called);
    LIBBGP_ASSERT_EQ_I64(1, ctx.recv_called);
    libbgp_out_handler_destroy(&handler);
}

LIBBGP_TEST(out_handler_zero_length_succeeds)
{
    libbgp_out_handler_t handler;
    size_t count = 99u;
    uint8_t byte = 0u;

    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_out_handler_init(&handler));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_out_handler_send(&handler, &byte, 0u, &count));
    LIBBGP_ASSERT_EQ_U64(0u, count);
    count = 99u;
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_out_handler_recv(&handler, &byte, 0u, &count));
    LIBBGP_ASSERT_EQ_U64(0u, count);
    libbgp_out_handler_destroy(&handler);
}

LIBBGP_TEST(out_handler_zero_length_allows_null_buffers)
{
    libbgp_out_handler_t handler;
    size_t count = 99u;

    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_out_handler_init(&handler));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_out_handler_send(&handler, NULL, 0u, &count));
    LIBBGP_ASSERT_EQ_U64(0u, count);
    count = 99u;
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_out_handler_recv(&handler, NULL, 0u, &count));
    LIBBGP_ASSERT_EQ_U64(0u, count);
    libbgp_out_handler_destroy(&handler);
}

LIBBGP_TEST(out_handler_short_callbacks_report_short_counts)
{
    const uint8_t send_buf[] = { 1u, 2u, 3u, 4u };
    uint8_t recv_buf[4] = { 0u };
    short_io_ctx_t ctx;
    libbgp_io_ops_t ops;
    libbgp_out_handler_t handler;
    size_t count = 99u;

    ctx.expected_ctx = &ctx;
    ctx.return_len = 2u;
    ctx.called = 0;
    ops.send_fn = short_send;
    ops.recv_fn = short_recv;
    ops.ctx = &ctx;

    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_out_handler_init(&handler));
    libbgp_out_handler_set_ops(&handler, &ops);
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_out_handler_send(&handler, send_buf, sizeof(send_buf), &count));
    LIBBGP_ASSERT_EQ_U64(2u, count);
    LIBBGP_ASSERT_EQ_I64(1, ctx.called);
    count = 99u;
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_out_handler_recv(&handler, recv_buf, sizeof(recv_buf), &count));
    LIBBGP_ASSERT_EQ_U64(2u, count);
    LIBBGP_ASSERT_EQ_I64(2, ctx.called);
    LIBBGP_ASSERT_EQ_U64(0xabu, recv_buf[0]);
    LIBBGP_ASSERT_EQ_U64(0xabu, recv_buf[1]);
    LIBBGP_ASSERT_EQ_U64(0u, recv_buf[2]);
    LIBBGP_ASSERT_EQ_U64(0u, recv_buf[3]);
    libbgp_out_handler_destroy(&handler);
}

LIBBGP_TEST(out_handler_rejects_null_buffers_for_nonzero_io)
{
    int send_called = 0;
    int recv_called = 0;
    libbgp_io_ops_t send_ops;
    libbgp_io_ops_t recv_ops;
    libbgp_out_handler_t handler;
    size_t count = 99u;

    send_ops.send_fn = counting_send;
    send_ops.recv_fn = NULL;
    send_ops.ctx = &send_called;
    recv_ops.send_fn = NULL;
    recv_ops.recv_fn = counting_recv;
    recv_ops.ctx = &recv_called;

    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_out_handler_init(&handler));
    libbgp_out_handler_set_ops(&handler, &send_ops);
    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_BAD_LEN, libbgp_out_handler_send(&handler, NULL, 1u, &count));
    LIBBGP_ASSERT_EQ_U64(99u, count);
    LIBBGP_ASSERT_EQ_I64(0, send_called);
    count = 99u;
    libbgp_out_handler_set_ops(&handler, &recv_ops);
    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_BAD_LEN, libbgp_out_handler_recv(&handler, NULL, 1u, &count));
    LIBBGP_ASSERT_EQ_U64(99u, count);
    LIBBGP_ASSERT_EQ_I64(0, recv_called);
    libbgp_out_handler_destroy(&handler);
}

LIBBGP_TEST(out_handler_unconfigured_is_invalid)
{
    libbgp_out_handler_t handler;
    size_t count = 99u;
    uint8_t byte = 0u;

    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_out_handler_init(&handler));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_INVALID, libbgp_out_handler_send(&handler, &byte, 1u, &count));
    LIBBGP_ASSERT_EQ_U64(99u, count);
    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_INVALID, libbgp_out_handler_recv(&handler, &byte, 1u, &count));
    LIBBGP_ASSERT_EQ_U64(99u, count);
    libbgp_out_handler_destroy(&handler);
}

LIBBGP_TEST(out_handler_negative_callbacks_map_errors)
{
    libbgp_io_ops_t ops;
    libbgp_out_handler_t handler;
    size_t count = 99u;
    uint8_t byte = 0u;

    ops.send_fn = negative_send;
    ops.recv_fn = negative_recv;
    ops.ctx = NULL;

    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_out_handler_init(&handler));
    libbgp_out_handler_set_ops(&handler, &ops);
    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_WRITE, libbgp_out_handler_send(&handler, &byte, 1u, &count));
    LIBBGP_ASSERT_EQ_U64(99u, count);
    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_PARSE, libbgp_out_handler_recv(&handler, &byte, 1u, &count));
    LIBBGP_ASSERT_EQ_U64(99u, count);
    libbgp_out_handler_destroy(&handler);
}

LIBBGP_TEST(out_handler_set_fd_resets_custom_ops)
{
    libbgp_io_ops_t ops;
    libbgp_out_handler_t handler;
    size_t count = 99u;
    uint8_t byte = 0u;

    ops.send_fn = negative_send;
    ops.recv_fn = negative_recv;
    ops.ctx = NULL;

    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_out_handler_init(&handler));
    libbgp_out_handler_set_ops(&handler, &ops);
    libbgp_out_handler_set_fd(&handler, -1);
    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_INVALID, libbgp_out_handler_send(&handler, &byte, 1u, &count));
    libbgp_out_handler_destroy(&handler);
}

LIBBGP_TEST(out_handler_send_callback_can_reenter_handler)
{
    libbgp_io_ops_t ops;
    libbgp_out_handler_t handler;
    reentrant_ctx_t ctx;
    size_t count = 99u;
    uint8_t byte = 0u;

    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_out_handler_init(&handler));
    ctx.handler = &handler;
    ctx.called = 0;
    ops.send_fn = reentrant_send;
    ops.recv_fn = NULL;
    ops.ctx = &ctx;

    libbgp_out_handler_set_ops(&handler, &ops);
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_out_handler_send(&handler, &byte, 1u, &count));
    LIBBGP_ASSERT_EQ_U64(1u, count);
    LIBBGP_ASSERT_EQ_I64(1, ctx.called);
    count = 99u;
    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_INVALID, libbgp_out_handler_send(&handler, &byte, 1u, &count));
    LIBBGP_ASSERT_EQ_U64(99u, count);
    libbgp_out_handler_destroy(&handler);
}

int main(void)
{
    const libbgp_test_case_t tests[] = {
        { "out_handler_custom_callbacks", out_handler_custom_callbacks },
        { "out_handler_set_ops_null_clears_custom_callbacks", out_handler_set_ops_null_clears_custom_callbacks },
        { "out_handler_zero_length_succeeds", out_handler_zero_length_succeeds },
        { "out_handler_zero_length_allows_null_buffers", out_handler_zero_length_allows_null_buffers },
        { "out_handler_short_callbacks_report_short_counts", out_handler_short_callbacks_report_short_counts },
        { "out_handler_rejects_null_buffers_for_nonzero_io", out_handler_rejects_null_buffers_for_nonzero_io },
        { "out_handler_unconfigured_is_invalid", out_handler_unconfigured_is_invalid },
        { "out_handler_negative_callbacks_map_errors", out_handler_negative_callbacks_map_errors },
        { "out_handler_set_fd_resets_custom_ops", out_handler_set_fd_resets_custom_ops },
        { "out_handler_send_callback_can_reenter_handler", out_handler_send_callback_can_reenter_handler }
    };

    return libbgp_run_tests("out_handler", tests, LIBBGP_ARRAY_LEN(tests));
}
