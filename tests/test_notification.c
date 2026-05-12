#include "test_main.h"

#include "fixtures/bgp_packets.h"

#include "libbgp/notification.h"
#include "libbgp/types.h"

LIBBGP_TEST(notification_parse_write_cease_fixture_body)
{
    const uint8_t *body = LIBBGP_FIXTURE_NOTIFICATION_CEASE + LIBBGP_BGP_HEADER_LEN;
    uint8_t out[8];
    size_t used = 0u;
    size_t out_len = 0u;
    libbgp_notification_msg_t msg;

    libbgp_notification_init(&msg);
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_notification_parse(&msg, body, 2u, &used));
    LIBBGP_ASSERT_EQ_U64(2u, used);
    LIBBGP_ASSERT_EQ_U64(6u, msg.err_code);
    LIBBGP_ASSERT_EQ_U64(0u, msg.err_subcode);
    LIBBGP_ASSERT(msg.data == NULL);
    LIBBGP_ASSERT_EQ_U64(0u, msg.data_len);

    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_notification_write(&msg, out, sizeof(out), &out_len));
    LIBBGP_ASSERT_EQ_U64(2u, out_len);
    LIBBGP_ASSERT_BYTES_EQ(body, out, out_len);
    libbgp_notification_destroy(&msg);
}

LIBBGP_TEST(notification_parse_copies_data_and_destroy_clears_it)
{
    const uint8_t body[] = { 2u, 3u, 0xaau, 0xbbu, 0xccu };
    size_t used = 0u;
    libbgp_notification_msg_t msg;

    libbgp_notification_init(&msg);
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_notification_parse(&msg, body, sizeof(body), &used));
    LIBBGP_ASSERT_EQ_U64(sizeof(body), used);
    LIBBGP_ASSERT_EQ_U64(2u, msg.err_code);
    LIBBGP_ASSERT_EQ_U64(3u, msg.err_subcode);
    LIBBGP_ASSERT_EQ_U64(3u, msg.data_len);
    LIBBGP_ASSERT(msg.data != &body[2]);
    LIBBGP_ASSERT_BYTES_EQ(&body[2], msg.data, msg.data_len);

    libbgp_notification_destroy(&msg);
    LIBBGP_ASSERT(msg.data == NULL);
    LIBBGP_ASSERT_EQ_U64(0u, msg.data_len);
}

LIBBGP_TEST(notification_rejects_bad_lengths_and_small_output)
{
    const uint8_t one[] = { 1u };
    uint8_t out[2];
    size_t marker = 99u;
    libbgp_notification_msg_t msg;

    libbgp_notification_init(&msg);
    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_BAD_LEN, libbgp_notification_parse(NULL, one, sizeof(one), &marker));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_BAD_LEN, libbgp_notification_parse(&msg, NULL, sizeof(one), &marker));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_BAD_LEN, libbgp_notification_parse(&msg, one, sizeof(one), &marker));
    LIBBGP_ASSERT_EQ_U64(99u, marker);

    msg.err_code = 1u;
    msg.err_subcode = 2u;
    msg.data = (uint8_t *)"abc";
    msg.data_len = 3u;
    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_BAD_LEN, libbgp_notification_write(NULL, out, sizeof(out), &marker));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_BAD_LEN, libbgp_notification_write(&msg, NULL, sizeof(out), &marker));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_BUFFER, libbgp_notification_write(&msg, out, sizeof(out), &marker));
    LIBBGP_ASSERT_EQ_U64(99u, marker);
}

LIBBGP_TEST(notification_write_allows_null_data_when_length_zero_and_exact_buffer)
{
    const uint8_t expected[] = { 3u, 1u };
    uint8_t out[sizeof(expected)];
    size_t out_len = 99u;
    libbgp_notification_msg_t msg;

    libbgp_notification_init(&msg);
    msg.err_code = 3u;
    msg.err_subcode = 1u;
    msg.data = NULL;
    msg.data_len = 0u;

    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_notification_write(&msg, out, sizeof(out), &out_len));
    LIBBGP_ASSERT_EQ_U64(sizeof(expected), out_len);
    LIBBGP_ASSERT_BYTES_EQ(expected, out, sizeof(expected));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, libbgp_notification_write(&msg, out, sizeof(out), NULL));
    libbgp_notification_destroy(&msg);
}

LIBBGP_TEST(notification_write_rejects_null_data_with_nonzero_length)
{
    uint8_t out[8];
    size_t out_len = 99u;
    libbgp_notification_msg_t msg;

    libbgp_notification_init(&msg);
    msg.err_code = 2u;
    msg.err_subcode = 3u;
    msg.data = NULL;
    msg.data_len = 1u;

    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_BAD_LEN, libbgp_notification_write(&msg, out, sizeof(out), &out_len));
    LIBBGP_ASSERT_EQ_U64(99u, out_len);
    msg.data_len = 0u;
    libbgp_notification_destroy(&msg);
}

int main(void)
{
    const libbgp_test_case_t tests[] = {
        { "notification_parse_write_cease_fixture_body", notification_parse_write_cease_fixture_body },
        { "notification_parse_copies_data_and_destroy_clears_it", notification_parse_copies_data_and_destroy_clears_it },
        { "notification_rejects_bad_lengths_and_small_output", notification_rejects_bad_lengths_and_small_output },
        { "notification_write_allows_null_data_when_length_zero_and_exact_buffer", notification_write_allows_null_data_when_length_zero_and_exact_buffer },
        { "notification_write_rejects_null_data_with_nonzero_length", notification_write_rejects_null_data_with_nonzero_length }
    };

    return libbgp_run_tests("notification", tests, LIBBGP_ARRAY_LEN(tests));
}
