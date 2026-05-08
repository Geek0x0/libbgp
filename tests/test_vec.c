#include "test_main.h"

#include "../src/vec.h"

LIBBGP_TEST(vec_push_grows_and_preserves_values)
{
    bgp_vec_t(int) values;
    size_t i;
    libbgp_err_t err;

    bgp_vec_init(&values);
    LIBBGP_ASSERT(values.data == NULL);
    LIBBGP_ASSERT_EQ_U64(0u, values.len);
    LIBBGP_ASSERT_EQ_U64(0u, values.cap);

    for (i = 0; i < 9u; i++) {
        bgp_vec_push(&values, (int)(i * 3u), &err);
        LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, err);
    }

    LIBBGP_ASSERT_EQ_U64(9u, values.len);
    LIBBGP_ASSERT(values.cap >= 9u);
    for (i = 0; i < values.len; i++) {
        LIBBGP_ASSERT_EQ_I64((int)(i * 3u), values.data[i]);
    }

    bgp_vec_free(&values);
    LIBBGP_ASSERT(values.data == NULL);
    LIBBGP_ASSERT_EQ_U64(0u, values.len);
    LIBBGP_ASSERT_EQ_U64(0u, values.cap);
}

LIBBGP_TEST(vec_reserve_increases_capacity_without_changing_length)
{
    bgp_vec_t(unsigned) values;
    libbgp_err_t err;

    bgp_vec_init(&values);

    bgp_vec_reserve(&values, 17u, &err);
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, err);
    LIBBGP_ASSERT(values.data != NULL);
    LIBBGP_ASSERT_EQ_U64(0u, values.len);
    LIBBGP_ASSERT(values.cap >= 17u);

    bgp_vec_push(&values, 42u, &err);
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, err);
    LIBBGP_ASSERT_EQ_U64(1u, values.len);
    LIBBGP_ASSERT_EQ_U64(42u, values.data[0]);

    bgp_vec_free(&values);
}

LIBBGP_TEST(vec_failed_reserve_preserves_existing_storage)
{
    bgp_vec_t(unsigned) values;
    unsigned *data;
    size_t cap;
    libbgp_err_t err;

    bgp_vec_init(&values);
    bgp_vec_push(&values, 7u, &err);
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, err);

    data = values.data;
    cap = values.cap;

    bgp_vec_reserve(&values, (size_t)-1, &err);
    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_NOMEM, err);
    LIBBGP_ASSERT(values.data == data);
    LIBBGP_ASSERT_EQ_U64(1u, values.len);
    LIBBGP_ASSERT_EQ_U64(cap, values.cap);
    LIBBGP_ASSERT_EQ_U64(7u, values.data[0]);

    bgp_vec_free(&values);
}

int main(void)
{
    const libbgp_test_case_t tests[] = {
        { "vec_push_grows_and_preserves_values", vec_push_grows_and_preserves_values },
        { "vec_reserve_increases_capacity_without_changing_length", vec_reserve_increases_capacity_without_changing_length },
        { "vec_failed_reserve_preserves_existing_storage", vec_failed_reserve_preserves_existing_storage }
    };

    return libbgp_run_tests("vec", tests, LIBBGP_ARRAY_LEN(tests));
}
