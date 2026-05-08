#include "test_main.h"

#include "../src/vec.h"

LIBBGP_TEST(vec_push_grows_and_preserves_values)
{
    bgp_vec_t(int) values;
    size_t i;

    bgp_vec_init(&values);
    LIBBGP_ASSERT(values.data == NULL);
    LIBBGP_ASSERT_EQ_U64(0u, values.len);
    LIBBGP_ASSERT_EQ_U64(0u, values.cap);

    for (i = 0; i < 9u; i++) {
        LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, bgp_vec_push(&values, (int)(i * 3u)));
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

    bgp_vec_init(&values);

    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, bgp_vec_reserve(&values, 17u));
    LIBBGP_ASSERT(values.data != NULL);
    LIBBGP_ASSERT_EQ_U64(0u, values.len);
    LIBBGP_ASSERT(values.cap >= 17u);

    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, bgp_vec_push(&values, 42u));
    LIBBGP_ASSERT_EQ_U64(1u, values.len);
    LIBBGP_ASSERT_EQ_U64(42u, values.data[0]);

    bgp_vec_free(&values);
}

int main(void)
{
    const libbgp_test_case_t tests[] = {
        { "vec_push_grows_and_preserves_values", vec_push_grows_and_preserves_values },
        { "vec_reserve_increases_capacity_without_changing_length", vec_reserve_increases_capacity_without_changing_length }
    };

    return libbgp_run_tests("vec", tests, LIBBGP_ARRAY_LEN(tests));
}
