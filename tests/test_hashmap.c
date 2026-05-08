#include "test_main.h"

#include "../src/hashmap.h"

#include <stdbool.h>
#include <stdint.h>

typedef struct free_counter {
    size_t calls;
    int key_sum;
    int value_sum;
} free_counter_t;

static uint64_t int_hash(const void *key, void *ctx)
{
    (void)ctx;
    return (uint64_t)*(const int *)key * 11400714819323198485ull;
}

static bool int_eq(const void *a, const void *b, void *ctx)
{
    (void)ctx;
    return *(const int *)a == *(const int *)b;
}

static void count_free(void *key, void *value, void *ctx)
{
    free_counter_t *counter = (free_counter_t *)ctx;

    counter->calls++;
    counter->key_sum += *(int *)key;
    counter->value_sum += *(int *)value;
}

LIBBGP_TEST(hashmap_insert_find_and_count_multimap_entries)
{
    bgp_hashmap_t map;
    int k1 = 7;
    int k1_equiv = 7;
    int k2 = 9;
    int v1 = 10;
    int v2 = 20;
    int v3 = 30;

    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, bgp_hashmap_init(&map, int_hash, int_eq, NULL, NULL));
    LIBBGP_ASSERT_EQ_U64(0u, bgp_hashmap_len(&map));
    LIBBGP_ASSERT(bgp_hashmap_find_first(&map, &k1) == NULL);

    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, bgp_hashmap_insert(&map, &k1, &v1));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, bgp_hashmap_insert(&map, &k1_equiv, &v2));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, bgp_hashmap_insert(&map, &k2, &v3));

    LIBBGP_ASSERT_EQ_U64(3u, bgp_hashmap_len(&map));
    LIBBGP_ASSERT_EQ_U64(2u, bgp_hashmap_count_key(&map, &k1));
    LIBBGP_ASSERT_EQ_U64(1u, bgp_hashmap_count_key(&map, &k2));
    LIBBGP_ASSERT(bgp_hashmap_find_first(&map, &k1) == &v1 ||
        bgp_hashmap_find_first(&map, &k1) == &v2);

    bgp_hashmap_destroy(&map);
    LIBBGP_ASSERT_EQ_U64(0u, bgp_hashmap_len(&map));
}

LIBBGP_TEST(hashmap_remove_one_by_value_and_by_key)
{
    bgp_hashmap_t map;
    int k = 3;
    int missing = 99;
    int v1 = 1;
    int v2 = 2;

    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, bgp_hashmap_init(&map, int_hash, int_eq, NULL, NULL));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, bgp_hashmap_insert(&map, &k, &v1));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, bgp_hashmap_insert(&map, &k, &v2));

    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, bgp_hashmap_remove_one(&map, &k, &v2));
    LIBBGP_ASSERT_EQ_U64(1u, bgp_hashmap_len(&map));
    LIBBGP_ASSERT_EQ_U64(1u, bgp_hashmap_count_key(&map, &k));
    LIBBGP_ASSERT(bgp_hashmap_find_first(&map, &k) == &v1);

    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_NOT_FOUND, bgp_hashmap_remove_one(&map, &missing, NULL));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, bgp_hashmap_remove_one(&map, &k, NULL));
    LIBBGP_ASSERT_EQ_U64(0u, bgp_hashmap_len(&map));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_NOT_FOUND, bgp_hashmap_remove_one(&map, &k, NULL));

    bgp_hashmap_destroy(&map);
}

LIBBGP_TEST(hashmap_destroy_invokes_callback_for_all_entries)
{
    bgp_hashmap_t map;
    free_counter_t counter = { 0u, 0, 0 };
    int keys[] = { 1, 2, 3 };
    int vals[] = { 10, 20, 30 };

    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, bgp_hashmap_init(&map, int_hash, int_eq, count_free, &counter));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, bgp_hashmap_insert(&map, &keys[0], &vals[0]));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, bgp_hashmap_insert(&map, &keys[1], &vals[1]));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, bgp_hashmap_insert(&map, &keys[2], &vals[2]));

    bgp_hashmap_destroy(&map);
    LIBBGP_ASSERT_EQ_U64(3u, counter.calls);
    LIBBGP_ASSERT_EQ_I64(6, counter.key_sum);
    LIBBGP_ASSERT_EQ_I64(60, counter.value_sum);
}

LIBBGP_TEST(hashmap_resizes_and_preserves_entries)
{
    bgp_hashmap_t map;
    int keys[256];
    int vals[256];
    size_t i;

    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, bgp_hashmap_init(&map, int_hash, int_eq, NULL, NULL));
    for (i = 0u; i < LIBBGP_ARRAY_LEN(keys); i++) {
        keys[i] = (int)i;
        vals[i] = (int)(i * 5u);
        LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, bgp_hashmap_insert(&map, &keys[i], &vals[i]));
    }

    LIBBGP_ASSERT_EQ_U64(LIBBGP_ARRAY_LEN(keys), bgp_hashmap_len(&map));
    for (i = 0u; i < LIBBGP_ARRAY_LEN(keys); i++) {
        LIBBGP_ASSERT_EQ_U64(1u, bgp_hashmap_count_key(&map, &keys[i]));
        LIBBGP_ASSERT(bgp_hashmap_find_first(&map, &keys[i]) == &vals[i]);
    }

    bgp_hashmap_destroy(&map);
}

int main(void)
{
    const libbgp_test_case_t tests[] = {
        { "hashmap_insert_find_and_count_multimap_entries", hashmap_insert_find_and_count_multimap_entries },
        { "hashmap_remove_one_by_value_and_by_key", hashmap_remove_one_by_value_and_by_key },
        { "hashmap_destroy_invokes_callback_for_all_entries", hashmap_destroy_invokes_callback_for_all_entries },
        { "hashmap_resizes_and_preserves_entries", hashmap_resizes_and_preserves_entries }
    };

    return libbgp_run_tests("hashmap", tests, LIBBGP_ARRAY_LEN(tests));
}
