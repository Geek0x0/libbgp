#include "test_main.h"

#include "../src/hashmap.h"
#include "libbgp/alloc.h"

#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

typedef struct free_counter {
    size_t calls;
    int key_sum;
    int value_sum;
} free_counter_t;

typedef struct fail_alloc_ctx {
    size_t malloc_calls;
    size_t fail_malloc_at;
    size_t calloc_calls;
    size_t fail_calloc_at;
    size_t realloc_calls;
    size_t fail_realloc_at;
} fail_alloc_ctx_t;

typedef struct foreach_counter {
    size_t calls;
    size_t stop_after;
    int key_sum;
    int value_sum;
} foreach_counter_t;

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

static void *fail_malloc(size_t size, void *ctx)
{
    fail_alloc_ctx_t *fail = (fail_alloc_ctx_t *)ctx;

    fail->malloc_calls++;
    if (fail->fail_malloc_at != 0u && fail->malloc_calls == fail->fail_malloc_at) {
        return NULL;
    }
    return malloc(size);
}

static void *fail_calloc(size_t nmemb, size_t size, void *ctx)
{
    fail_alloc_ctx_t *fail = (fail_alloc_ctx_t *)ctx;

    fail->calloc_calls++;
    if (fail->fail_calloc_at != 0u && fail->calloc_calls == fail->fail_calloc_at) {
        return NULL;
    }
    return calloc(nmemb, size);
}

static void *fail_realloc(void *ptr, size_t size, void *ctx)
{
    fail_alloc_ctx_t *fail = (fail_alloc_ctx_t *)ctx;

    fail->realloc_calls++;
    if (fail->fail_realloc_at != 0u && fail->realloc_calls == fail->fail_realloc_at) {
        return NULL;
    }
    return realloc(ptr, size);
}

static void fail_free(void *ptr, void *ctx)
{
    (void)ctx;
    free(ptr);
}

static uint64_t constant_hash(const void *key, void *ctx)
{
    (void)key;
    (void)ctx;
    return 1u;
}

static bool foreach_count_and_maybe_stop(void *key, void *value, void *ctx)
{
    foreach_counter_t *counter = (foreach_counter_t *)ctx;

    counter->calls++;
    counter->key_sum += *(int *)key;
    counter->value_sum += *(int *)value;
    return counter->stop_after == 0u || counter->calls < counter->stop_after;
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

LIBBGP_TEST(test_hashmap_reserve_prevents_resize)
{
    bgp_hashmap_t map;
    int keys[1000];
    size_t i;
    const size_t n = LIBBGP_ARRAY_LEN(keys);
    size_t bucket_count_before;
    size_t resize_threshold;

    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, bgp_hashmap_init(&map, int_hash, int_eq, NULL, NULL));

    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, bgp_hashmap_reserve(&map, n));
    resize_threshold = map.bucket_count - map.bucket_count / 4u;
    LIBBGP_ASSERT(resize_threshold >= n);

    bucket_count_before = map.bucket_count;
    for (i = 0u; i < n; i++) {
        keys[i] = (int)i;
        LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, bgp_hashmap_insert(&map, &keys[i], NULL));
    }
    LIBBGP_ASSERT_EQ_U64(bucket_count_before, map.bucket_count);
    LIBBGP_ASSERT_EQ_U64(n, bgp_hashmap_len(&map));

    bgp_hashmap_destroy(&map);
}

LIBBGP_TEST(hashmap_invalid_inputs_and_destroy_null_are_safe)
{
    bgp_hashmap_t map;
    int key = 1;
    int value = 2;

    memset(&map, 0, sizeof(map));
    bgp_hashmap_destroy(NULL);
    bgp_hashmap_destroy(&map);
    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_INVALID, bgp_hashmap_init(NULL, int_hash, int_eq, NULL, NULL));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_INVALID, bgp_hashmap_init(&map, NULL, int_eq, NULL, NULL));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_INVALID, bgp_hashmap_init(&map, int_hash, NULL, NULL, NULL));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_INVALID, bgp_hashmap_reserve(NULL, 1u));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_INVALID, bgp_hashmap_reserve(&map, 1u));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_INVALID, bgp_hashmap_insert(NULL, &key, &value));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_INVALID, bgp_hashmap_insert(&map, &key, &value));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_INVALID, bgp_hashmap_remove_one(NULL, &key, &value));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_INVALID, bgp_hashmap_remove_one(&map, &key, &value));
    LIBBGP_ASSERT(bgp_hashmap_find_first(NULL, &key) == NULL);
    LIBBGP_ASSERT(bgp_hashmap_find_first(&map, &key) == NULL);
    LIBBGP_ASSERT_EQ_U64(0u, bgp_hashmap_count_key(NULL, &key));
    LIBBGP_ASSERT_EQ_U64(0u, bgp_hashmap_count_key(&map, &key));
    bgp_hashmap_foreach(NULL, NULL, NULL);
    bgp_hashmap_foreach(&map, NULL, NULL);
}

LIBBGP_TEST(hashmap_init_reports_bucket_alloc_failure_without_leaking_allocator)
{
    bgp_hashmap_t map;
    fail_alloc_ctx_t ctx = { 0u, 0u, 0u, 1u, 0u, 0u };
    libbgp_alloc_t alloc = { fail_malloc, fail_calloc, fail_realloc, fail_free, &ctx };
    libbgp_err_t err;

    libbgp_set_alloc(&alloc);
    err = bgp_hashmap_init(&map, int_hash, int_eq, NULL, NULL);
    libbgp_set_alloc(NULL);

    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_NOMEM, err);
    LIBBGP_ASSERT_EQ_U64(1u, ctx.calloc_calls);
}

LIBBGP_TEST(hashmap_insert_reports_entry_alloc_failure_without_leaking_allocator)
{
    bgp_hashmap_t map;
    int key = 1;
    int value = 2;
    fail_alloc_ctx_t ctx = { 0u, 1u, 0u, 0u, 0u, 0u };
    libbgp_alloc_t alloc = { fail_malloc, fail_calloc, fail_realloc, fail_free, &ctx };
    libbgp_err_t err;

    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, bgp_hashmap_init(&map, int_hash, int_eq, NULL, NULL));
    libbgp_set_alloc(&alloc);
    err = bgp_hashmap_insert(&map, &key, &value);
    libbgp_set_alloc(NULL);

    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_NOMEM, err);
    LIBBGP_ASSERT_EQ_U64(0u, bgp_hashmap_len(&map));
    LIBBGP_ASSERT_EQ_U64(1u, ctx.malloc_calls);
    bgp_hashmap_destroy(&map);
}

LIBBGP_TEST(hashmap_resize_failure_preserves_existing_entries)
{
    bgp_hashmap_t map;
    int keys[13];
    int vals[13];
    fail_alloc_ctx_t ctx = { 0u, 0u, 0u, 0u, 0u, 0u };
    libbgp_alloc_t alloc = { fail_malloc, fail_calloc, fail_realloc, fail_free, &ctx };
    libbgp_err_t err;
    size_t i;

    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, bgp_hashmap_init(&map, int_hash, int_eq, NULL, NULL));
    for (i = 0u; i < 12u; i++) {
        keys[i] = (int)i;
        vals[i] = (int)(i + 100u);
        LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, bgp_hashmap_insert(&map, &keys[i], &vals[i]));
    }
    keys[12] = 12;
    vals[12] = 112;
    ctx.fail_calloc_at = ctx.calloc_calls + 1u;
    libbgp_set_alloc(&alloc);
    err = bgp_hashmap_insert(&map, &keys[12], &vals[12]);
    libbgp_set_alloc(NULL);

    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_NOMEM, err);
    LIBBGP_ASSERT_EQ_U64(12u, bgp_hashmap_len(&map));
    LIBBGP_ASSERT_EQ_U64(1u, ctx.calloc_calls);
    for (i = 0u; i < 12u; i++) {
        LIBBGP_ASSERT(bgp_hashmap_find_first(&map, &keys[i]) == &vals[i]);
    }
    LIBBGP_ASSERT(bgp_hashmap_find_first(&map, &keys[12]) == NULL);
    bgp_hashmap_destroy(&map);
}

LIBBGP_TEST(hashmap_chained_lookup_count_remove_and_foreach_cover_misses_and_stops)
{
    bgp_hashmap_t map;
    foreach_counter_t all = { 0u, 0u, 0, 0 };
    foreach_counter_t stop = { 0u, 2u, 0, 0 };
    free_counter_t freed = { 0u, 0, 0 };
    int keys[] = { 1, 2, 3 };
    int vals[] = { 10, 20, 30 };
    int missing = 4;

    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, bgp_hashmap_init(&map, constant_hash, int_eq, count_free, &freed));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, bgp_hashmap_insert(&map, &keys[0], &vals[0]));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, bgp_hashmap_insert(&map, &keys[1], &vals[1]));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, bgp_hashmap_insert(&map, &keys[2], &vals[2]));

    LIBBGP_ASSERT(bgp_hashmap_find_first(&map, &keys[1]) == &vals[1]);
    LIBBGP_ASSERT(bgp_hashmap_find_first(&map, &missing) == NULL);
    LIBBGP_ASSERT_EQ_U64(1u, bgp_hashmap_count_key(&map, &keys[1]));
    LIBBGP_ASSERT_EQ_U64(0u, bgp_hashmap_count_key(&map, &missing));
    LIBBGP_ASSERT_EQ_I64(LIBBGP_ERR_NOT_FOUND, bgp_hashmap_remove_one(&map, &keys[1], &vals[0]));

    bgp_hashmap_foreach(&map, foreach_count_and_maybe_stop, &all);
    LIBBGP_ASSERT_EQ_U64(3u, all.calls);
    LIBBGP_ASSERT_EQ_I64(6, all.key_sum);
    LIBBGP_ASSERT_EQ_I64(60, all.value_sum);

    bgp_hashmap_foreach(&map, foreach_count_and_maybe_stop, &stop);
    LIBBGP_ASSERT_EQ_U64(2u, stop.calls);

    LIBBGP_ASSERT_EQ_I64(LIBBGP_OK, bgp_hashmap_remove_one(&map, &keys[1], NULL));
    LIBBGP_ASSERT_EQ_U64(1u, freed.calls);
    LIBBGP_ASSERT_EQ_I64(2, freed.key_sum);
    LIBBGP_ASSERT_EQ_I64(20, freed.value_sum);
    LIBBGP_ASSERT_EQ_U64(2u, bgp_hashmap_len(&map));
    bgp_hashmap_destroy(&map);
}

int main(void)
{
    const libbgp_test_case_t tests[] = {
        { "hashmap_insert_find_and_count_multimap_entries", hashmap_insert_find_and_count_multimap_entries },
        { "hashmap_remove_one_by_value_and_by_key", hashmap_remove_one_by_value_and_by_key },
        { "hashmap_destroy_invokes_callback_for_all_entries", hashmap_destroy_invokes_callback_for_all_entries },
        { "hashmap_resizes_and_preserves_entries", hashmap_resizes_and_preserves_entries },
        { "test_hashmap_reserve_prevents_resize", test_hashmap_reserve_prevents_resize },
        { "hashmap_invalid_inputs_and_destroy_null_are_safe", hashmap_invalid_inputs_and_destroy_null_are_safe },
        { "hashmap_init_reports_bucket_alloc_failure_without_leaking_allocator", hashmap_init_reports_bucket_alloc_failure_without_leaking_allocator },
        { "hashmap_insert_reports_entry_alloc_failure_without_leaking_allocator", hashmap_insert_reports_entry_alloc_failure_without_leaking_allocator },
        { "hashmap_resize_failure_preserves_existing_entries", hashmap_resize_failure_preserves_existing_entries },
        { "hashmap_chained_lookup_count_remove_and_foreach_cover_misses_and_stops", hashmap_chained_lookup_count_remove_and_foreach_cover_misses_and_stops }
    };

    return libbgp_run_tests("hashmap", tests, LIBBGP_ARRAY_LEN(tests));
}
