#include "test_main.h"
#include "fixtures/alloc_tracker.h"

#include "libbgp/alloc.h"
#include "libbgp/types.h"

LIBBGP_TEST(default_allocator_wrappers_allocate_and_free)
{
    void *p;
    unsigned char *z;

    libbgp_set_alloc(NULL);

    p = libbgp_malloc(16u);
    LIBBGP_ASSERT(p != NULL);
    p = libbgp_realloc(p, 32u);
    LIBBGP_ASSERT(p != NULL);
    libbgp_free(p);

    z = (unsigned char *)libbgp_calloc(4u, sizeof(*z));
    LIBBGP_ASSERT(z != NULL);
    LIBBGP_ASSERT_EQ_U64(0u, z[0]);
    LIBBGP_ASSERT_EQ_U64(0u, z[3]);
    libbgp_free(z);
}

LIBBGP_TEST(custom_allocator_callbacks_are_used_with_ctx)
{
    libbgp_alloc_tracker_t tracker;
    libbgp_alloc_t alloc;
    void *p;

    libbgp_alloc_tracker_init(&tracker);
    alloc = libbgp_alloc_tracker_make(&tracker);
    libbgp_set_alloc(&alloc);

    p = libbgp_malloc(11u);
    LIBBGP_ASSERT(p != NULL);
    LIBBGP_ASSERT_EQ_U64(1u, tracker.malloc_calls);
    LIBBGP_ASSERT(tracker.last_ctx == &tracker);

    p = libbgp_realloc(p, 19u);
    LIBBGP_ASSERT(p != NULL);
    LIBBGP_ASSERT_EQ_U64(1u, tracker.realloc_calls);
    LIBBGP_ASSERT(tracker.last_ctx == &tracker);

    libbgp_free(p);
    LIBBGP_ASSERT_EQ_U64(1u, tracker.free_calls);
    LIBBGP_ASSERT(tracker.last_ctx == &tracker);

    p = libbgp_calloc(2u, 7u);
    LIBBGP_ASSERT(p != NULL);
    LIBBGP_ASSERT_EQ_U64(1u, tracker.calloc_calls);
    LIBBGP_ASSERT(tracker.last_ctx == &tracker);
    libbgp_free(p);

    LIBBGP_ASSERT_EQ_U64(44u, tracker.bytes_requested);
    libbgp_set_alloc(NULL);
}

LIBBGP_TEST(set_alloc_null_resets_default_allocator)
{
    libbgp_alloc_tracker_t tracker;
    libbgp_alloc_t alloc;
    void *p;

    libbgp_alloc_tracker_init(&tracker);
    alloc = libbgp_alloc_tracker_make(&tracker);

    libbgp_set_alloc(&alloc);
    LIBBGP_ASSERT(libbgp_get_alloc() == &alloc);

    libbgp_set_alloc(NULL);
    LIBBGP_ASSERT(libbgp_get_alloc() == &libbgp_default_alloc);

    p = libbgp_malloc(8u);
    LIBBGP_ASSERT(p != NULL);
    libbgp_free(p);
    LIBBGP_ASSERT_EQ_U64(0u, tracker.malloc_calls);
}

LIBBGP_TEST(strerror_returns_exact_strings)
{
    LIBBGP_ASSERT(strcmp("ok", libbgp_strerror(LIBBGP_OK)) == 0);
    LIBBGP_ASSERT(strcmp("error", libbgp_strerror(LIBBGP_ERR)) == 0);
    LIBBGP_ASSERT(strcmp("parse error", libbgp_strerror(LIBBGP_ERR_PARSE)) == 0);
    LIBBGP_ASSERT(strcmp("write error", libbgp_strerror(LIBBGP_ERR_WRITE)) == 0);
    LIBBGP_ASSERT(strcmp("bad type", libbgp_strerror(LIBBGP_ERR_BAD_TYPE)) == 0);
    LIBBGP_ASSERT(strcmp("bad length", libbgp_strerror(LIBBGP_ERR_BAD_LEN)) == 0);
    LIBBGP_ASSERT(strcmp("buffer too small", libbgp_strerror(LIBBGP_ERR_BUFFER)) == 0);
    LIBBGP_ASSERT(strcmp("invalid value", libbgp_strerror(LIBBGP_ERR_INVALID)) == 0);
    LIBBGP_ASSERT(strcmp("already exists", libbgp_strerror(LIBBGP_ERR_EXISTS)) == 0);
    LIBBGP_ASSERT(strcmp("not found", libbgp_strerror(LIBBGP_ERR_NOT_FOUND)) == 0);
    LIBBGP_ASSERT(strcmp("out of memory", libbgp_strerror(LIBBGP_ERR_NOMEM)) == 0);
    LIBBGP_ASSERT(strcmp("unknown error", libbgp_strerror((libbgp_err_t)-999)) == 0);
}

int main(void)
{
    const libbgp_test_case_t tests[] = {
        { "default_allocator_wrappers_allocate_and_free", default_allocator_wrappers_allocate_and_free },
        { "custom_allocator_callbacks_are_used_with_ctx", custom_allocator_callbacks_are_used_with_ctx },
        { "set_alloc_null_resets_default_allocator", set_alloc_null_resets_default_allocator },
        { "strerror_returns_exact_strings", strerror_returns_exact_strings }
    };

    return libbgp_run_tests("alloc_log", tests, LIBBGP_ARRAY_LEN(tests));
}
