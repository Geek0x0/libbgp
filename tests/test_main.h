#ifndef LIBBGP_TEST_MAIN_H
#define LIBBGP_TEST_MAIN_H

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef void (*libbgp_test_fn)(void);

typedef struct libbgp_test_case {
    const char *name;
    libbgp_test_fn fn;
} libbgp_test_case_t;

#define LIBBGP_TEST(name) static void name(void)
#define LIBBGP_ARRAY_LEN(a) (sizeof(a) / sizeof((a)[0]))

#define LIBBGP_ASSERT(cond) do { \
    if (!(cond)) { \
        fprintf(stderr, "%s:%d: assertion failed: %s\n", __FILE__, __LINE__, #cond); \
        abort(); \
    } \
} while (0)

#define LIBBGP_ASSERT_EQ_U64(exp, act) do { \
    uint64_t e__ = (uint64_t)(exp); \
    uint64_t a__ = (uint64_t)(act); \
    if (e__ != a__) { \
        fprintf(stderr, "%s:%d: expected %llu, got %llu\n", \
            __FILE__, __LINE__, \
            (unsigned long long)e__, \
            (unsigned long long)a__); \
        abort(); \
    } \
} while (0)

#define LIBBGP_ASSERT_EQ_I64(exp, act) do { \
    int64_t e__ = (int64_t)(exp); \
    int64_t a__ = (int64_t)(act); \
    if (e__ != a__) { \
        fprintf(stderr, "%s:%d: expected %lld, got %lld\n", \
            __FILE__, __LINE__, \
            (long long)e__, \
            (long long)a__); \
        abort(); \
    } \
} while (0)

#define LIBBGP_ASSERT_BYTES_EQ(exp, act, len) do { \
    if (memcmp((exp), (act), (len)) != 0) { \
        fprintf(stderr, "%s:%d: byte buffers differ, len=%zu\n", \
            __FILE__, __LINE__, (size_t)(len)); \
        abort(); \
    } \
} while (0)

int libbgp_run_tests(const char *suite, const libbgp_test_case_t *tests, size_t count);

#endif
