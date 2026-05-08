#include "test_main.h"

int libbgp_run_tests(const char *suite, const libbgp_test_case_t *tests, size_t count)
{
    size_t i;

    for (i = 0; i < count; i++) {
        fprintf(stderr, "[ RUN      ] %s.%s\n", suite, tests[i].name);
        tests[i].fn();
        fprintf(stderr, "[       OK ] %s.%s\n", suite, tests[i].name);
    }

    fprintf(stderr, "[  PASSED  ] %s: %zu tests\n", suite, count);
    return 0;
}
