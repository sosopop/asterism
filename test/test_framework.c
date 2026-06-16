#include "test_framework.h"

int g_test_failures = 0;
int g_test_passes = 0;
int g_case_failures = 0;

#define MAX_TESTS 256
static test_case_t g_tests[MAX_TESTS];
static int g_test_count = 0;

void register_test(const char *suite_name, const char *case_name, test_func_t func) {
    if (g_test_count < MAX_TESTS) {
        g_tests[g_test_count].suite_name = suite_name;
        g_tests[g_test_count].case_name = case_name;
        g_tests[g_test_count].func = func;
        g_test_count++;
    } else {
        fprintf(stderr, "Error: Maximum test count exceeded\n");
    }
}

int run_all_tests(void) {
    printf("[==========] Running %d tests.\n", g_test_count);
    int passed_cases = 0;
    int failed_cases = 0;
    
    for (int i = 0; i < g_test_count; i++) {
        test_case_t *tc = &g_tests[i];
        printf("[ RUN      ] %s.%s\n", tc->suite_name, tc->case_name);
        fflush(stdout);
        
        g_case_failures = 0;
        tc->func();
        
        if (g_case_failures == 0) {
            printf("[       OK ] %s.%s\n", tc->suite_name, tc->case_name);
            fflush(stdout);
            passed_cases++;
        } else {
            printf("[  FAILED  ] %s.%s\n", tc->suite_name, tc->case_name);
            fflush(stdout);
            failed_cases++;
        }
    }
    
    printf("[==========] %d tests ran.\n", g_test_count);
    printf("[  PASSED  ] %d tests.\n", passed_cases);
    if (failed_cases > 0) {
        printf("[  FAILED  ] %d tests.\n", failed_cases);
    }
    return failed_cases > 0 ? 1 : 0;
}
