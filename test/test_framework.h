#ifndef TEST_FRAMEWORK_H_
#define TEST_FRAMEWORK_H_

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

extern int g_test_failures;
extern int g_test_passes;
extern int g_case_failures;

#define EXPECT_TRUE(expr) \
    do { \
        if (!(expr)) { \
            fprintf(stderr, "  [  FAILED  ] %s:%d: Expected %s to be true\n", __FILE__, __LINE__, #expr); \
            g_test_failures++; \
            g_case_failures++; \
        } else { \
            g_test_passes++; \
        } \
    } while (0)

#define EXPECT_FALSE(expr) \
    do { \
        if (expr) { \
            fprintf(stderr, "  [  FAILED  ] %s:%d: Expected %s to be false\n", __FILE__, __LINE__, #expr); \
            g_test_failures++; \
            g_case_failures++; \
        } else { \
            g_test_passes++; \
        } \
    } while (0)

#define EXPECT_EQ(val1, val2) \
    do { \
        long long v1 = (long long)(val1); \
        long long v2 = (long long)(val2); \
        if (v1 != v2) { \
            fprintf(stderr, "  [  FAILED  ] %s:%d: Expected %s == %s (actual: %lld vs %lld)\n", \
                    __FILE__, __LINE__, #val1, #val2, v1, v2); \
            g_test_failures++; \
            g_case_failures++; \
        } else { \
            g_test_passes++; \
        } \
    } while (0)

#define EXPECT_NE(val1, val2) \
    do { \
        long long v1 = (long long)(val1); \
        long long v2 = (long long)(val2); \
        if (v1 == v2) { \
            fprintf(stderr, "  [  FAILED  ] %s:%d: Expected %s != %s (actual: both are %lld)\n", \
                    __FILE__, __LINE__, #val1, #val2, v1); \
            g_test_failures++; \
            g_case_failures++; \
        } else { \
            g_test_passes++; \
        } \
    } while (0)

#define EXPECT_STR_EQ(str1, str2) \
    do { \
        const char *s1 = (str1); \
        const char *s2 = (str2); \
        if (!s1 || !s2 || strcmp(s1, s2) != 0) { \
            fprintf(stderr, "  [  FAILED  ] %s:%d: Expected %s == %s (actual: \"%s\" vs \"%s\")\n", \
                    __FILE__, __LINE__, #str1, #str2, s1 ? s1 : "NULL", s2 ? s2 : "NULL"); \
            g_test_failures++; \
            g_case_failures++; \
        } else { \
            g_test_passes++; \
        } \
    } while (0)

#define EXPECT_STR_CONTAINS(str, sub) \
    do { \
        const char *s = (str); \
        const char *t = (sub); \
        if (!s || !t || strstr(s, t) == NULL) { \
            fprintf(stderr, "  [  FAILED  ] %s:%d: Expected \"%s\" to contain \"%s\"\n", \
                    __FILE__, __LINE__, s ? s : "NULL", t ? t : "NULL"); \
            g_test_failures++; \
            g_case_failures++; \
        } else { \
            g_test_passes++; \
        } \
    } while (0)

typedef void (*test_func_t)(void);

typedef struct {
    const char *suite_name;
    const char *case_name;
    test_func_t func;
} test_case_t;

void register_test(const char *suite_name, const char *case_name, test_func_t func);
int run_all_tests(void);

#endif
