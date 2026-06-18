#ifndef ASTERISM_UTILS_H_
#define ASTERISM_UTILS_H_

#ifdef _WIN32
#ifndef _CRTDBG_MAP_ALLOC
#define _CRTDBG_MAP_ALLOC
#endif
#include <crtdbg.h>
#endif

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <memory.h>
#include <stddef.h>

#ifdef _WIN32
#define vsnprintf _vsnprintf
#endif

#ifdef ASTERISM_TEST_HOOKS
/* Test-only allocator seam. Lets unit tests drive out-of-memory branches by
   forcing the Nth AS_MALLOC to return NULL. Compiled into asterism_lib only
   when UNIT_TEST is ON (see src/asterism/CMakeLists.txt); production builds
   (-DUNIT_TEST=OFF) fall back to the plain libc allocator below with zero
   overhead. (AS_REALLOC is unused in the code base, so it is not hooked.) */
void *asterism_test_malloc(size_t size);
/* nth_alloc == 0 disables injection; otherwise the nth_alloc-th AS_MALLOC
   counted from this call returns NULL. SINGLE-THREADED USE ONLY: enable only
   while no asterism event-loop thread is running, or libuv's own allocations
   on the loop thread may be failed nondeterministically. Pair every
   set_alloc_fail() with reset_alloc_fail(). */
void asterism_test_set_alloc_fail(unsigned long nth_alloc);
void asterism_test_reset_alloc_fail(void);
#define AS_MALLOC asterism_test_malloc
#else
#define AS_MALLOC malloc
#endif
#define AS_FREE free
#define AS_REALLOC realloc

#define AS_SFREE(d) \
    if (d)          \
    {               \
        AS_FREE(d); \
        d = 0;      \
    }

static inline void *asterism_zmalloc(size_t size)
{
    void *p = AS_MALLOC(size);
    return p ? memset(p, 0, size) : NULL;
}

static inline void *asterism_dup_mem(const void *src, size_t size)
{
    if (!src && size)
        return NULL;
    void *p = AS_MALLOC(size);
    return p ? memcpy(p, src, size) : NULL;
}

#define AS_ZMALLOC(s) (s *)asterism_zmalloc(sizeof(s))
#define __DUP_MEM(b, s) asterism_dup_mem(b, s)
/* container_of: recover the enclosing struct from a member pointer. Uses
   offsetof rather than &((s*)0)->m so it is well-defined (the latter forms a
   pointer to a member of a null object, which UBSan flags). */
#define __CONTAINER_PTR(s, m, p) (s *)((unsigned char *)(p) - offsetof(s, m))
#define __ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))
#define __CSLEN(s) (sizeof(s)-1)

#define ASTERISM_SNPRINTF_FLAG_ZERO 1

#define ASTERISM_SNPRINTF_APPEND_CHAR(ch) \
    do                                    \
    {                                     \
        if (i < (int)buf_size)            \
            buf[i] = ch;                  \
        i++;                              \
    } while (0)

struct asterism_str
{
    const char *p; /* Memory chunk pointer */
    size_t len;    /* Memory chunk length */
};

struct asterism_slist
{
    char *data;
    struct asterism_slist *next;
};

struct asterism_str asterism_mk_str(const char *s);

struct asterism_str asterism_mk_str_n(const char *s, size_t len);

int asterism_vcmp(const struct asterism_str *str1, const char *str2);

int asterism_ncasecmp(const char *s1, const char *s2, size_t len);

int asterism_casecmp(const char *s1, const char *s2);

int asterism_vcasecmp(const struct asterism_str *str1, const char *str2);

struct asterism_str asterism_strdup(const struct asterism_str s);

struct asterism_str asterism_strdup_nul(const struct asterism_str s);

char *as_strdup(const char *src);

char *as_strdup2(const char *src, size_t len);

const char *asterism_strchr(const struct asterism_str s, int c);

int asterism_strcmp(const struct asterism_str str1, const struct asterism_str str2);

int asterism_strncmp(const struct asterism_str str1, const struct asterism_str str2, size_t n);

const char *asterism_strstr(const struct asterism_str haystack,
                            const struct asterism_str needle);

int asterism_str_empty(const struct asterism_str *str);

struct asterism_str asterism_strstrip(struct asterism_str s);

typedef enum
{
    ASTERISM_HOST_TYPE_IPV4,
    ASTERISM_HOST_TYPE_IPV6,
    ASTERISM_HOST_TYPE_DOMAIN
} asterism_host_type;

int asterism_parse_address(
    const char *address,
    struct asterism_str *scheme,
    struct asterism_str *host,
    unsigned int *port,
    asterism_host_type *host_type);

int asterism_vsnprintf(char **buf, size_t size, const char *fmt, va_list ap);

int asterism_snprintf(char **buf, size_t size, const char *fmt, ...);

struct asterism_slist *asterism_slist_duplicate(struct asterism_slist *inlist);

void asterism_slist_free_all(struct asterism_slist *list);

struct asterism_slist *asterism_slist_append(struct asterism_slist *list, const char *data);

int asterism_base64_decode(const unsigned char *s, int len, char *dst, size_t dst_size, int *dec_len);

int asterism_itoa(char *buf, size_t buf_size, long long num, int base, int flags,
                  int field_width);
#endif
