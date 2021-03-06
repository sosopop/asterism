#ifndef ASTERISM_UTILS_H_
#define ASTERISM_UTILS_H_

#ifdef WIN32
#ifndef _CRTDBG_MAP_ALLOC
#define _CRTDBG_MAP_ALLOC
#endif
#include <crtdbg.h>
#endif

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <memory.h>

#ifdef WIN32
#define vsnprintf _vsnprintf
#endif

#define AS_MALLOC malloc
#define AS_FREE free
#define AS_REALLOC realloc

#define AS_SFREE(d) \
    if (d)          \
    {               \
        AS_FREE(d); \
        d = 0;      \
    }

#define AS_ZMALLOC(s) (s *)memset(AS_MALLOC(sizeof(s)), 0, sizeof(s))
#define __DUP_MEM(b, s) memcpy(AS_MALLOC(s), b, s)
#define __CONTAINER_PTR(s, m, p) (s *)((unsigned char *)p - (unsigned char *)(&((s *)0)->m))
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

int asterism_base64_decode(const unsigned char *s, int len, char *dst, int *dec_len);

int asterism_itoa(char *buf, size_t buf_size, long long num, int base, int flags,
                  int field_width);
#endif
