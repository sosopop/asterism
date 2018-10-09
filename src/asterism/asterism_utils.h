#ifndef ASTERISM_UTILS_H_
#define ASTERISM_UTILS_H_
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

#define AS_SAFEFREE(d) \
    if (d)             \
    {                  \
        AS_FREE(d);    \
        d = 0;         \
    }

#define __ZERO_MALLOC_ST(s) (s *)memset(AS_MALLOC(sizeof(s)), 0, sizeof(s))
#define __DUP_MEM(b, s) memcpy(AS_MALLOC(s), b, s)
#define __CONTAINER_PTR(s, m, p) (s *)((unsigned char *)p - (unsigned char *)(&((s *)0)->m))

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

int asterism_base64_decode(const unsigned char *s, int len, char *dst, int *dec_len);

int asterism_itoa(char *buf, size_t buf_size, long long num, int base, int flags,
                  int field_width);
#endif
