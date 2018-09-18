#ifndef ASTERISM_UTILS_H_
#define ASTERISM_UTILS_H_
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <memory.h>

#ifdef WIN32
#define vsnprintf _vsnprintf
#endif

#define asterism_safefree(d) \
    if (d)                   \
    {                        \
        free(d);             \
        d = 0;               \
    }

#define __zero_malloc_st(s) (s *)memset(malloc(sizeof(s)), 0, sizeof(s))
#define __dup_mem(b, s) memcpy(malloc(s), b, s)

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

#endif
