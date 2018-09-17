#include "asterism_utils.h"
#include <string.h>
#include <ctype.h>
#ifdef WIN32
#include <ws2tcpip.h>
#else
#include <sys/socket.h>
#endif

int asterism_vsnprintf(char **buf, size_t size, const char *fmt, va_list ap)
{
    va_list ap_copy;
    int len;

    va_copy(ap_copy, ap);
    len = vsnprintf(*buf, size, fmt, ap_copy);
    va_end(ap_copy);

    if (len < 0)
    {
        *buf = NULL;
        while (len < 0)
        {
            free(*buf);
            if (size == 0)
            {
                size = 5;
            }
            size *= 2;
            if ((*buf = (char *)malloc(size)) == NULL)
            {
                len = -1;
                break;
            }
            va_copy(ap_copy, ap);
            len = vsnprintf(*buf, size - 1, fmt, ap_copy);
            va_end(ap_copy);
        }

        (*buf)[len] = 0;
    }
    else if (len >= (int)size)
    {
        if ((*buf = (char *)malloc(len + 1)) == NULL)
        {
            len = -1;
        }
        else
        {
            va_copy(ap_copy, ap);
            len = vsnprintf(*buf, len + 1, fmt, ap_copy);
            va_end(ap_copy);
        }
    }

    return len;
}

int asterism_snprintf(char **buf, size_t size, const char *fmt, ...)
{
    int ret;
    va_list ap;
    va_start(ap, fmt);
    ret = asterism_vsnprintf(buf, size, fmt, ap);
    va_end(ap);
    return ret;
}

struct asterism_str asterism_mk_str(const char *s)
{
    struct asterism_str ret = {s, 0};
    if (s != NULL)
        ret.len = strlen(s);
    return ret;
}

struct asterism_str asterism_mk_str_n(const char *s, size_t len)
{
    struct asterism_str ret = {s, len};
    return ret;
}

int asterism_vcmp(const struct asterism_str *str1, const char *str2)
{
    size_t n2 = strlen(str2), n1 = str1->len;
    int r = strncmp(str1->p, str2, (n1 < n2) ? n1 : n2);
    if (r == 0)
    {
        return n1 - n2;
    }
    return r;
}

static int str_util_lowercase(const char *s)
{
    return tolower(*(const unsigned char *)s);
}

int asterism_ncasecmp(const char *s1, const char *s2, size_t len)
{
    int diff = 0;

    if (len > 0)
        do
        {
            diff = str_util_lowercase(s1++) - str_util_lowercase(s2++);
        } while (diff == 0 && s1[-1] != '\0' && --len > 0);

    return diff;
}

int asterism_casecmp(const char *s1, const char *s2)
{
    return asterism_ncasecmp(s1, s2, (size_t)~0);
}

int asterism_vcasecmp(const struct asterism_str *str1, const char *str2)
{
    size_t n2 = strlen(str2), n1 = str1->len;
    int r = asterism_ncasecmp(str1->p, str2, (n1 < n2) ? n1 : n2);
    if (r == 0)
    {
        return n1 - n2;
    }
    return r;
}

static struct asterism_str asterism_strdup_common(const struct asterism_str s,
                                                  int nul_terminate)
{
    struct asterism_str r = {NULL, 0};
    if (s.len > 0 && s.p != NULL)
    {
        char *sc = (char *)malloc(s.len + (nul_terminate ? 1 : 0));
        if (sc != NULL)
        {
            memcpy(sc, s.p, s.len);
            if (nul_terminate)
                sc[s.len] = '\0';
            r.p = sc;
            r.len = s.len;
        }
    }
    return r;
}

struct asterism_str asterism_strdup(const struct asterism_str s)
{
    return asterism_strdup_common(s, 0 /* NUL-terminate */);
}

struct asterism_str asterism_strdup_nul(const struct asterism_str s)
{
    return asterism_strdup_common(s, 1 /* NUL-terminate */);
}

const char *asterism_strchr(const struct asterism_str s, int c)
{
    size_t i;
    for (i = 0; i < s.len; i++)
    {
        if (s.p[i] == c)
            return &s.p[i];
    }
    return NULL;
}

int asterism_strcmp(const struct asterism_str str1, const struct asterism_str str2)
{
    size_t i = 0;
    while (i < str1.len && i < str2.len)
    {
        if (str1.p[i] < str2.p[i])
            return -1;
        if (str1.p[i] > str2.p[i])
            return 1;
        i++;
    }
    if (i < str1.len)
        return 1;
    if (i < str2.len)
        return -1;
    return 0;
}

int asterism_strncmp(const struct asterism_str str1, const struct asterism_str str2, size_t n)
{
    struct asterism_str s1 = str1;
    struct asterism_str s2 = str2;

    if (s1.len > n)
    {
        s1.len = n;
    }
    if (s2.len > n)
    {
        s2.len = n;
    }
    return asterism_strcmp(s1, s2);
}

const char *asterism_strstr(const struct asterism_str haystack,
                            const struct asterism_str needle)
{
    size_t i;
    if (needle.len > haystack.len)
        return NULL;
    for (i = 0; i <= haystack.len - needle.len; i++)
    {
        if (memcmp(haystack.p + i, needle.p, needle.len) == 0)
        {
            return haystack.p + i;
        }
    }
    return NULL;
}

struct asterism_str asterism_strstrip(struct asterism_str s)
{
    while (s.len > 0 && isspace((int)*s.p))
    {
        s.p++;
        s.len--;
    }
    while (s.len > 0 && isspace((int)*(s.p + s.len - 1)))
    {
        s.len--;
    }
    return s;
}

int asterism_str_empty(const struct asterism_str *str)
{
    return !str->p || !str->len;
}

int asterism_parse_address(
    const char *address,
    struct asterism_str *scheme,
    struct asterism_str *host,
    unsigned int *port,
    asterism_host_type *host_type)
{
    char __scheme[100] = {0};
    char __host[100] = {0};
    int ch = 0, len = 0, host_offset = 0, host_len = 0;

    if (sscanf(address, "%99[^:]://%n", __scheme, &host_offset) == 1)
    {
        if (scheme && host_offset)
        {
            //3 is :// length
            scheme->len = host_offset - 3;
            scheme->p = address;
        }
    }
    if (sscanf(address + host_offset, "%99[^:[]%n:%u%n", __host, &host_len, port, &len) == 2)
    {
        int a = 0;
        int ret = sscanf(address + host_offset, "%*u.%*u.%*u.%*u:%u%n", &a, &len);
        if (ret == 1)
        {
            *host_type = ASTERISM_HOST_TYPE_IPV4;
        }
        else
        {
            *host_type = ASTERISM_HOST_TYPE_DOMAIN;
        }

        if (host && host_len)
        {
            //2 is [] length
            host->len = host_len;
            //1 is [ length
            host->p = address + host_offset;
        }
    }
    else if (sscanf(address + host_offset, "[%99[^]]]%n:%u%n", __host, &host_len, port, &len) == 2)
    {
        *host_type = ASTERISM_HOST_TYPE_IPV6;
        if (host && host_len)
        {
            //2 is [] length
            host->len = host_len - 2;
            //1 is [ length
            host->p = address + host_offset + 1;
        }
    }
    else
    {
        return -1;
    }

    ch = address[host_offset + len];

    return *port < 0xffffUL && (ch == '\0' || ch == ',' || isspace(ch)) ? 0 : -1;
}
