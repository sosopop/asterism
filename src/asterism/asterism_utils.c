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

/* Convert one byte of encoded base64 input stream to 6-bit chunk */
static unsigned char from_b64(unsigned char ch)
{
    /* Inverse lookup map */
    static const unsigned char tab[128] = {
        255, 255, 255, 255,
        255, 255, 255, 255, /*  0 */
        255, 255, 255, 255,
        255, 255, 255, 255, /*  8 */
        255, 255, 255, 255,
        255, 255, 255, 255, /*  16 */
        255, 255, 255, 255,
        255, 255, 255, 255, /*  24 */
        255, 255, 255, 255,
        255, 255, 255, 255, /*  32 */
        255, 255, 255, 62,
        255, 255, 255, 63, /*  40 */
        52, 53, 54, 55,
        56, 57, 58, 59, /*  48 */
        60, 61, 255, 255,
        255, 200, 255, 255, /*  56   '=' is 200, on index 61 */
        255, 0, 1, 2,
        3, 4, 5, 6, /*  64 */
        7, 8, 9, 10,
        11, 12, 13, 14, /*  72 */
        15, 16, 17, 18,
        19, 20, 21, 22, /*  80 */
        23, 24, 25, 255,
        255, 255, 255, 255, /*  88 */
        255, 26, 27, 28,
        29, 30, 31, 32, /*  96 */
        33, 34, 35, 36,
        37, 38, 39, 40, /*  104 */
        41, 42, 43, 44,
        45, 46, 47, 48, /*  112 */
        49, 50, 51, 255,
        255, 255, 255, 255, /*  120 */
    };
    return tab[ch & 127];
}

int asterism_base64_decode(const unsigned char *s, int len, char *dst, int *dec_len)
{
    unsigned char a, b, c, d;
    int orig_len = len;
    char *orig_dst = dst;
    while (len >= 4 && (a = from_b64(s[0])) != 255 &&
           (b = from_b64(s[1])) != 255 && (c = from_b64(s[2])) != 255 &&
           (d = from_b64(s[3])) != 255)
    {
        s += 4;
        len -= 4;
        if (a == 200 || b == 200)
            break; /* '=' can't be there */
        *dst++ = a << 2 | b >> 4;
        if (c == 200)
            break;
        *dst++ = b << 4 | c >> 2;
        if (d == 200)
            break;
        *dst++ = c << 6 | d;
    }
    *dst = 0;
    if (dec_len != NULL)
        *dec_len = (dst - orig_dst);
    return orig_len - len;
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
        return (int)(n1 - n2);
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
        return (int)(n1 - n2);
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

int asterism_itoa(char *buf, size_t buf_size, long long num, int base, int flags,
                  int field_width)
{
    char tmp[40];
    int i = 0, k = 0, neg = 0;

    if (num < 0)
    {
        neg++;
        num = -num;
    }

    /* Print into temporary buffer - in reverse order */
    do
    {
        int rem = num % base;
        if (rem < 10)
        {
            tmp[k++] = '0' + rem;
        }
        else
        {
            tmp[k++] = 'a' + (rem - 10);
        }
        num /= base;
    } while (num > 0);

    /* Zero padding */
    if (flags && ASTERISM_SNPRINTF_FLAG_ZERO)
    {
        while (k < field_width && k < (int)sizeof(tmp) - 1)
        {
            tmp[k++] = '0';
        }
    }

    /* And sign */
    if (neg)
    {
        tmp[k++] = '-';
    }

    /* Now output */
    while (--k >= 0)
    {
        ASTERISM_SNPRINTF_APPEND_CHAR(tmp[k]);
    }

    return i;
}