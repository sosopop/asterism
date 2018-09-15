#include "asterism_utils.h"

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