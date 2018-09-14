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
        /* eCos and Windows are not standard-compliant and return -1 when
     * the buffer is too small. Keep allocating larger buffers until we
     * succeed or out of memory. */
        *buf = NULL; /* LCOV_EXCL_START */
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

        /*
     * Microsoft version of vsnprintf() is not always null-terminated, so put
     * the terminator manually
     */
        (*buf)[len] = 0;
        /* LCOV_EXCL_STOP */
    }
    else if (len >= (int)size)
    {
        /* Standard-compliant code path. Allocate a buffer that is large enough. */
        if ((*buf = (char *)malloc(len + 1)) == NULL)
        {
            len = -1; /* LCOV_EXCL_LINE */
        }
        else
        { /* LCOV_EXCL_LINE */
            va_copy(ap_copy, ap);
            len = vsnprintf(*buf, len + 1, fmt, ap_copy);
            va_end(ap_copy);
        }
    }

    return len;
}