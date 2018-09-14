#ifndef ASTERISM_UTILS_H_
#define ASTERISM_UTILS_H_
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>

#ifdef WIN32
#define vsnprintf _vsnprintf
#endif

int asterism_vsnprintf(char **buf, size_t size, const char *fmt, va_list ap);

#endif
