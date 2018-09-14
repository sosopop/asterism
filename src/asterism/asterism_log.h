#ifndef ASTERISM_LOG_H_
#define ASTERISM_LOG_H_

typedef enum
{
    ASTERISM_LOG_DEBUG,
    ASTERISM_LOG_INFO,
    ASTERISM_LOG_WARN,
    ASTERISM_LOG_ERROR
} asterism_log_level;

void asterism_log_init();

void asterism_set_log_level(
    asterism_log_level level);

void _asterism_log(
    asterism_log_level level,
    const char *fun,
    const char *fmt,
    ...);

#define __log_symx(l) #l
#define __log_sym(l) __log_symx(l)
#define __log_sym__ __FILE__ "(" __log_sym(__LINE__) ")"

#define asterism_log(level, fmt, ...) \
    _asterism_log(level, __log_sym__, fmt, ##__VA_ARGS__);

#endif
