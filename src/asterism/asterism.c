#include "asterism.h"
#include "asterism_core.h"
#include "asterism_log.h"
#include <string.h>
#include "asterism_core.h"
#include "asterism_utils.h"
#include "asterism_stream.h"

#define ASTERISM_ERROR_GEN(n, s) {"ASTERISM_E_" #n, s},
static struct
{
    const char *name;
    const char *description;
} asterism_strerror_tab[] = {ASTERISM_ERROR_MAP(ASTERISM_ERROR_GEN)};
#undef ASTERISM_ERROR_GEN

const char *asterism_errno_description(
    asterism_errno error)
{
    return asterism_strerror_tab[error].description;
}

const char *asterism_version()
{
    return ASTERISM_VERSION;
}

asterism asterism_create()
{
    asterism_log(ASTERISM_LOG_DEBUG, "%s", "asterism_create");
    return (asterism)AS_ZMALLOC(struct asterism_s);
}

void asterism_destroy(asterism as)
{
    asterism_log(ASTERISM_LOG_DEBUG, "%s", "asterism_destroy");
    struct asterism_s *__as = (struct asterism_s *)as;
    asterism_core_destory(__as);
}

int asterism_set_option(asterism as, asterism_option opt, ...)
{
    int ret = ASTERISM_E_OK;
    struct asterism_s *__as = (struct asterism_s *)as;
    va_list ap;
    va_start(ap, opt);

    switch (opt)
    {
    case ASTERISM_OPT_INNER_BIND_ADDR:
        __as->inner_bind_addrs = asterism_slist_append(__as->inner_bind_addrs,
            va_arg(ap, const char *));
        break;
    case ASTERISM_OPT_OUTER_BIND_ADDR:
        if (__as->outer_bind_addr)
            free(__as->outer_bind_addr);
        __as->outer_bind_addr = as_strdup(va_arg(ap, const char *));
        break;
    case ASTERISM_OPT_CONNECT_ADDR:
        if (__as->connect_addr)
            free(__as->connect_addr);
        __as->connect_addr = as_strdup(va_arg(ap, const char *));
        break;
    case ASTERISM_OPT_IDLE_TIMEOUT:
        __as->idle_timeout = va_arg(ap, unsigned int);
        break;
    case ASTERISM_OPT_RECONNECT_DELAY:
        __as->reconnect_delay = va_arg(ap, unsigned int);
        break;
    case ASTERISM_OPT_HEARTBEAT_INTERVAL:
        __as->heartbeart_interval = va_arg(ap, unsigned int);
        break;
    case ASTERISM_OPT_USERNAME:
    {
        const char *username = va_arg(ap, const char *);
        size_t username_len = strlen(username);
        if (username_len > ASTREISM_USERNAME_MAX_LEN || username_len == 0)
        {
            ret = ASTERISM_E_INVALID_ARGS;
            break;
        }
        if (__as->username)
            free(__as->username);
        __as->username = as_strdup(username);
    }
    break;
    case ASTERISM_OPT_PASSWORD:
    {
        const char *password = va_arg(ap, const char *);
        size_t password_len = strlen(password);
        if (password_len > ASTREISM_PASSWORD_MAX_LEN || password_len == 0)
        {
            ret = ASTERISM_E_INVALID_ARGS;
            break;
        }
        if (__as->password)
            free(__as->password);
        __as->password = as_strdup(password);
    }
    break;
    case ASTERISM_OPT_CONNECT_REDIRECT_HOOK:
        __as->connect_redirect_hook_cb = va_arg(ap, asterism_connnect_redirect_hook);
        break;
    case ASTERISM_OPT_CONNECT_REDIRECT_HOOK_DATA:
        __as->connect_redirect_hook_data = va_arg(ap, void *);
        break;
    default:
        ret = ASTERISM_E_INVALID_ARGS;
        break;
    }
    va_end(ap);
    return ret;
}


int asterism_run(asterism as)
{
    return asterism_core_run((struct asterism_s *)as);
}

int asterism_stop(asterism as)
{
    return asterism_core_stop((struct asterism_s *)as);
}

void *asterism_alloc(unsigned int size)
{
    return AS_MALLOC(size);
}

void asterism_free(void *data)
{
    AS_FREE(data);
}