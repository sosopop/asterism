#include "asterism.h"
#include "asterism_core.h"
#include "asterism_log.h"
#include "asterism_portal.h"
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
    if ((int)error < 0 || (size_t)error >= __ARRAY_SIZE(asterism_strerror_tab))
        return "unknown error";
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
    if (!as)
        return;
    asterism_log(ASTERISM_LOG_DEBUG, "%s", "asterism_destroy");
    struct asterism_s *__as = (struct asterism_s *)as;
    asterism_core_destory(__as);
}

int asterism_set_option(asterism as, asterism_option opt, ...)
{
    if (!as)
        return ASTERISM_E_INVALID_ARGS;

    int ret = ASTERISM_E_OK;
    struct asterism_s *__as = (struct asterism_s *)as;
    va_list ap;
    va_start(ap, opt);

    switch (opt)
    {
    case ASTERISM_OPT_INNER_BIND_ADDR:
    {
        const char *addr = va_arg(ap, const char *);
        if (!addr) {
            ret = ASTERISM_E_INVALID_ARGS;
            break;
        }
        struct asterism_slist *new_list = asterism_slist_append(__as->inner_bind_addrs, addr);
        if (!new_list) {
            ret = ASTERISM_E_FAILED;
            break;
        }
        __as->inner_bind_addrs = new_list;
        break;
    }
    case ASTERISM_OPT_OUTER_BIND_ADDR:
    {
        const char *addr = va_arg(ap, const char *);
        if (!addr) {
            ret = ASTERISM_E_INVALID_ARGS;
            break;
        }
        char *new_addr = as_strdup(addr);
        if (!new_addr) {
            ret = ASTERISM_E_FAILED;
            break;
        }
        AS_SFREE(__as->outer_bind_addr);
        __as->outer_bind_addr = new_addr;
        break;
    }
    case ASTERISM_OPT_CONNECT_ADDR:
    {
        const char *addr = va_arg(ap, const char *);
        if (!addr) {
            ret = ASTERISM_E_INVALID_ARGS;
            break;
        }
        char *new_addr = as_strdup(addr);
        if (!new_addr) {
            ret = ASTERISM_E_FAILED;
            break;
        }
        AS_SFREE(__as->connect_addr);
        __as->connect_addr = new_addr;
        break;
    }
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
        if (!username) {
            ret = ASTERISM_E_INVALID_ARGS;
            break;
        }
        size_t username_len = strlen(username);
        if (username_len > ASTREISM_USERNAME_MAX_LEN || username_len == 0)
        {
            ret = ASTERISM_E_INVALID_ARGS;
            break;
        }
        char *new_username = as_strdup(username);
        if (!new_username) {
            ret = ASTERISM_E_FAILED;
            break;
        }
        AS_SFREE(__as->username);
        __as->username = new_username;
    }
    break;
    case ASTERISM_OPT_PASSWORD:
    {
        const char *password = va_arg(ap, const char *);
        if (!password) {
            ret = ASTERISM_E_INVALID_ARGS;
            break;
        }
        size_t password_len = strlen(password);
        if (password_len > ASTREISM_PASSWORD_MAX_LEN || password_len == 0)
        {
            ret = ASTERISM_E_INVALID_ARGS;
            break;
        }
        char *new_password = as_strdup(password);
        if (!new_password) {
            ret = ASTERISM_E_FAILED;
            break;
        }
        AS_SFREE(__as->password);
        __as->password = new_password;
    }
    break;
    case ASTERISM_OPT_CONNECT_REDIRECT_HOOK:
        __as->connect_redirect_hook_cb = va_arg(ap, asterism_connnect_redirect_hook);
        break;
    case ASTERISM_OPT_CONNECT_REDIRECT_HOOK_DATA:
        __as->connect_redirect_hook_data = va_arg(ap, void *);
        break;
    case ASTERISM_OPT_SOCKS5_UDP:
        __as->socks5_udp = va_arg(ap, unsigned int);
        break;
    case ASTERISM_OPT_UDP_IDLE_TIMEOUT:
        __as->udp_idle_timeout = va_arg(ap, unsigned int);
        break;
    case ASTERISM_OPT_SESSION_AUTH:
        __as->session_policy = va_arg(ap, unsigned int) ?
            ASTERISM_SESSION_POLICY_AUTH_REQUIRED : ASTERISM_SESSION_POLICY_PUBLIC;
        break;
    case ASTERISM_OPT_SESSION_AUTH_USER:
    {
        const char *username = va_arg(ap, const char *);
        if (!username) {
            ret = ASTERISM_E_INVALID_ARGS;
            break;
        }
        size_t username_len = strlen(username);
        if (username_len > ASTREISM_USERNAME_MAX_LEN || username_len == 0)
        {
            ret = ASTERISM_E_INVALID_ARGS;
            break;
        }
        char *new_username = as_strdup(username);
        if (!new_username) {
            ret = ASTERISM_E_FAILED;
            break;
        }
        AS_SFREE(__as->session_auth_user);
        __as->session_auth_user = new_username;
    }
    break;
    case ASTERISM_OPT_SESSION_AUTH_PASS:
    {
        const char *password = va_arg(ap, const char *);
        if (!password) {
            ret = ASTERISM_E_INVALID_ARGS;
            break;
        }
        size_t password_len = strlen(password);
        if (password_len > ASTREISM_PASSWORD_MAX_LEN || password_len == 0)
        {
            ret = ASTERISM_E_INVALID_ARGS;
            break;
        }
        char *new_password = as_strdup(password);
        if (!new_password) {
            ret = ASTERISM_E_FAILED;
            break;
        }
        AS_SFREE(__as->session_auth_pass);
        __as->session_auth_pass = new_password;
    }
    break;
    case ASTERISM_OPT_PORTAL:
    {
        const char *rule_str = va_arg(ap, const char *);
        if (!rule_str) {
            ret = ASTERISM_E_INVALID_ARGS;
            break;
        }
        struct asterism_portal_config_list_s *node = AS_ZMALLOC(struct asterism_portal_config_list_s);
        if (!node) {
            ret = ASTERISM_E_FAILED;
            break;
        }
        if (asterism_portal_parse_rule(rule_str, &node->config) != 0) {
            AS_FREE(node);
            ret = ASTERISM_E_INVALID_ARGS;
            break;
        }
        node->next = __as->portal_configs;
        __as->portal_configs = node;
    }
    break;
    case ASTERISM_OPT_SESSION_POLICY:
    {
        asterism_session_policy policy = (asterism_session_policy)va_arg(ap, int);
        if (policy != ASTERISM_SESSION_POLICY_AUTH_REQUIRED &&
            policy != ASTERISM_SESSION_POLICY_PUBLIC &&
            policy != ASTERISM_SESSION_POLICY_DISABLED) {
            ret = ASTERISM_E_INVALID_ARGS;
            break;
        }
        __as->session_policy = policy;
    }
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
    if (!as)
        return ASTERISM_E_INVALID_ARGS;
    return asterism_core_run((struct asterism_s *)as);
}

int asterism_stop(asterism as)
{
    if (!as)
        return ASTERISM_E_INVALID_ARGS;
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
