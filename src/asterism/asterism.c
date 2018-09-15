#include "asterism.h"
#include "asterism_internal.h"
#include "asterism_log.h"

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
    return (asterism)malloc(sizeof(struct asterism_s));
}

void asterism_destroy(asterism as)
{
    asterism_log(ASTERISM_LOG_DEBUG, "%s", "asterism_destroy");
    free(as);
}

int asterism_set_option(asterism as, asterism_option opt, ...)
{
    int ret = ASTERISM_E_OK;
    struct asterism_s *__as = (struct asterism_s *)as;
    va_list ap;
    va_start(ap, opt);

    switch (opt)
    {
    default:
        ret = ASTERISM_E_INVALID_ARGS;
        break;
    }
    va_end(ap);
    return ret;
}

int asterism_get_info(asterism as, asterism_info info, ...)
{
    int ret = ASTERISM_E_OK;
    struct asterism_s *__as = (struct asterism_s *)as;

    va_list ap;
    va_start(ap, info);

    switch (info)
    {
    case ASTERISM_INFO_DUMMY:
    {
        *va_arg(ap, const char **) = "test";
        goto cleanup;
    }
    break;
    default:
        ret = ASTERISM_E_INVALID_ARGS;
        break;
    }
cleanup:
    va_end(ap);
    return ret;
}