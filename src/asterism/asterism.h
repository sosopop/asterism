#ifndef ASTERISM_H_
#define ASTERISM_H_

#if defined(WIN32)
#if defined(ASTERISM_EXPORTS)
#ifdef __cplusplus
#define ASTERISM_EXPORT extern "C" __declspec(dllexport)
#else
#define ASTERISM_EXPORT __declspec(dllexport)
#endif
#else /* defined (ASTERISM_EXPORTS) */
#ifdef __cplusplus
#define ASTERISM_EXPORT extern "C"
#else
#define ASTERISM_EXPORT
#endif
#endif
#else /* defined (_WIN32) */
#if defined(ASTERISM_EXPORTS)
#ifdef __cplusplus
#define ASTERISM_EXPORT extern "C" __attribute__((visibility("default")))
#else
#define ASTERISM_EXPORT __attribute__((visibility("default")))
#endif
#else /* defined (ASTERISM_EXPORTS) */
#ifdef __cplusplus
#define ASTERISM_EXPORT extern "C"
#else
#define ASTERISM_EXPORT
#endif
#endif
#endif

#ifdef __cplusplus
extern "C"
{
#endif
    typedef void *asterism;

#define ASTERISM_ERROR_MAP(XX)                       \
    XX(OK, "success")                                \
    XX(UNKNOWN, "unknown error happened")            \
    XX(INVALID_ARGS, "invalid arguments")            \
    XX(OBJECT_ALREADY_EXIST, "object already exist") \
    XX(OBJECT_NOT_EXIST, "object not exist")

#define ASTERISM_ERROR_GEN(n, s) ASTERISM_E_##n,
    typedef enum
    {
        ASTERISM_ERROR_MAP(ASTERISM_ERROR_GEN)
    } asterism_errno;
#undef ASTERISM_ERROR_GEN

    typedef enum
    {
        ASTERISM_OPT_DUMMY = 0,
    } asterism_option;

    typedef enum
    {
        ASTERISM_INFO_DUMMY = 0,
    } asterism_info;

    asterism asterism_create();

    void asterism_destroy(asterism as);

    int asterism_set_option(asterism as, asterism_option opt, ...);

    int asterism_get_info(asterism as, asterism_info info, ...);

    int asterism_prepare(asterism as);

    int asterism_run(asterism as);

    int asterism_stop(asterism as);

    const char *asterism_errno_description(
        asterism_errno error);

    const char *asterism_version();

#ifdef __cplusplus
}
#endif
#endif