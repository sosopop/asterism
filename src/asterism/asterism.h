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

    typedef enum
    {
        ASTERISM_LOG_DEBUG,
        ASTERISM_LOG_INFO,
        ASTERISM_LOG_WARN,
        ASTERISM_LOG_ERROR
    } asterism_log_level;

    void asterism_set_log_level(
        asterism_log_level level);

#define ASTERISM_ERROR_MAP(XX)                       \
    XX(OK, "success")                                \
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
        ASTERISM_OPT_HTTP_INNER_LISTEN_ADDR = 0,
        ASTERISM_OPT_TCP_OUTER_LISTEN_ADDR,
        ASTERISM_OPT_CONNECT_ADDR,
        ASTERISM_OPT_MY_USERNAME,
        ASTERISM_OPT_MY_PASSWORD,
        ASTERISM_OPT_ROUTE_LIST
    } asterism_option;

    typedef enum
    {
        ASTERISM_INFO_DUMMY = 0,
    } asterism_info;

    struct asterism_slist
    {
        char *data;
        struct asterism_slist *next;
    };

    asterism asterism_create();

    void asterism_destroy(asterism as);

    int asterism_set_option(asterism as, asterism_option opt, ...);

    int asterism_get_info(asterism as, asterism_info info, ...);

    int asterism_prepare(asterism as);

    int asterism_run(asterism as);

    int asterism_stop(asterism as);

    void asterism_free(void *data);

    void asterism_slist_free_all(struct asterism_slist *list);

    struct asterism_slist *asterism_slist_append(struct asterism_slist *list, const char *data);

    const char *asterism_errno_description(
        asterism_errno error);

    const char *asterism_version();

#ifdef __cplusplus
}
#endif
#endif