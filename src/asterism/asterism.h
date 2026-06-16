#ifndef ASTERISM_H_
#define ASTERISM_H_

#if defined(_WIN32)
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
        ASTERISM_LOG_ERROR,
        ASTERISM_LOG_NULL
    } asterism_log_level;

    typedef enum
    {
        ASTERISM_SESSION_POLICY_AUTH_REQUIRED = 0,
        ASTERISM_SESSION_POLICY_PUBLIC = 1,
        ASTERISM_SESSION_POLICY_DISABLED = 2,
    } asterism_session_policy;

    /**
     * @brief set log level
     */
    void asterism_set_log_level(
        asterism_log_level level);

#define ASTERISM_ERROR_MAP(XX)                          \
    XX(OK, "success")                                   \
    XX(FAILED, "failed")                                \
    XX(INVALID_ARGS, "invalid arguments")               \
    XX(OBJECT_ALREADY_EXIST, "object already exist")    \
    XX(OBJECT_NOT_EXIST, "object not exist")            \
    XX(ADDRESS_PARSE_ERROR, "address parse error")      \
    XX(USERPASS_EMPTY, "username or password is empty") \
    XX(PROTOCOL_NOT_SUPPORT, "protocol not support")    \
    XX(SOCKET_LISTEN_ERROR, "socket listen error")

#define ASTERISM_ERROR_GEN(n, s) ASTERISM_E_##n,
    typedef enum
    {
        ASTERISM_ERROR_MAP(ASTERISM_ERROR_GEN)
    } asterism_errno;
#undef ASTERISM_ERROR_GEN

    /**
     * @brief Used to redirect the connection request (for agent),
     *        return value must be allocated by asterism_alloc
     * @see ASTERISM_OPT_CONNECT_REDIRECT_HOOK
     * @see ASTERISM_OPT_CONNECT_REDIRECT_HOOK_DATA
     */
    typedef char *(*asterism_connnect_redirect_hook)(char *target_addr, void *data);

    /**
     * @brief Some basic option settings for service startup
     * @see asterism_set_option
     */
    typedef enum
    {
        /* Proxy listen address for client connections (for relay) */
        ASTERISM_OPT_INNER_BIND_ADDR = 0,
        /* Agent connection listen address (for relay) */
        ASTERISM_OPT_OUTER_BIND_ADDR,
        /* Relay address to connect to (for agent) */
        ASTERISM_OPT_CONNECT_ADDR,
        /* Agent authentication username (for agent) */
        ASTERISM_OPT_USERNAME,
        /* Agent authentication password (for agent) */
        ASTERISM_OPT_PASSWORD,
        /* Agent request redirect hook callback (for agent) */
        ASTERISM_OPT_CONNECT_REDIRECT_HOOK,
        /* Agent request redirect hook callback context (for agent) */
        ASTERISM_OPT_CONNECT_REDIRECT_HOOK_DATA,
        /* Idle timeout in seconds; connections with no data transfer will be closed */
        ASTERISM_OPT_IDLE_TIMEOUT,
        /* Heartbeat interval in milliseconds (for agent) */
        ASTERISM_OPT_HEARTBEAT_INTERVAL,
        /* Reconnection delay in milliseconds (for agent) */
        ASTERISM_OPT_RECONNECT_DELAY,
        /* Enable SOCKS5 UDP support (for relay) */
        ASTERISM_OPT_SOCKS5_UDP,
        /* Idle timeout for UDP sessions (for relay) */
        ASTERISM_OPT_UDP_IDLE_TIMEOUT,
        /* Enable authentication for session list HTTP GET /sessions (for relay) */
        ASTERISM_OPT_SESSION_AUTH,
        /* Username for session list authentication (for relay) */
        ASTERISM_OPT_SESSION_AUTH_USER,
        /* Password for session list authentication (for relay) */
        ASTERISM_OPT_SESSION_AUTH_PASS,
        /* Portal rule (format: local_addr:local_port#relay_addr#remote_addr:remote_port) */
        ASTERISM_OPT_PORTAL,
        /* Policy for HTTP GET /sessions on relay HTTP proxy address */
        ASTERISM_OPT_SESSION_POLICY,
    } asterism_option;

    /**
     * @brief create asterism object
     * 
     * @return asterism 
     */
    asterism asterism_create();

    /**
     * @brief destroy asterism object
     * 
     * @param as 
     */
    void asterism_destroy(
        asterism as);

    /**
     * @brief asterism option settings
     * 
     * @param as 
     * @param opt options 
     * @see asterism_option
     */
    int asterism_set_option(
        asterism as,
        asterism_option opt,
        ...);

    /**
     * @brief Run asterism
     * 
     * @param as 
     * @return int 
     */
    int asterism_run(
        asterism as);

    /**
     * @brief Stop asterism
     * 
     * @param as 
     * @return int 
     */
    int asterism_stop(
        asterism as);

    /**
     * @brief Allocate memory by asterism
     * 
     * @param size 
     * @return void* 
     */
    void *asterism_alloc(
        unsigned int size);

    /**
     * @brief Free memory allocated by asterism
     * 
     * @param data 
     */
    void asterism_free(
        void *data);

    /**
     * @brief Get error string
     * 
     * @param error 
     */
    const char *asterism_errno_description(
        asterism_errno error);

    /**
     * @brief Get version string
     * 
     * @return const char* 
     */
    const char *asterism_version();

#ifdef __cplusplus
}
#endif
#endif
