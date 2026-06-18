#include "test_framework.h"
#include "asterism.h"
#include "asterism_core.h"
#include "asterism_utils.h"

/* Reach into the opaque handle to confirm options actually land in the struct. */
#define AS(a) ((struct asterism_s *)(a))

static char *dummy_redirect_hook(char *target_addr, void *data) {
    (void)target_addr;
    (void)data;
    return NULL;
}

static void test_options_errno_description(void) {
    /* Every mapped code returns its non-empty description. */
    EXPECT_STR_EQ(asterism_errno_description(ASTERISM_E_OK), "success");
    EXPECT_STR_EQ(asterism_errno_description(ASTERISM_E_FAILED), "failed");
    EXPECT_STR_EQ(asterism_errno_description(ASTERISM_E_INVALID_ARGS), "invalid arguments");
    EXPECT_STR_EQ(asterism_errno_description(ASTERISM_E_SOCKET_LISTEN_ERROR), "socket listen error");
    for (int code = ASTERISM_E_OK; code <= ASTERISM_E_SOCKET_LISTEN_ERROR; code++) {
        const char *d = asterism_errno_description((asterism_errno)code);
        EXPECT_TRUE(d != NULL && d[0] != 0);
    }
    /* Out of range (both ends) -> "unknown error". */
    EXPECT_STR_EQ(asterism_errno_description((asterism_errno)-1), "unknown error");
    EXPECT_STR_EQ(asterism_errno_description((asterism_errno)999), "unknown error");
}

static void test_options_lifecycle_api(void) {
    asterism a = asterism_create();
    EXPECT_TRUE(a != NULL);
    asterism_destroy(a);

    /* Tolerate NULL. */
    asterism_destroy(NULL);

    EXPECT_TRUE(asterism_version() != NULL);
    EXPECT_TRUE(asterism_version()[0] != 0);

    void *p = asterism_alloc(32);
    EXPECT_TRUE(p != NULL);
    memset(p, 0, 32);
    asterism_free(p);
    asterism_free(NULL);
}

static void test_options_setters_success(void) {
    asterism a = asterism_create();
    EXPECT_TRUE(a != NULL);
    if (!a) return;

    EXPECT_EQ(asterism_set_option(a, ASTERISM_OPT_INNER_BIND_ADDR, "http://127.0.0.1:1080"), ASTERISM_E_OK);
    EXPECT_TRUE(AS(a)->inner_bind_addrs != NULL);
    EXPECT_STR_EQ(AS(a)->inner_bind_addrs->data, "http://127.0.0.1:1080");
    /* a second inner bind address appends to the list */
    EXPECT_EQ(asterism_set_option(a, ASTERISM_OPT_INNER_BIND_ADDR, "socks5://127.0.0.1:1081"), ASTERISM_E_OK);
    EXPECT_TRUE(AS(a)->inner_bind_addrs->next != NULL);

    EXPECT_EQ(asterism_set_option(a, ASTERISM_OPT_OUTER_BIND_ADDR, "tcp://0.0.0.0:9000"), ASTERISM_E_OK);
    EXPECT_STR_EQ(AS(a)->outer_bind_addr, "tcp://0.0.0.0:9000");
    /* setting it again frees the old value and replaces it */
    EXPECT_EQ(asterism_set_option(a, ASTERISM_OPT_OUTER_BIND_ADDR, "tcp://0.0.0.0:9001"), ASTERISM_E_OK);
    EXPECT_STR_EQ(AS(a)->outer_bind_addr, "tcp://0.0.0.0:9001");

    EXPECT_EQ(asterism_set_option(a, ASTERISM_OPT_CONNECT_ADDR, "tcp://1.2.3.4:9000"), ASTERISM_E_OK);
    EXPECT_STR_EQ(AS(a)->connect_addr, "tcp://1.2.3.4:9000");

    EXPECT_EQ(asterism_set_option(a, ASTERISM_OPT_USERNAME, "user"), ASTERISM_E_OK);
    EXPECT_STR_EQ(AS(a)->username, "user");
    EXPECT_EQ(asterism_set_option(a, ASTERISM_OPT_PASSWORD, "pass"), ASTERISM_E_OK);
    EXPECT_STR_EQ(AS(a)->password, "pass");

    EXPECT_EQ(asterism_set_option(a, ASTERISM_OPT_IDLE_TIMEOUT, 123u), ASTERISM_E_OK);
    EXPECT_EQ(AS(a)->idle_timeout, 123);
    EXPECT_EQ(AS(a)->idle_timeout_set, 1);

    EXPECT_EQ(asterism_set_option(a, ASTERISM_OPT_HEARTBEAT_INTERVAL, 456u), ASTERISM_E_OK);
    EXPECT_EQ(AS(a)->heartbeat_interval, 456);
    EXPECT_EQ(asterism_set_option(a, ASTERISM_OPT_RECONNECT_DELAY, 789u), ASTERISM_E_OK);
    EXPECT_EQ(AS(a)->reconnect_delay, 789);

    EXPECT_EQ(asterism_set_option(a, ASTERISM_OPT_SOCKS5_UDP, 1u), ASTERISM_E_OK);
    EXPECT_EQ(AS(a)->socks5_udp, 1);
    EXPECT_EQ(asterism_set_option(a, ASTERISM_OPT_UDP_IDLE_TIMEOUT, 99u), ASTERISM_E_OK);
    EXPECT_EQ(AS(a)->udp_idle_timeout, 99);
    EXPECT_EQ(AS(a)->udp_idle_timeout_set, 1);

    /* SESSION_AUTH maps a truthy value to AUTH_REQUIRED and 0 to PUBLIC. */
    EXPECT_EQ(asterism_set_option(a, ASTERISM_OPT_SESSION_AUTH, 1u), ASTERISM_E_OK);
    EXPECT_EQ(AS(a)->session_policy, ASTERISM_SESSION_POLICY_AUTH_REQUIRED);
    EXPECT_EQ(asterism_set_option(a, ASTERISM_OPT_SESSION_AUTH, 0u), ASTERISM_E_OK);
    EXPECT_EQ(AS(a)->session_policy, ASTERISM_SESSION_POLICY_PUBLIC);

    EXPECT_EQ(asterism_set_option(a, ASTERISM_OPT_SESSION_AUTH_USER, "admin"), ASTERISM_E_OK);
    EXPECT_STR_EQ(AS(a)->session_auth_user, "admin");
    EXPECT_EQ(asterism_set_option(a, ASTERISM_OPT_SESSION_AUTH_PASS, "secret"), ASTERISM_E_OK);
    EXPECT_STR_EQ(AS(a)->session_auth_pass, "secret");

    EXPECT_EQ(asterism_set_option(a, ASTERISM_OPT_CONNECT_REDIRECT_HOOK, dummy_redirect_hook), ASTERISM_E_OK);
    EXPECT_TRUE(AS(a)->connect_redirect_hook_cb == dummy_redirect_hook);
    int hook_ctx = 0;
    EXPECT_EQ(asterism_set_option(a, ASTERISM_OPT_CONNECT_REDIRECT_HOOK_DATA, &hook_ctx), ASTERISM_E_OK);
    EXPECT_TRUE(AS(a)->connect_redirect_hook_data == &hook_ctx);

    /* SESSION_POLICY accepts each of the three valid values. */
    EXPECT_EQ(asterism_set_option(a, ASTERISM_OPT_SESSION_POLICY, ASTERISM_SESSION_POLICY_DISABLED), ASTERISM_E_OK);
    EXPECT_EQ(AS(a)->session_policy, ASTERISM_SESSION_POLICY_DISABLED);
    EXPECT_EQ(asterism_set_option(a, ASTERISM_OPT_SESSION_POLICY, ASTERISM_SESSION_POLICY_PUBLIC), ASTERISM_E_OK);
    EXPECT_EQ(asterism_set_option(a, ASTERISM_OPT_SESSION_POLICY, ASTERISM_SESSION_POLICY_AUTH_REQUIRED), ASTERISM_E_OK);

    /* PORTAL with a valid rule appends a config node. */
    EXPECT_EQ(asterism_set_option(a, ASTERISM_OPT_PORTAL, "0.0.0.0:1080#1.1.1.1:8080#8.8.8.8:53"), ASTERISM_E_OK);
    EXPECT_TRUE(AS(a)->portal_configs != NULL);

    asterism_destroy(a);
}

static void test_options_guards(void) {
    asterism a = asterism_create();
    EXPECT_TRUE(a != NULL);
    if (!a) return;

    char long_str[ASTREISM_USERNAME_MAX_LEN + 8];
    memset(long_str, 'x', sizeof(long_str) - 1);
    long_str[sizeof(long_str) - 1] = 0;

    /* NULL string arguments */
    EXPECT_EQ(asterism_set_option(a, ASTERISM_OPT_INNER_BIND_ADDR, (const char *)NULL), ASTERISM_E_INVALID_ARGS);
    EXPECT_EQ(asterism_set_option(a, ASTERISM_OPT_OUTER_BIND_ADDR, (const char *)NULL), ASTERISM_E_INVALID_ARGS);
    EXPECT_EQ(asterism_set_option(a, ASTERISM_OPT_CONNECT_ADDR, (const char *)NULL), ASTERISM_E_INVALID_ARGS);
    EXPECT_EQ(asterism_set_option(a, ASTERISM_OPT_USERNAME, (const char *)NULL), ASTERISM_E_INVALID_ARGS);
    EXPECT_EQ(asterism_set_option(a, ASTERISM_OPT_PASSWORD, (const char *)NULL), ASTERISM_E_INVALID_ARGS);
    EXPECT_EQ(asterism_set_option(a, ASTERISM_OPT_SESSION_AUTH_USER, (const char *)NULL), ASTERISM_E_INVALID_ARGS);
    EXPECT_EQ(asterism_set_option(a, ASTERISM_OPT_SESSION_AUTH_PASS, (const char *)NULL), ASTERISM_E_INVALID_ARGS);
    EXPECT_EQ(asterism_set_option(a, ASTERISM_OPT_PORTAL, (const char *)NULL), ASTERISM_E_INVALID_ARGS);

    /* empty (len 0) credentials */
    EXPECT_EQ(asterism_set_option(a, ASTERISM_OPT_USERNAME, ""), ASTERISM_E_INVALID_ARGS);
    EXPECT_EQ(asterism_set_option(a, ASTERISM_OPT_PASSWORD, ""), ASTERISM_E_INVALID_ARGS);
    EXPECT_EQ(asterism_set_option(a, ASTERISM_OPT_SESSION_AUTH_USER, ""), ASTERISM_E_INVALID_ARGS);
    EXPECT_EQ(asterism_set_option(a, ASTERISM_OPT_SESSION_AUTH_PASS, ""), ASTERISM_E_INVALID_ARGS);

    /* over-length credentials */
    EXPECT_EQ(asterism_set_option(a, ASTERISM_OPT_USERNAME, long_str), ASTERISM_E_INVALID_ARGS);
    EXPECT_EQ(asterism_set_option(a, ASTERISM_OPT_PASSWORD, long_str), ASTERISM_E_INVALID_ARGS);
    EXPECT_EQ(asterism_set_option(a, ASTERISM_OPT_SESSION_AUTH_USER, long_str), ASTERISM_E_INVALID_ARGS);
    EXPECT_EQ(asterism_set_option(a, ASTERISM_OPT_SESSION_AUTH_PASS, long_str), ASTERISM_E_INVALID_ARGS);

    /* malformed portal rule (no '#') */
    EXPECT_EQ(asterism_set_option(a, ASTERISM_OPT_PORTAL, "not-a-rule"), ASTERISM_E_INVALID_ARGS);

    /* invalid session policy value */
    EXPECT_EQ(asterism_set_option(a, ASTERISM_OPT_SESSION_POLICY, 99), ASTERISM_E_INVALID_ARGS);

    /* unknown option id falls into the default arm */
    EXPECT_EQ(asterism_set_option(a, (asterism_option)9999, 0), ASTERISM_E_INVALID_ARGS);

    /* NULL handle */
    EXPECT_EQ(asterism_set_option(NULL, ASTERISM_OPT_IDLE_TIMEOUT, 1u), ASTERISM_E_INVALID_ARGS);

    asterism_destroy(a);
}

static void test_options_oom(void) {
    asterism a = asterism_create();
    EXPECT_TRUE(a != NULL);
    if (!a) return;

    /* Each string/struct duplicate inside set_option fails -> E_FAILED, and the
       existing field is left untouched (no leak; verified under ASan/LSan). */
    asterism_test_set_alloc_fail(1);
    EXPECT_EQ(asterism_set_option(a, ASTERISM_OPT_INNER_BIND_ADDR, "http://127.0.0.1:1"), ASTERISM_E_FAILED);
    asterism_test_reset_alloc_fail();

    asterism_test_set_alloc_fail(1);
    EXPECT_EQ(asterism_set_option(a, ASTERISM_OPT_OUTER_BIND_ADDR, "tcp://127.0.0.1:1"), ASTERISM_E_FAILED);
    asterism_test_reset_alloc_fail();

    asterism_test_set_alloc_fail(1);
    EXPECT_EQ(asterism_set_option(a, ASTERISM_OPT_CONNECT_ADDR, "tcp://127.0.0.1:1"), ASTERISM_E_FAILED);
    asterism_test_reset_alloc_fail();

    asterism_test_set_alloc_fail(1);
    EXPECT_EQ(asterism_set_option(a, ASTERISM_OPT_USERNAME, "user"), ASTERISM_E_FAILED);
    asterism_test_reset_alloc_fail();

    asterism_test_set_alloc_fail(1);
    EXPECT_EQ(asterism_set_option(a, ASTERISM_OPT_PASSWORD, "pass"), ASTERISM_E_FAILED);
    asterism_test_reset_alloc_fail();

    asterism_test_set_alloc_fail(1);
    EXPECT_EQ(asterism_set_option(a, ASTERISM_OPT_SESSION_AUTH_USER, "admin"), ASTERISM_E_FAILED);
    asterism_test_reset_alloc_fail();

    asterism_test_set_alloc_fail(1);
    EXPECT_EQ(asterism_set_option(a, ASTERISM_OPT_SESSION_AUTH_PASS, "secret"), ASTERISM_E_FAILED);
    asterism_test_reset_alloc_fail();

    /* PORTAL: the config-list node allocation is the first AS_MALLOC. */
    asterism_test_set_alloc_fail(1);
    EXPECT_EQ(asterism_set_option(a, ASTERISM_OPT_PORTAL, "0.0.0.0:1080#1.1.1.1:8080#8.8.8.8:53"), ASTERISM_E_FAILED);
    asterism_test_reset_alloc_fail();

    EXPECT_TRUE(AS(a)->inner_bind_addrs == NULL);
    EXPECT_TRUE(AS(a)->outer_bind_addr == NULL);
    EXPECT_TRUE(AS(a)->connect_addr == NULL);
    EXPECT_TRUE(AS(a)->username == NULL);
    EXPECT_TRUE(AS(a)->portal_configs == NULL);

    asterism_destroy(a);
}

void register_suite_options(void) {
    register_test("Options", "ErrnoDescription", test_options_errno_description);
    register_test("Options", "LifecycleAPI", test_options_lifecycle_api);
    register_test("Options", "SettersSuccess", test_options_setters_success);
    register_test("Options", "Guards", test_options_guards);
    register_test("Options", "OOM", test_options_oom);
}
