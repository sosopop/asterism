#include "test_framework.h"
#include "test_utils.h"
#include "asterism.h"
#include "asterism_core.h"

#define AS(a) ((struct asterism_s *)(a))

/* Non-static in asterism_core.c; used here to drain a prepared-but-not-run loop
   the same way asterism_core_run does on its error path. */
extern void handles_close_cb(uv_handle_t *handle, void *arg);

static void drain_and_destroy(struct asterism_s *as) {
    if (as->loop) {
        uv_walk(as->loop, handles_close_cb, as);
        uv_run(as->loop, UV_RUN_DEFAULT);
    }
    asterism_destroy((asterism)as);
}

static void expect_run_errno(asterism a, int expected) {
    EXPECT_TRUE(a != NULL);
    if (!a) return;
    EXPECT_EQ(asterism_run(a), expected);
    asterism_destroy(a);
}

/* prepare() with nothing configured succeeds and fills in the documented
   default timeouts/intervals; also exercises the check_timer creation tail. */
static void test_core_prepare_defaults(void) {
    asterism a = asterism_create();
    EXPECT_TRUE(a != NULL);
    if (!a) return;
    EXPECT_EQ(asterism_core_prepare(AS(a)), ASTERISM_E_OK);
    EXPECT_EQ(AS(a)->idle_timeout, ASTERISM_CONNECTION_MAX_IDLE_COUNT);
    EXPECT_EQ(AS(a)->udp_idle_timeout, ASTERISM_UDP_MAX_IDLE_COUNT);
    EXPECT_EQ(AS(a)->reconnect_delay, ASTERISM_RECONNECT_DELAY);
    EXPECT_EQ(AS(a)->heartbeat_interval, ASTERISM_HEARTBEAT_INTERVAL);
    EXPECT_TRUE(AS(a)->check_timer != NULL);
    drain_and_destroy(AS(a));
}

/* Explicit values (including an explicit 0 for the idle timeouts) survive
   prepare() instead of being overwritten by defaults. */
static void test_core_prepare_explicit_values(void) {
    asterism a = asterism_create();
    EXPECT_TRUE(a != NULL);
    if (!a) return;
    EXPECT_EQ(asterism_set_option(a, ASTERISM_OPT_IDLE_TIMEOUT, 0u), ASTERISM_E_OK);
    EXPECT_EQ(asterism_set_option(a, ASTERISM_OPT_UDP_IDLE_TIMEOUT, 0u), ASTERISM_E_OK);
    EXPECT_EQ(asterism_set_option(a, ASTERISM_OPT_RECONNECT_DELAY, 1234u), ASTERISM_E_OK);
    EXPECT_EQ(asterism_set_option(a, ASTERISM_OPT_HEARTBEAT_INTERVAL, 4321u), ASTERISM_E_OK);
    EXPECT_EQ(asterism_core_prepare(AS(a)), ASTERISM_E_OK);
    EXPECT_EQ(AS(a)->idle_timeout, 0);
    EXPECT_EQ(AS(a)->udp_idle_timeout, 0);
    EXPECT_EQ(AS(a)->reconnect_delay, 1234);
    EXPECT_EQ(AS(a)->heartbeat_interval, 4321);
    drain_and_destroy(AS(a));
}

static void test_core_prepare_error_matrix(void) {
    asterism a;

    /* inner: unparseable address */
    a = asterism_create();
    asterism_set_option(a, ASTERISM_OPT_INNER_BIND_ADDR, "garbage");
    expect_run_errno(a, ASTERISM_E_ADDRESS_PARSE_ERROR);

    /* inner: address with no scheme */
    a = asterism_create();
    asterism_set_option(a, ASTERISM_OPT_INNER_BIND_ADDR, "127.0.0.1:8080");
    expect_run_errno(a, ASTERISM_E_PROTOCOL_NOT_SUPPORT);

    /* inner: unsupported scheme */
    a = asterism_create();
    asterism_set_option(a, ASTERISM_OPT_INNER_BIND_ADDR, "ftp://127.0.0.1:8080");
    expect_run_errno(a, ASTERISM_E_PROTOCOL_NOT_SUPPORT);

    /* outer: non-tcp scheme */
    a = asterism_create();
    asterism_set_option(a, ASTERISM_OPT_OUTER_BIND_ADDR, "udp://127.0.0.1:8080");
    expect_run_errno(a, ASTERISM_E_PROTOCOL_NOT_SUPPORT);

    /* outer: unparseable address */
    a = asterism_create();
    asterism_set_option(a, ASTERISM_OPT_OUTER_BIND_ADDR, "garbage");
    expect_run_errno(a, ASTERISM_E_ADDRESS_PARSE_ERROR);

    /* connect: missing username/password */
    a = asterism_create();
    asterism_set_option(a, ASTERISM_OPT_CONNECT_ADDR, "tcp://127.0.0.1:8080");
    expect_run_errno(a, ASTERISM_E_USERPASS_EMPTY);

    /* connect: unparseable address */
    a = asterism_create();
    asterism_set_option(a, ASTERISM_OPT_USERNAME, "u");
    asterism_set_option(a, ASTERISM_OPT_PASSWORD, "p");
    asterism_set_option(a, ASTERISM_OPT_CONNECT_ADDR, "garbage");
    expect_run_errno(a, ASTERISM_E_ADDRESS_PARSE_ERROR);

    /* connect: non-tcp scheme */
    a = asterism_create();
    asterism_set_option(a, ASTERISM_OPT_USERNAME, "u");
    asterism_set_option(a, ASTERISM_OPT_PASSWORD, "p");
    asterism_set_option(a, ASTERISM_OPT_CONNECT_ADDR, "udp://127.0.0.1:8080");
    expect_run_errno(a, ASTERISM_E_PROTOCOL_NOT_SUPPORT);
}

/* prepare()'s check_timer allocation failing -> E_FAILED (OOM injection, fully
   synchronous so no event-loop thread sees the forced failure). */
static void test_core_prepare_oom(void) {
    asterism a = asterism_create();
    EXPECT_TRUE(a != NULL);
    if (!a) return;
    /* The only AS_MALLOC in a no-listener prepare() is the check_timer. */
    asterism_test_set_alloc_fail(1);
    int r = asterism_core_prepare(AS(a));
    asterism_test_reset_alloc_fail();
    EXPECT_EQ(r, ASTERISM_E_FAILED);
    drain_and_destroy(AS(a));
}

static void test_core_stop_guards(void) {
    /* stop before run: loop is still NULL -> INVALID_ARGS. */
    asterism a = asterism_create();
    EXPECT_TRUE(a != NULL);
    if (!a) return;
    EXPECT_EQ(asterism_stop(a), ASTERISM_E_INVALID_ARGS);
    asterism_destroy(a);

    EXPECT_EQ(asterism_stop(NULL), ASTERISM_E_INVALID_ARGS);
}

static void core_run_thread(void *arg) {
    asterism_run((asterism)arg);
}

/* Run a bare instance (only the check_timer keeps the loop alive) with both
   idle timeouts disabled, so check_timer_cb evaluates and skips both reaping
   blocks. Also exercises the async stop path and check_timer teardown. */
static void test_core_reaping_disabled(void) {
    asterism a = asterism_create();
    EXPECT_TRUE(a != NULL);
    if (!a) return;
    EXPECT_EQ(asterism_set_option(a, ASTERISM_OPT_IDLE_TIMEOUT, 0u), ASTERISM_E_OK);
    EXPECT_EQ(asterism_set_option(a, ASTERISM_OPT_UDP_IDLE_TIMEOUT, 0u), ASTERISM_E_OK);

    uv_thread_t t;
    EXPECT_EQ(uv_thread_create(&t, core_run_thread, a), 0);
    /* let the 1 Hz check timer fire at least once */
    test_sleep(1300);
    EXPECT_EQ(asterism_stop(a), 0);
    uv_thread_join(&t);
    asterism_destroy(a);
}

void register_suite_core(void) {
    register_test("Core", "PrepareDefaults", test_core_prepare_defaults);
    register_test("Core", "PrepareExplicitValues", test_core_prepare_explicit_values);
    register_test("Core", "PrepareErrorMatrix", test_core_prepare_error_matrix);
    register_test("Core", "PrepareOOM", test_core_prepare_oom);
    register_test("Core", "StopGuards", test_core_stop_guards);
    register_test("Core", "ReapingDisabled", test_core_reaping_disabled);
}
