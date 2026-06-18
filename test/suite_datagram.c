#include "test_framework.h"
#include "test_utils.h"
#include "asterism_core.h"
#include "asterism_datagram.h"
#include "asterism_utils.h"

static int g_close_cb_called;
static void recording_close_cb(uv_handle_t *handle) {
    (void)handle;
    g_close_cb_called++;
}

/* asterism_datagram_init rejects every missing dependency. */
static void test_datagram_init_guards(void) {
    struct asterism_datagram_s d;
    memset(&d, 0, sizeof(d));
    struct asterism_s as;
    memset(&as, 0, sizeof(as));

    /* NULL as */
    EXPECT_EQ(asterism_datagram_init(NULL, NULL, NULL, recording_close_cb, &d), ASTERISM_E_INVALID_ARGS);
    /* as with NULL loop */
    EXPECT_EQ(asterism_datagram_init(&as, NULL, NULL, recording_close_cb, &d), ASTERISM_E_INVALID_ARGS);

    as.loop = uv_loop_new();
    EXPECT_TRUE(as.loop != NULL);
    QUEUE_INIT(&as.udp_conns_queue);
    /* NULL datagram */
    EXPECT_EQ(asterism_datagram_init(&as, NULL, NULL, recording_close_cb, NULL), ASTERISM_E_INVALID_ARGS);
    /* NULL close_cb */
    EXPECT_EQ(asterism_datagram_init(&as, NULL, NULL, NULL, &d), ASTERISM_E_INVALID_ARGS);

    /* none of the guard failures created a handle, so the loop is empty */
    uv_loop_delete(as.loop);
}

/* The deferred-free contract: a datagram closed while a cross-stream write is
   still in flight must not be freed until write_unref drops the count to 0. */
static void test_datagram_refcount_lifecycle(void) {
    struct asterism_s as;
    memset(&as, 0, sizeof(as));
    as.loop = uv_loop_new();
    EXPECT_TRUE(as.loop != NULL);
    QUEUE_INIT(&as.udp_conns_queue);

    struct asterism_datagram_s *d = AS_ZMALLOC(struct asterism_datagram_s);
    EXPECT_TRUE(d != NULL);
    g_close_cb_called = 0;
    EXPECT_EQ(asterism_datagram_init(&as, NULL, NULL, recording_close_cb, d), 0);

    /* simulate an in-flight cross-stream write holding a back-pointer */
    asterism_datagram_write_ref(d);
    asterism_datagram_write_ref(d);
    EXPECT_EQ(d->pending_writes, 2);
    EXPECT_FALSE(asterism_datagram_is_closing(d));

    /* close the uv handle; its callback marks closing but must NOT free yet */
    asterism_datagram_close((uv_handle_t *)&d->socket);
    uv_run(as.loop, UV_RUN_DEFAULT);
    EXPECT_EQ(g_close_cb_called, 1);
    EXPECT_TRUE(asterism_datagram_is_closing(d));

    /* first unref: still one writer outstanding -> not freed */
    asterism_datagram_write_unref(d);
    EXPECT_EQ(d->pending_writes, 1);
    /* last unref: frees the struct (ASan/LSan verifies exactly one free, no UAF) */
    asterism_datagram_write_unref(d);

    uv_loop_delete(as.loop);
}

/* Closing with no outstanding writes frees immediately in the close callback. */
static void test_datagram_close_no_pending(void) {
    struct asterism_s as;
    memset(&as, 0, sizeof(as));
    as.loop = uv_loop_new();
    EXPECT_TRUE(as.loop != NULL);
    QUEUE_INIT(&as.udp_conns_queue);

    struct asterism_datagram_s *d = AS_ZMALLOC(struct asterism_datagram_s);
    EXPECT_TRUE(d != NULL);
    EXPECT_EQ(asterism_datagram_init(&as, NULL, NULL, recording_close_cb, d), 0);

    /* idempotent close guard: a second close while already closing is a no-op */
    asterism_datagram_close((uv_handle_t *)&d->socket);
    asterism_datagram_close((uv_handle_t *)&d->socket);
    uv_run(as.loop, UV_RUN_DEFAULT);

    uv_loop_delete(as.loop);
}

static void test_datagram_write(void) {
    struct asterism_s as;
    memset(&as, 0, sizeof(as));
    as.loop = uv_loop_new();
    EXPECT_TRUE(as.loop != NULL);
    QUEUE_INIT(&as.udp_conns_queue);

    struct asterism_datagram_s *d = AS_ZMALLOC(struct asterism_datagram_s);
    EXPECT_TRUE(d != NULL);
    EXPECT_EQ(asterism_datagram_init(&as, NULL, NULL, recording_close_cb, d), 0);

    struct sockaddr_in peer;
    EXPECT_EQ(uv_ip4_addr("127.0.0.1", 9, &peer), 0);
    char payload[4] = {'a', 'b', 'c', 0};
    uv_buf_t buf = uv_buf_init(payload, 3);

    /* OOM on the send-request allocation (1st AS_MALLOC) */
    asterism_test_set_alloc_fail(1);
    EXPECT_EQ(asterism_datagram_write(d, &buf, (const struct sockaddr *)&peer), ASTERISM_E_FAILED);
    asterism_test_reset_alloc_fail();

    /* OOM on the payload copy (2nd AS_MALLOC): request is released, no leak */
    asterism_test_set_alloc_fail(2);
    EXPECT_EQ(asterism_datagram_write(d, &buf, (const struct sockaddr *)&peer), ASTERISM_E_FAILED);
    asterism_test_reset_alloc_fail();

    /* success: send is queued and returns 0 */
    EXPECT_EQ(asterism_datagram_write(d, &buf, (const struct sockaddr *)&peer), 0);

    /* close and drain: the queued send completes/cancels (freeing its request)
       and the datagram is freed once closing. */
    asterism_datagram_close((uv_handle_t *)&d->socket);
    uv_run(as.loop, UV_RUN_DEFAULT);

    uv_loop_delete(as.loop);
}

void register_suite_datagram(void) {
    register_test("Datagram", "InitGuards", test_datagram_init_guards);
    register_test("Datagram", "RefcountLifecycle", test_datagram_refcount_lifecycle);
    register_test("Datagram", "CloseNoPending", test_datagram_close_no_pending);
    register_test("Datagram", "Write", test_datagram_write);
}
