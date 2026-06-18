#include "test_framework.h"
#include "test_utils.h"
#include "asterism_core.h"
#include <string.h>

/* Tests that drive the relay's agent-facing TCP listener (outer_tcp) directly
   with a raw socket speaking the transport framing protocol, exercising the
   JOIN / PING / CONNECT_ACK parsers and their error branches. */

static void put_be16(unsigned char *p, unsigned short v) {
    p[0] = (unsigned char)(v >> 8);
    p[1] = (unsigned char)(v & 0xff);
}

/* Build a JOIN frame; returns total length. */
static int build_join(unsigned char *out, const char *user, const char *pass) {
    int ulen = (int)strlen(user);
    int plen = (int)strlen(pass);
    int total = 4 + 2 + ulen + 2 + plen;
    out[0] = ASTERISM_TRANS_PROTO_VERSION;
    out[1] = ASTERISM_TRANS_PROTO_JOIN;
    put_be16(out + 2, (unsigned short)total);
    int off = 4;
    put_be16(out + off, (unsigned short)ulen); off += 2;
    memcpy(out + off, user, ulen); off += ulen;
    put_be16(out + off, (unsigned short)plen); off += 2;
    memcpy(out + off, pass, plen); off += plen;
    return total;
}

static int connect_outer(test_env_t *env) {
    int fd = test_socket_connect("127.0.0.1", env->outer_port);
    if (fd >= 0) test_set_socket_recv_timeout(fd, 3000);
    return fd;
}

/* A frame with a bad protocol version is rejected and the connection closed. */
static void test_wire_bad_version(void) {
    test_env_t *env = test_env_create(NULL, 0);
    EXPECT_TRUE(env != NULL);
    if (!env) return;
    int fd = connect_outer(env);
    EXPECT_TRUE(fd >= 0);
    if (fd >= 0) {
        unsigned char frame[4] = {ASTERISM_TRANS_PROTO_VERSION + 1, ASTERISM_TRANS_PROTO_PING, 0, 4};
        send(fd, (const char *)frame, 4, 0);
        char b[8];
        EXPECT_EQ(recv(fd, b, sizeof(b), 0), 0);
        test_socket_close(fd);
    }
    test_env_destroy(env);
}

/* An unknown command is rejected and the connection closed. */
static void test_wire_unknown_command(void) {
    test_env_t *env = test_env_create(NULL, 0);
    EXPECT_TRUE(env != NULL);
    if (!env) return;
    int fd = connect_outer(env);
    EXPECT_TRUE(fd >= 0);
    if (fd >= 0) {
        unsigned char frame[4] = {ASTERISM_TRANS_PROTO_VERSION, 0x7f, 0, 4};
        send(fd, (const char *)frame, 4, 0);
        char b[8];
        EXPECT_EQ(recv(fd, b, sizeof(b), 0), 0);
        test_socket_close(fd);
    }
    test_env_destroy(env);
}

/* A JOIN frame whose declared username length runs past the frame is rejected. */
static void test_wire_malformed_join(void) {
    test_env_t *env = test_env_create(NULL, 0);
    EXPECT_TRUE(env != NULL);
    if (!env) return;
    int fd = connect_outer(env);
    EXPECT_TRUE(fd >= 0);
    if (fd >= 0) {
        /* frame len 8, but username_len claims 100 */
        unsigned char frame[8] = {ASTERISM_TRANS_PROTO_VERSION, ASTERISM_TRANS_PROTO_JOIN, 0, 8};
        put_be16(frame + 4, 100);
        frame[6] = 0; frame[7] = 0;
        send(fd, (const char *)frame, 8, 0);
        char b[8];
        EXPECT_EQ(recv(fd, b, sizeof(b), 0), 0);
        test_socket_close(fd);
    }
    test_env_destroy(env);
}

/* A valid JOIN registers the session; a following PING is answered with PONG. */
static void test_wire_join_then_ping(void) {
    test_env_t *env = test_env_create(NULL, 0);
    EXPECT_TRUE(env != NULL);
    if (!env) return;
    int fd = connect_outer(env);
    EXPECT_TRUE(fd >= 0);
    if (fd >= 0) {
        unsigned char join[64];
        int n = build_join(join, "wireuser", "wirepass");
        EXPECT_EQ(send(fd, (const char *)join, n, 0), n);
        test_sleep(100);

        unsigned char ping[4] = {ASTERISM_TRANS_PROTO_VERSION, ASTERISM_TRANS_PROTO_PING, 0, 4};
        EXPECT_EQ(send(fd, (const char *)ping, 4, 0), 4);

        unsigned char resp[8] = {0};
        int r = recv(fd, (char *)resp, sizeof(resp), 0);
        EXPECT_EQ(r, 4);
        EXPECT_EQ(resp[0], ASTERISM_TRANS_PROTO_VERSION);
        EXPECT_EQ(resp[1], ASTERISM_TRANS_PROTO_PONG);
        test_socket_close(fd);
    }
    test_env_destroy(env);
}

/* A duplicate username from a second agent is rejected (session already exists). */
static void test_wire_duplicate_join(void) {
    test_env_t *env = test_env_create(NULL, 0);
    EXPECT_TRUE(env != NULL);
    if (!env) return;

    int fd1 = connect_outer(env);
    int fd2 = connect_outer(env);
    EXPECT_TRUE(fd1 >= 0 && fd2 >= 0);
    if (fd1 >= 0 && fd2 >= 0) {
        unsigned char join[64];
        int n = build_join(join, "dupuser", "p");
        EXPECT_EQ(send(fd1, (const char *)join, n, 0), n);
        test_sleep(150);
        /* second JOIN with the same username is refused -> connection closed */
        EXPECT_EQ(send(fd2, (const char *)join, n, 0), n);
        char b[8];
        EXPECT_EQ(recv(fd2, b, sizeof(b), 0), 0);
    }
    if (fd1 >= 0) test_socket_close(fd1);
    if (fd2 >= 0) test_socket_close(fd2);
    test_env_destroy(env);
}

/* A CONNECT_ACK referencing an unknown handshake id tears the connection down. */
static void test_wire_connect_ack_unknown(void) {
    test_env_t *env = test_env_create(NULL, 0);
    EXPECT_TRUE(env != NULL);
    if (!env) return;
    int fd = connect_outer(env);
    EXPECT_TRUE(fd >= 0);
    if (fd >= 0) {
        unsigned char frame[9] = {ASTERISM_TRANS_PROTO_VERSION, ASTERISM_TRANS_PROTO_CONNECT_ACK, 0, 9};
        /* handshake id 0x12345678, success = 0 */
        frame[4] = 0x12; frame[5] = 0x34; frame[6] = 0x56; frame[7] = 0x78;
        frame[8] = 0;
        send(fd, (const char *)frame, 9, 0);
        char b[8];
        EXPECT_EQ(recv(fd, b, sizeof(b), 0), 0);
        test_socket_close(fd);
    }
    test_env_destroy(env);
}

void register_suite_wire(void) {
    register_test("Wire", "BadVersion", test_wire_bad_version);
    register_test("Wire", "UnknownCommand", test_wire_unknown_command);
    register_test("Wire", "MalformedJoin", test_wire_malformed_join);
    register_test("Wire", "JoinThenPing", test_wire_join_then_ping);
    register_test("Wire", "DuplicateJoin", test_wire_duplicate_join);
    register_test("Wire", "ConnectAckUnknown", test_wire_connect_ack_unknown);
}
