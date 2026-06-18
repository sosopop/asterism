#include "test_framework.h"
#include "test_utils.h"
#include <stdio.h>
#include <string.h>

static void test_proxy_http_tunnel_no_auth(void) {
    test_env_t *env = test_env_create(NULL, 0);
    EXPECT_TRUE(env != NULL);
    if (!env) return;
    
    int sock = test_socket_connect("127.0.0.1", env->inner_port);
    EXPECT_TRUE(sock >= 0);
    if (sock >= 0) {
        char req[512];
        sprintf(req, "CONNECT 127.0.0.1:%u HTTP/1.1\r\nHost: 127.0.0.1:%u\r\nProxy-Connection: Keep-Alive\r\n\r\n", env->mock_port, env->mock_port);
        
        int ret = send(sock, req, (int)strlen(req), 0);
        EXPECT_EQ(ret, (int)strlen(req));
        
        char buffer[1024] = {0};
        test_sleep(100);
        ret = recv(sock, buffer, sizeof(buffer) - 1, 0);
        EXPECT_TRUE(ret > 0);
        EXPECT_TRUE(strstr(buffer, "HTTP/1.1 407") == buffer);
        
        test_socket_close(sock);
    }
    test_env_destroy(env);
}

static void test_proxy_http_tunnel_wrong_auth(void) {
    test_env_t *env = test_env_create(NULL, 0);
    EXPECT_TRUE(env != NULL);
    if (!env) return;
    
    int sock = test_socket_connect("127.0.0.1", env->inner_port);
    EXPECT_TRUE(sock >= 0);
    if (sock >= 0) {
        char req[512];
        sprintf(req, "CONNECT 127.0.0.1:%u HTTP/1.1\r\nHost: 127.0.0.1:%u\r\nProxy-Authorization: Basic aGVsbG86aGVsbG8=\r\n\r\n", env->mock_port, env->mock_port);
        
        int ret = send(sock, req, (int)strlen(req), 0);
        EXPECT_EQ(ret, (int)strlen(req));
        
        char buffer[1024] = {0};
        test_sleep(100);
        ret = recv(sock, buffer, sizeof(buffer) - 1, 0);
        EXPECT_TRUE(ret > 0);
        EXPECT_TRUE(strstr(buffer, "HTTP/1.1 407") == buffer);
        
        test_socket_close(sock);
    }
    test_env_destroy(env);
}

static void test_proxy_normal_http_no_auth(void) {
    test_env_t *env = test_env_create(NULL, 0);
    EXPECT_TRUE(env != NULL);
    if (!env) return;
    
    int sock = test_socket_connect("127.0.0.1", env->inner_port);
    EXPECT_TRUE(sock >= 0);
    if (sock >= 0) {
        char req[512];
        sprintf(req, "GET http://127.0.0.1:%u/ HTTP/1.1\r\nHost: 127.0.0.1:%u\r\nRange: bytes=0-10\r\nConnection: keep-alive\r\n\r\n", env->mock_port, env->mock_port);
        
        int ret = send(sock, req, (int)strlen(req), 0);
        EXPECT_EQ(ret, (int)strlen(req));
        
        char buffer[1024] = {0};
        test_sleep(100);
        ret = recv(sock, buffer, sizeof(buffer) - 1, 0);
        EXPECT_TRUE(ret > 0);
        EXPECT_TRUE(strstr(buffer, "HTTP/1.1 407") == buffer);
        
        // Peek should show 0 since connection must be closed by server
        ret = recv(sock, buffer, sizeof(buffer) - 1, MSG_PEEK);
        EXPECT_EQ(ret, 0);
        
        test_socket_close(sock);
    }
    test_env_destroy(env);
}

static void test_proxy_http_tunnel_success(void) {
    test_env_t *env = test_env_create(NULL, 0);
    EXPECT_TRUE(env != NULL);
    if (!env) return;
    
    char expected_req[512];
    sprintf(expected_req, "Host: 127.0.0.1:%u", env->mock_port);
    
    mock_server_args_t mock_args;
    mock_args.port = env->mock_port;
    mock_args.expected_req = expected_req;
    
    uv_thread_t server_tid;
    int r = uv_thread_create(&server_tid, mock_server_keep_alive_thread, &mock_args);
    EXPECT_EQ(r, 0);
    test_sleep(100);
    
    int sock = test_socket_connect("127.0.0.1", env->inner_port);
    EXPECT_TRUE(sock >= 0);
    if (sock >= 0) {
        char req1[512];
        sprintf(req1, "CONNECT 127.0.0.1:%u HTTP/1.1\r\nHost: 127.0.0.1:%u\r\nProxy-Connection: Keep-Alive\r\nProxy-Authorization: Basic dGVzdDp0ZXN0\r\n\r\n", env->mock_port, env->mock_port);
        
        int ret = send(sock, req1, (int)strlen(req1), 0);
        EXPECT_EQ(ret, (int)strlen(req1));
        
        char buffer[1024] = {0};
        test_sleep(100);
        ret = recv(sock, buffer, sizeof(buffer) - 1, 0);
        EXPECT_TRUE(ret > 0);
        EXPECT_TRUE(strstr(buffer, "HTTP/1.1 200") == buffer);
        
        char req2[512];
        sprintf(req2, "GET / HTTP/1.1\r\nHost: 127.0.0.1:%u\r\nRange: bytes=0-10\r\nConnection: keep-alive\r\n\r\n", env->mock_port);
        ret = send(sock, req2, (int)strlen(req2), 0);
        EXPECT_EQ(ret, (int)strlen(req2));
        
        memset(buffer, 0, sizeof(buffer));
        test_sleep(100);
        ret = recv(sock, buffer, sizeof(buffer) - 1, 0);
        EXPECT_TRUE(ret > 0);
        EXPECT_TRUE(strstr(buffer, "HTTP/1.1 200 ok") == buffer);
        
        test_socket_close(sock);
    }
    
    uv_thread_join(&server_tid);
    test_env_destroy(env);
}

static void test_proxy_normal_http_success(void) {
    test_env_t *env = test_env_create(NULL, 0);
    EXPECT_TRUE(env != NULL);
    if (!env) return;
    
    char expected_req[512];
    sprintf(expected_req, "Host: 127.0.0.1:%u", env->mock_port);
    
    mock_server_args_t mock_args;
    mock_args.port = env->mock_port;
    mock_args.expected_req = expected_req;
    
    uv_thread_t server_tid;
    int r = uv_thread_create(&server_tid, mock_server_thread, &mock_args);
    EXPECT_EQ(r, 0);
    test_sleep(100);
    
    int sock = test_socket_connect("127.0.0.1", env->inner_port);
    EXPECT_TRUE(sock >= 0);
    if (sock >= 0) {
        char req[512];
        sprintf(req, "GET http://127.0.0.1:%u/ HTTP/1.1\r\nHost: 127.0.0.1:%u\r\nRange: bytes=0-10\r\nConnection: keep-alive\r\nProxy-Authorization: Basic dGVzdDp0ZXN0\r\n\r\n", env->mock_port, env->mock_port);
        
        int ret = send(sock, req, (int)strlen(req), 0);
        EXPECT_EQ(ret, (int)strlen(req));
        
        char buffer[1024] = {0};
        test_sleep(100);
        ret = recv(sock, buffer, sizeof(buffer) - 1, 0);
        EXPECT_TRUE(ret > 0);
        EXPECT_TRUE(strstr(buffer, "HTTP/1.1 200 ok") == buffer);
        
        test_socket_close(sock);
    }
    
    uv_thread_join(&server_tid);
    test_env_destroy(env);
}

static void test_proxy_send_one_by_one(void) {
    test_env_t *env = test_env_create(NULL, 0);
    EXPECT_TRUE(env != NULL);
    if (!env) return;
    
    char expected_req[512];
    sprintf(expected_req, "Host: 127.0.0.1:%u", env->mock_port);
    
    mock_server_args_t mock_args;
    mock_args.port = env->mock_port;
    mock_args.expected_req = expected_req;
    
    uv_thread_t server_tid;
    int r = uv_thread_create(&server_tid, mock_server_thread, &mock_args);
    EXPECT_EQ(r, 0);
    test_sleep(100);
    
    int sock = test_socket_connect("127.0.0.1", env->inner_port);
    EXPECT_TRUE(sock >= 0);
    if (sock >= 0) {
        int ret;
        char req[512];
        sprintf(req, "GET http://127.0.0.1:%u/ HTTP/1.1\r\nHost: 127.0.0.1:%u\r\nRange: bytes=0-10\r\nConnection: keep-alive\r\nProxy-Authorization: Basic dGVzdDp0ZXN0\r\n\r\n", env->mock_port, env->mock_port);
        
        int len = (int)strlen(req);
        for (int i = 0; i < len; i++) {
            ret = send(sock, req + i, 1, 0);
            EXPECT_EQ(ret, 1);
        }
        
        char buffer[1024] = {0};
        test_sleep(100);
        ret = recv(sock, buffer, sizeof(buffer) - 1, 0);
        EXPECT_TRUE(ret > 0);
        EXPECT_TRUE(strstr(buffer, "HTTP/1.1 200 ok") == buffer);
        
        test_socket_close(sock);
    }
    
    uv_thread_join(&server_tid);
    test_env_destroy(env);
}

static void test_proxy_socks5_connect_success(void) {
    test_env_t *env = test_env_create_ex("socks5", NULL, 0, 0);
    EXPECT_TRUE(env != NULL);
    if (!env) return;

    char expected_req[512];
    sprintf(expected_req, "Host: 127.0.0.1:%u", env->mock_port);

    mock_server_args_t mock_args;
    mock_args.port = env->mock_port;
    mock_args.expected_req = expected_req;

    uv_thread_t server_tid;
    int r = uv_thread_create(&server_tid, mock_server_thread, &mock_args);
    EXPECT_EQ(r, 0);
    test_sleep(100);

    int sock = test_socket_connect("127.0.0.1", env->inner_port);
    EXPECT_TRUE(sock >= 0);
    if (sock >= 0) {
        // 1. SOCKS5 Greeting (v5, 1 method: username/password)
        int ret = send(sock, "\x05\x01\x02", 3, 0);
        EXPECT_EQ(ret, 3);

        char buffer[1024] = {0};
        test_sleep(100);
        ret = recv(sock, buffer, sizeof(buffer) - 1, 0);
        EXPECT_EQ(ret, 2);
        EXPECT_EQ(buffer[0], 0x05);
        EXPECT_EQ(buffer[1], 0x02);

        // 2. Authentication: v1, user len 4 "test", pass len 4 "test"
        ret = send(sock, "\x01\x04test\x04test", 11, 0);
        EXPECT_EQ(ret, 11);

        memset(buffer, 0, sizeof(buffer));
        test_sleep(100);
        ret = recv(sock, buffer, sizeof(buffer) - 1, 0);
        EXPECT_EQ(ret, 2);
        EXPECT_EQ(buffer[0], 0x01);
        EXPECT_EQ(buffer[1], 0x00);

        // 3. Connect request: v5, cmd CONNECT (0x01), RSV 0x00, atyp IPv4 (0x01), target 127.0.0.1, port
        char conn_req[10];
        conn_req[0] = 0x05;
        conn_req[1] = 0x01;
        conn_req[2] = 0x00;
        conn_req[3] = 0x01;
        conn_req[4] = 127;
        conn_req[5] = 0;
        conn_req[6] = 0;
        conn_req[7] = 1;
        unsigned short net_port = htons(env->mock_port);
        memcpy(&conn_req[8], &net_port, 2);

        ret = send(sock, conn_req, 10, 0);
        EXPECT_EQ(ret, 10);

        memset(buffer, 0, sizeof(buffer));
        test_sleep(100);
        ret = recv(sock, buffer, sizeof(buffer) - 1, 0);
        EXPECT_EQ(ret, 10);
        EXPECT_EQ(buffer[0], 0x05);
        EXPECT_EQ(buffer[1], 0x00);

        // 4. Send HTTP request
        char http_req[512];
        sprintf(http_req, "GET / HTTP/1.1\r\nHost: 127.0.0.1:%u\r\n\r\n", env->mock_port);
        ret = send(sock, http_req, (int)strlen(http_req), 0);
        EXPECT_EQ(ret, (int)strlen(http_req));

        memset(buffer, 0, sizeof(buffer));
        test_sleep(100);
        ret = recv(sock, buffer, sizeof(buffer) - 1, 0);
        EXPECT_TRUE(ret > 0);
        EXPECT_TRUE(strstr(buffer, "HTTP/1.1 200 ok") == buffer);

        test_socket_close(sock);
    }

    uv_thread_join(&server_tid);
    test_env_destroy(env);
}

static void test_proxy_socks5_unsupported_method(void) {
    test_env_t *env = test_env_create_ex("socks5", NULL, 0, 0);
    EXPECT_TRUE(env != NULL);
    if (!env) return;

    int sock = test_socket_connect("127.0.0.1", env->inner_port);
    EXPECT_TRUE(sock >= 0);
    if (sock >= 0) {
        int ret = send(sock, "\x05\x01\x00", 3, 0);
        EXPECT_EQ(ret, 3);

        char buffer[1024] = {0};
        test_sleep(100);
        ret = recv(sock, buffer, sizeof(buffer) - 1, 0);
        EXPECT_EQ(ret, 2);
        EXPECT_EQ(buffer[0], 0x05);
        EXPECT_EQ((unsigned char)buffer[1], 0xFF);

        test_socket_close(sock);
    }
    test_env_destroy(env);
}

static void test_proxy_socks5_auth_failure(void) {
    test_env_t *env = test_env_create_ex("socks5", NULL, 0, 0);
    EXPECT_TRUE(env != NULL);
    if (!env) return;

    int sock = test_socket_connect("127.0.0.1", env->inner_port);
    EXPECT_TRUE(sock >= 0);
    if (sock >= 0) {
        int ret = send(sock, "\x05\x01\x02", 3, 0);
        EXPECT_EQ(ret, 3);

        char buffer[1024] = {0};
        test_sleep(100);
        ret = recv(sock, buffer, sizeof(buffer) - 1, 0);
        EXPECT_EQ(ret, 2);
        EXPECT_EQ(buffer[0], 0x05);
        EXPECT_EQ(buffer[1], 0x02);

        ret = send(sock, "\x01\x04test\x05wrong", 12, 0);
        EXPECT_EQ(ret, 12);

        memset(buffer, 0, sizeof(buffer));
        test_sleep(100);
        ret = recv(sock, buffer, sizeof(buffer) - 1, 0);
        EXPECT_EQ(ret, 2);
        EXPECT_EQ(buffer[0], 0x01);
        EXPECT_EQ(buffer[1], 0x01);

        test_socket_close(sock);
    }
    test_env_destroy(env);
}

static void test_proxy_sessions_endpoint_default_requires_auth(void) {
    test_env_t *env = test_env_create_ex("http", NULL, 0, 0);
    EXPECT_TRUE(env != NULL);
    if (!env) return;

    int sock = test_socket_connect("127.0.0.1", env->inner_port);
    EXPECT_TRUE(sock >= 0);
    if (sock >= 0) {
        const char *req = "GET /sessions HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n";
        int ret = send(sock, req, (int)strlen(req), 0);
        EXPECT_EQ(ret, (int)strlen(req));

        char buffer[2048] = {0};
        test_sleep(150);
        ret = recv(sock, buffer, sizeof(buffer) - 1, 0);
        EXPECT_TRUE(ret > 0);
        EXPECT_TRUE(strstr(buffer, "HTTP/1.1 401 Unauthorized") == buffer);

        test_socket_close(sock);
    }
    test_env_destroy(env);
}

static void test_proxy_sessions_endpoint_public(void) {
    test_env_t *env = test_env_create_ex("http", NULL, 0, 0);
    EXPECT_TRUE(env != NULL);
    if (!env) return;

    int opt_ret = asterism_set_option(env->as, ASTERISM_OPT_SESSION_POLICY, ASTERISM_SESSION_POLICY_PUBLIC);
    EXPECT_EQ(opt_ret, 0);

    int sock = test_socket_connect("127.0.0.1", env->inner_port);
    EXPECT_TRUE(sock >= 0);
    if (sock >= 0) {
        const char *req = "GET /sessions HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n";
        int ret = send(sock, req, (int)strlen(req), 0);
        EXPECT_EQ(ret, (int)strlen(req));

        char buffer[2048] = {0};
        test_sleep(150);
        ret = recv(sock, buffer, sizeof(buffer) - 1, 0);
        EXPECT_TRUE(ret > 0);
        EXPECT_TRUE(strstr(buffer, "HTTP/1.1 200 OK") == buffer);
        EXPECT_TRUE(strstr(buffer, "test") != NULL);

        test_socket_close(sock);
    }
    test_env_destroy(env);
}

static void test_proxy_sessions_endpoint_disabled(void) {
    test_env_t *env = test_env_create_ex("http", NULL, 0, 0);
    EXPECT_TRUE(env != NULL);
    if (!env) return;

    int opt_ret = asterism_set_option(env->as, ASTERISM_OPT_SESSION_POLICY, ASTERISM_SESSION_POLICY_DISABLED);
    EXPECT_EQ(opt_ret, 0);

    int sock = test_socket_connect("127.0.0.1", env->inner_port);
    EXPECT_TRUE(sock >= 0);
    if (sock >= 0) {
        const char *req = "GET /sessions HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n";
        int ret = send(sock, req, (int)strlen(req), 0);
        EXPECT_EQ(ret, (int)strlen(req));

        char buffer[2048] = {0};
        test_sleep(150);
        ret = recv(sock, buffer, sizeof(buffer) - 1, 0);
        EXPECT_TRUE(ret > 0);
        EXPECT_TRUE(strstr(buffer, "HTTP/1.1 404 Not Found") == buffer);

        test_socket_close(sock);
    }
    test_env_destroy(env);
}

static void test_proxy_sessions_endpoint_long_basic_rejected(void) {
    test_env_t *env = test_env_create_ex("http", NULL, 0, 1);
    EXPECT_TRUE(env != NULL);
    if (!env) return;

    int sock = test_socket_connect("127.0.0.1", env->inner_port);
    EXPECT_TRUE(sock >= 0);
    if (sock >= 0) {
        char req[512];
        memset(req, 'A', sizeof(req));
        int prefix = snprintf(req, sizeof(req), "GET /sessions HTTP/1.1\r\nHost: 127.0.0.1\r\nAuthorization: Basic ");
        EXPECT_TRUE(prefix > 0);
        memset(req + prefix, 'A', 180);
        memcpy(req + prefix + 180, "\r\n\r\n", 4);
        int req_len = prefix + 184;

        int ret = send(sock, req, req_len, 0);
        EXPECT_EQ(ret, req_len);

        char buffer[2048] = {0};
        test_sleep(150);
        ret = recv(sock, buffer, sizeof(buffer) - 1, 0);
        EXPECT_TRUE(ret > 0);
        EXPECT_TRUE(strstr(buffer, "HTTP/1.1 401 Unauthorized") == buffer);

        test_socket_close(sock);
    }
    test_env_destroy(env);
}

static void test_proxy_sessions_endpoint_with_auth(void) {
    test_env_t *env = test_env_create_ex("http", NULL, 0, 1);
    EXPECT_TRUE(env != NULL);
    if (!env) return;

    int sock = test_socket_connect("127.0.0.1", env->inner_port);
    EXPECT_TRUE(sock >= 0);
    if (sock >= 0) {
        const char *req = "GET /sessions HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n";
        int ret = send(sock, req, (int)strlen(req), 0);
        EXPECT_EQ(ret, (int)strlen(req));

        char buffer[2048] = {0};
        test_sleep(100);
        ret = recv(sock, buffer, sizeof(buffer) - 1, 0);
        EXPECT_TRUE(ret > 0);
        EXPECT_TRUE(strstr(buffer, "HTTP/1.1 401 Unauthorized") == buffer);

        test_socket_close(sock);
    }

    sock = test_socket_connect("127.0.0.1", env->inner_port);
    EXPECT_TRUE(sock >= 0);
    if (sock >= 0) {
        const char *req = "GET /sessions HTTP/1.1\r\nHost: 127.0.0.1\r\nAuthorization: Basic YWRtaW46YWRtaW5wYXNz\r\n\r\n";
        int ret = send(sock, req, (int)strlen(req), 0);
        EXPECT_EQ(ret, (int)strlen(req));

        char buffer[2048] = {0};
        test_sleep(150);
        ret = recv(sock, buffer, sizeof(buffer) - 1, 0);
        EXPECT_TRUE(ret > 0);
        EXPECT_TRUE(strstr(buffer, "HTTP/1.1 200 OK") != NULL);
        EXPECT_TRUE(strstr(buffer, "test") != NULL);

        test_socket_close(sock);
    }
    test_env_destroy(env);
}

void register_suite_proxy(void) {
    register_test("Proxy", "HTTPTunnelNoAuth", test_proxy_http_tunnel_no_auth);
    register_test("Proxy", "HTTPTunnelWrongAuth", test_proxy_http_tunnel_wrong_auth);
    register_test("Proxy", "NormalHTTPNoAuth", test_proxy_normal_http_no_auth);
    register_test("Proxy", "HTTPTunnelSuccess", test_proxy_http_tunnel_success);
    register_test("Proxy", "NormalHTTPSuccess", test_proxy_normal_http_success);
    register_test("Proxy", "SendOneByOne", test_proxy_send_one_by_one);
    register_test("Proxy", "Socks5ConnectSuccess", test_proxy_socks5_connect_success);
    register_test("Proxy", "Socks5UnsupportedMethod", test_proxy_socks5_unsupported_method);
    register_test("Proxy", "Socks5AuthFailure", test_proxy_socks5_auth_failure);
    register_test("Proxy", "SessionsEndpointDefaultRequiresAuth", test_proxy_sessions_endpoint_default_requires_auth);
    register_test("Proxy", "SessionsEndpointPublic", test_proxy_sessions_endpoint_public);
    register_test("Proxy", "SessionsEndpointDisabled", test_proxy_sessions_endpoint_disabled);
    register_test("Proxy", "SessionsEndpointLongBasicRejected", test_proxy_sessions_endpoint_long_basic_rejected);
    register_test("Proxy", "SessionsEndpointWithAuth", test_proxy_sessions_endpoint_with_auth);
}
