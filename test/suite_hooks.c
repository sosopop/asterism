#include "test_framework.h"
#include "test_utils.h"
#include "asterism.h"
#include <stdio.h>
#include <string.h>

static char *test_redirect_hook(char *target_addr, void *data) {
    test_env_t *env = (test_env_t *)data;
    if (strcmp(target_addr, "www.baidu.com:80") == 0) {
        return NULL;
    } else if (strcmp(target_addr, "www.hi-asterism.com:80") == 0) {
        char *buf = asterism_alloc(64);
        if (buf) {
            sprintf(buf, "127.0.0.1:%u", env->mock_port);
        }
        return buf;
    }
    return target_addr;
}

static void test_hooks_forbidden(void) {
    test_env_t *env = test_env_create(test_redirect_hook, 0);
    EXPECT_TRUE(env != NULL);
    if (!env) return;
    
    int sock = test_socket_connect("127.0.0.1", env->inner_port);
    EXPECT_TRUE(sock >= 0);
    if (sock >= 0) {
        const char *req = "CONNECT www.baidu.com:80 HTTP/1.1\r\nHost: www.baidu.com:80\r\nProxy-Connection: Keep-Alive\r\nProxy-Authorization: Basic dGVzdDp0ZXN0\r\n\r\n";
        
        int ret = send(sock, req, (int)strlen(req), 0);
        EXPECT_EQ(ret, (int)strlen(req));
        
        char buffer[1024] = {0};
        test_sleep(100);
        ret = recv(sock, buffer, sizeof(buffer) - 1, 0);
        // Expect connection closed by proxy (returns 0) or refused
        EXPECT_EQ(ret, 0);
        
        test_socket_close(sock);
    }
    test_env_destroy(env);
}

static void test_hooks_redirect(void) {
    test_env_t *env = test_env_create(test_redirect_hook, 0);
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
        const char *req1 = "CONNECT www.hi-asterism.com:80 HTTP/1.1\r\nHost: www.hi-asterism.com:80\r\nProxy-Connection: Keep-Alive\r\nProxy-Authorization: Basic dGVzdDp0ZXN0\r\n\r\n";
        
        int ret = send(sock, req1, (int)strlen(req1), 0);
        EXPECT_EQ(ret, (int)strlen(req1));
        
        char buffer[1024] = {0};
        test_sleep(100);
        ret = recv(sock, buffer, sizeof(buffer) - 1, 0);
        EXPECT_TRUE(ret > 0);
        EXPECT_TRUE(strstr(buffer, "HTTP/1.1 200 Connection Established") == buffer);
        
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

void register_suite_hooks(void) {
    register_test("Hooks", "Forbidden", test_hooks_forbidden);
    register_test("Hooks", "Redirect", test_hooks_redirect);
}
