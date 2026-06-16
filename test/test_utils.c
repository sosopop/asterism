#include "test_utils.h"
#include "test_framework.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int test_socket_listen(unsigned short *port) {
    int sock = (int)socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) return -1;
    
    int optval = 1;
    setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, (const char *)&optval, sizeof(optval));
    
    struct sockaddr_in serveraddr;
    memset(&serveraddr, 0, sizeof(serveraddr));
    serveraddr.sin_family = AF_INET;
    serveraddr.sin_addr.s_addr = htonl(INADDR_ANY);
    serveraddr.sin_port = htons(*port);
    
    if (bind(sock, (struct sockaddr *)&serveraddr, sizeof(serveraddr)) < 0) {
        test_socket_close(sock);
        return -1;
    }
    
    if (listen(sock, 5) < 0) {
        test_socket_close(sock);
        return -1;
    }
    
    if (*port == 0) {
        struct sockaddr_in addr;
        socklen_t addrlen = sizeof(addr);
        if (getsockname(sock, (struct sockaddr *)&addr, &addrlen) == 0) {
            *port = ntohs(addr.sin_port);
        }
    }
    
    return sock;
}

int test_socket_accept(int listen_fd) {
    int clt = (int)accept(listen_fd, NULL, NULL);
    return clt;
}

int test_socket_connect(const char *ip, unsigned short port) {
    struct sockaddr_in serv_addr;
    memset(&serv_addr, 0, sizeof(serv_addr));
    if (uv_ip4_addr(ip, port, &serv_addr) != 0) {
        return -1;
    }

    for (int attempt = 0; attempt < 50; ++attempt) {
        int sock = (int)socket(AF_INET, SOCK_STREAM, 0);
        if (sock < 0) return -1;

        if (connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) == 0) {
            return sock;
        }
        test_socket_close(sock);
        test_sleep(20);
    }

    return -1;
}

void test_sleep(int ms) {
#ifdef _WIN32
    Sleep(ms);
#else
    usleep(ms * 1000);
#endif
}

void test_socket_close(int fd) {
    if (fd >= 0) {
#ifdef _WIN32
        closesocket(fd);
#else
        close(fd);
#endif
    }
}

unsigned short test_get_free_port(void) {
    unsigned short port = 0;
    int fd = test_socket_listen(&port);
    if (fd >= 0) {
        test_socket_close(fd);
    }
    return port;
}

static void asterism_run_thread(void *arg) {
    test_env_t *env = (test_env_t *)arg;
    int ret = asterism_run(env->as);
    (void)ret;
}

test_env_t *test_env_create(asterism_connnect_redirect_hook hook, unsigned short idle_timeout) {
    return test_env_create_ex("http", hook, idle_timeout, 0);
}

test_env_t *test_env_create_ex(const char *inner_scheme, asterism_connnect_redirect_hook hook, unsigned short idle_timeout, int enable_session_auth) {
    test_env_t *env = malloc(sizeof(test_env_t));
    if (!env) return NULL;
    memset(env, 0, sizeof(test_env_t));
    
    env->outer_port = test_get_free_port();
    do {
        env->inner_port = test_get_free_port();
    } while (env->inner_port == env->outer_port);
    do {
        env->mock_port = test_get_free_port();
    } while (env->mock_port == env->outer_port || env->mock_port == env->inner_port);
    if (!env->outer_port || !env->inner_port || !env->mock_port) {
        free(env);
        return NULL;
    }
    
    env->as = asterism_create();
    if (!env->as) {
        free(env);
        return NULL;
    }
    
    char outer_addr[128];
    char inner_addr[128];
    char connect_addr[128];
    
    sprintf(outer_addr, "tcp://127.0.0.1:%u", env->outer_port);
    sprintf(inner_addr, "%s://127.0.0.1:%u", inner_scheme, env->inner_port);
    sprintf(connect_addr, "tcp://127.0.0.1:%u", env->outer_port);
    
    int ret;
    ret = asterism_set_option(env->as, ASTERISM_OPT_OUTER_BIND_ADDR, outer_addr);
    EXPECT_EQ(ret, 0);
    ret = asterism_set_option(env->as, ASTERISM_OPT_INNER_BIND_ADDR, inner_addr);
    EXPECT_EQ(ret, 0);
    ret = asterism_set_option(env->as, ASTERISM_OPT_USERNAME, "test");
    EXPECT_EQ(ret, 0);
    ret = asterism_set_option(env->as, ASTERISM_OPT_PASSWORD, "test");
    EXPECT_EQ(ret, 0);
    ret = asterism_set_option(env->as, ASTERISM_OPT_CONNECT_ADDR, connect_addr);
    EXPECT_EQ(ret, 0);
    
    if (hook) {
        ret = asterism_set_option(env->as, ASTERISM_OPT_CONNECT_REDIRECT_HOOK, hook);
        EXPECT_EQ(ret, 0);
        ret = asterism_set_option(env->as, ASTERISM_OPT_CONNECT_REDIRECT_HOOK_DATA, env);
        EXPECT_EQ(ret, 0);
    }
    
    ret = asterism_set_option(env->as, ASTERISM_OPT_HEARTBEAT_INTERVAL, 1000);
    EXPECT_EQ(ret, 0);
    ret = asterism_set_option(env->as, ASTERISM_OPT_IDLE_TIMEOUT, idle_timeout > 0 ? idle_timeout : 5);
    EXPECT_EQ(ret, 0);

    if (enable_session_auth) {
        ret = asterism_set_option(env->as, ASTERISM_OPT_SESSION_AUTH, 1);
        EXPECT_EQ(ret, 0);
        ret = asterism_set_option(env->as, ASTERISM_OPT_SESSION_AUTH_USER, "admin");
        EXPECT_EQ(ret, 0);
        ret = asterism_set_option(env->as, ASTERISM_OPT_SESSION_AUTH_PASS, "adminpass");
        EXPECT_EQ(ret, 0);
    }
    
    int r = uv_thread_create(&env->as_thread, asterism_run_thread, env);
    EXPECT_EQ(r, 0);
    if (r != 0) {
        asterism_destroy(env->as);
        free(env);
        return NULL;
    }
    
    test_sleep(100);
    return env;
}

void test_env_destroy(test_env_t *env) {
    if (!env) return;
    
    asterism_stop(env->as);
    uv_thread_join(&env->as_thread);
    asterism_destroy(env->as);
    free(env);
}

void mock_server_thread(void *arg) {
    mock_server_args_t *args = (mock_server_args_t *)arg;
    unsigned short port = args->port;
    int srv = test_socket_listen(&port);
    if (srv < 0) return;
    
    int clt = test_socket_accept(srv);
    if (clt >= 0) {
        char buffer[2048] = {0};
        int bytes_recv = recv(clt, buffer, sizeof(buffer) - 1, 0);
        if (bytes_recv > 0) {
            if (args->expected_req) {
                EXPECT_TRUE(strstr(buffer, args->expected_req) != NULL);
            }
            const char *http_resp = "HTTP/1.1 200 ok\r\n\r\n";
            send(clt, http_resp, (int)strlen(http_resp), 0);
        }
        shutdown(clt, 2);
        test_socket_close(clt);
    }
    test_socket_close(srv);
}

void mock_server_keep_alive_thread(void *arg) {
    mock_server_args_t *args = (mock_server_args_t *)arg;
    unsigned short port = args->port;
    int srv = test_socket_listen(&port);
    if (srv < 0) return;
    
    int clt = test_socket_accept(srv);
    if (clt >= 0) {
        char buffer[2048] = {0};
        // First request
        int bytes_recv = recv(clt, buffer, sizeof(buffer) - 1, 0);
        if (bytes_recv > 0) {
            if (args->expected_req) {
                EXPECT_TRUE(strstr(buffer, args->expected_req) != NULL);
            }
            const char *http_resp = "HTTP/1.1 200 ok\r\n\r\n";
            send(clt, http_resp, (int)strlen(http_resp), 0);
            
            // Second request
            memset(buffer, 0, sizeof(buffer));
            bytes_recv = recv(clt, buffer, sizeof(buffer) - 1, 0);
            if (bytes_recv > 0) {
                if (args->expected_req) {
                    EXPECT_TRUE(strstr(buffer, args->expected_req) != NULL);
                }
                send(clt, http_resp, (int)strlen(http_resp), 0);
            }
        }
        shutdown(clt, 2);
        test_socket_close(clt);
    }
    test_socket_close(srv);
}
