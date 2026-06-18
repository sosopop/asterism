#ifndef TEST_UTILS_H_
#define TEST_UTILS_H_

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#endif

#include <uv.h>
#include "asterism.h"

typedef struct {
    unsigned short port;
    const char *expected_req;
} mock_server_args_t;

typedef struct {
    asterism as;
    uv_thread_t as_thread;
    unsigned short outer_port;
    unsigned short inner_port;
    unsigned short mock_port;
} test_env_t;

int test_socket_listen(unsigned short *port);
int test_socket_accept(int listen_fd);
int test_socket_connect(const char *ip, unsigned short port);
void test_sleep(int ms);
void test_socket_close(int fd);
unsigned short test_get_free_port(void);

// Test environment setup helpers
test_env_t *test_env_create(asterism_connnect_redirect_hook hook, unsigned short idle_timeout);
test_env_t *test_env_create_ex(const char *inner_scheme, asterism_connnect_redirect_hook hook, unsigned short idle_timeout, int enable_session_auth);
void test_env_destroy(test_env_t *env);

// Mock HTTP echo / keep-alive server thread functions
void mock_server_thread(void *arg);
void mock_server_keep_alive_thread(void *arg);

// UDP echo + SOCKS5-UDP helpers (full-link UDP tests)
typedef struct {
    int socket_fd;
    int packet_count;
} udp_echo_args_t;

void test_set_socket_recv_timeout(int socket_fd, int milliseconds);
// Create a bound UDP echo socket on loopback for the given family (AF_INET or
// AF_INET6). Returns the socket fd and sets *port, or -1 on failure.
int test_create_udp_echo_socket(int family, unsigned short *port);
void test_udp_echo_thread(void *arg);
// Drive SOCKS5 greeting + auth(test/test) + UDP ASSOCIATE on an existing TCP
// control socket. On success returns 0 and sets *relay_udp_port.
int test_socks5_udp_associate(int control_fd, unsigned short *relay_udp_port);

#endif
