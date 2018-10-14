#include "asterism_test03.h"
#include "../asterism_inner_http.h"
#include "../asterism_core.h"

#ifdef UNIT_TEST

#define IDLE_TIMEOUT 5

#define TEST_HTTP_CONNECT_REQ1              \
    "CONNECT www.baidu.com:80 HTTP/1.1\r\n" \
    "Host: www.baidu.com:80\r\n"            \
    "Proxy-Connection: Keep-Alive\r\n"      \
    "Proxy-Authorization: Basic dGVzdDp0ZXN0\r\n\r\n"

#define TEST_HTTP_CONNECT_REQ2          \
    "CONNECT 127.0.0.1:1110 HTTP/1.1\r\n" \
    "Host: 127.0.0.1:1110\r\n"            \
    "Proxy-Connection: Keep-Alive\r\n"  \
    "Proxy-Authorization: Basic dGVzdDp0ZXN0\r\n\r\n"

#define TEST_HTTP_CONNECT_REQ3                    \
    "CONNECT www.hi-asterism.com:80 HTTP/1.1\r\n" \
    "Host: www.hi-asterism.com:80\r\n"            \
    "Proxy-Connection: Keep-Alive\r\n"            \
    "Proxy-Authorization: Basic dGVzdDp0ZXN0\r\n\r\n"

#define TEST_HTTP_CONNECT_REQ4          \
    "CONNECT 127.0.0.1:1110 HTTP/1.1\r\n" \
    "Host: 127.0.0.1:1110\r\n"            \
    "Proxy-Connection: Keep-Alive\r\n\r\n"

#define TEST_HTTP_CONNECT_REQ5          \
    "CONNECT 127.0.0.1:1110 HTTP/1.1\r\n" \
    "Host: 127.0.0.1:1110\r\n"            \
    "Proxy-Authorization: Basic aGVsbG86aGVsbG8=\r\n\r\n"

#define TEST_HTTP_GET_REQ1  \
    "GET / HTTP/1.1\r\n"    \
    "Host: 127.0.0.1:1110\r\n"   \
    "Range: bytes=0-10\r\n" \
    "Connection: keep-alive\r\n\r\n"

#define TEST_HTTP_GET_REQ2               \
    "GET http://127.0.0.1:1110/ HTTP/1.1\r\n" \
    "Host: 127.0.0.1:1110\r\n"                \
    "Range: bytes=0-10\r\n"              \
    "Connection: keep-alive\r\n\r\n"

#define TEST_HTTP_GET_REQ3               \
    "GET http://127.0.0.1:1110/ HTTP/1.1\r\n" \
    "Host: 127.0.0.1:1110\r\n"                \
    "Range: bytes=0-10\r\n"              \
    "Connection: keep-alive\r\n"         \
    "Proxy-Authorization: Basic dGVzdDp0ZXN0\r\n\r\n"

#define HTTP_CONNECT_RESP_200 \
    "HTTP/1.1 200 Connection Established\r\n\r\n"

#define HTTP_GET_RESP_200 \
    "HTTP/1.1 200 ok\r\n\r\n"

static char *redirect_hook(char *target_addr, void *data)
{
    //printf("remote request %s\n", target_addr);
    if (strcmp(target_addr, "www.baidu.com:80") == 0)
    {
        return 0;
    }
    else if (strcmp(target_addr, "www.hi-asterism.com:80") == 0)
    {
        char *buf = asterism_alloc(sizeof("127.0.0.1:1110"));
        memcpy(buf, "127.0.0.1:1110", sizeof("127.0.0.1:1110"));
        return buf;
    }
    return target_addr;
}

static void asterism_test_thread(void *arg)
{
    asterism as = (asterism)arg;
    int ret = 0;
    ret = asterism_set_option(as, ASTERISM_OPT_OUTER_BIND_ADDR, "tcp://0.0.0.0:1122");
    assert(!ret);
    ret = asterism_set_option(as, ASTERISM_OPT_INNER_BIND_ADDR, "http://0.0.0.0:8888");
    assert(!ret);

    ret = asterism_set_option(as, ASTERISM_OPT_USERNAME, "test");
    assert(!ret);
    ret = asterism_set_option(as, ASTERISM_OPT_PASSWORD, "test");
    assert(!ret);
    ret = asterism_set_option(as, ASTERISM_OPT_CONNECT_ADDR, "tcp://127.0.0.1:1122");
    assert(!ret);
    ret = asterism_set_option(as, ASTERISM_OPT_CONNECT_REDIRECT_HOOK, redirect_hook);
    assert(!ret);
    ret = asterism_set_option(as, ASTERISM_OPT_CONNECT_REDIRECT_HOOK_DATA, as);
    assert(!ret);
    ret = asterism_set_option(as, ASTERISM_OPT_HEARTBEAT_INTERVAL, 1000);
    assert(!ret);
    ret = asterism_set_option(as, ASTERISM_OPT_IDLE_TIMEOUT, IDLE_TIMEOUT);
    assert(!ret);
    ret = asterism_run(as);
    assert(!ret);

    asterism_destroy(as);
}

static void server_test_thread(void *arg)
{
    int srv = ut_server(1110);
    int clt = ut_accept(srv);
    char buffer[1024] = { 0 };
    assert(recv(clt, buffer, sizeof(buffer), 0) > 0);
    assert(strstr(buffer, (char*)arg) >= 0);
    assert(send(clt, HTTP_GET_RESP_200, (int)__CSLEN(HTTP_GET_RESP_200), 0) > 0);
    shutdown(clt, 0);
    ut_close(clt);
    ut_close(srv);
}

static void server_test_keep_alive_thread(void *arg)
{
    int srv = ut_server(1110);
    int clt = ut_accept(srv);
    char buffer[1024] = { 0 };
    assert(recv(clt, buffer, sizeof(buffer), 0) > 0);
    assert(strcmp(buffer, (char*)arg) == 0);
    assert(send(clt, HTTP_GET_RESP_200, (int)__CSLEN(HTTP_GET_RESP_200), 0) > 0);
    memset(buffer, 0, sizeof(buffer));
    assert(recv(clt, buffer, sizeof(buffer), 0) > 0);
    assert(strcmp(buffer, (char*)arg) == 0);
    assert(send(clt, HTTP_GET_RESP_200, (int)__CSLEN(HTTP_GET_RESP_200), 0) > 0);
    shutdown(clt, 0);
    ut_close(clt);
    ut_close(srv);
}

int asterism_test03()
{
    uv_thread_t tid;
    char buffer[1024] = { 0 };
    int sock = 0;
    asterism as = asterism_create();
    int ret = 0;

    assert(!uv_thread_create(&tid, asterism_test_thread, as));
    ut_sleep(100);

    {
        printf("http tunnel no auth test\n");

        sock = ut_connect("127.0.0.1", 8888);
        assert(send(sock, TEST_HTTP_CONNECT_REQ4, (int)strlen(TEST_HTTP_CONNECT_REQ4), 0) == strlen(TEST_HTTP_CONNECT_REQ4));
        memset(buffer, 0, sizeof(buffer));
        ut_sleep(100);
        assert(recv(sock, buffer, sizeof(buffer), 0) > 0);
        assert(strstr(buffer, "HTTP/1.1 407") == buffer);
        ut_close(sock);
    }

    {
        printf("http tunnel access baidu.com wrong auth test\n");

        sock = ut_connect("127.0.0.1", 8888);
        assert(send(sock, TEST_HTTP_CONNECT_REQ5, (int)strlen(TEST_HTTP_CONNECT_REQ5), 0) == strlen(TEST_HTTP_CONNECT_REQ5));
        memset(buffer, 0, sizeof(buffer));
        ut_sleep(100);
        assert(recv(sock, buffer, sizeof(buffer), 0) > 0);
        assert(strstr(buffer, "HTTP/1.1 407") == buffer);
        ut_close(sock);
    }

    {
        printf("normal http proxy test no auth\n");
        sock = ut_connect("127.0.0.1", 8888);
        assert(send(sock, TEST_HTTP_GET_REQ2, (int)strlen(TEST_HTTP_GET_REQ2), 0) == strlen(TEST_HTTP_GET_REQ2));
        memset(buffer, 0, sizeof(buffer));
        ut_sleep(100);
        assert(recv(sock, buffer, sizeof(buffer), 0) > 0);
        assert(strstr(buffer, "HTTP/1.1 407") == buffer);
        assert(recv(sock, buffer, sizeof(buffer), MSG_PEEK) == 0);
        ut_close(sock);
    }
    {
        printf("http tunnel access 127.0.0.1:1110 test\n");

        uv_thread_t server_tid;
        assert(!uv_thread_create(&server_tid, server_test_keep_alive_thread, TEST_HTTP_GET_REQ1));
        ut_sleep(100);

        sock = ut_connect("127.0.0.1", 8888);
        ret = send(sock, TEST_HTTP_CONNECT_REQ2, (int)strlen(TEST_HTTP_CONNECT_REQ2), 0);
        assert(ret == strlen(TEST_HTTP_CONNECT_REQ2));
        memset(buffer, 0, sizeof(buffer));
        ut_sleep(100);
        ret = recv(sock, buffer, sizeof(buffer), 0);
        assert(ret == strlen(HTTP_RESP_200));
        assert(strncmp(HTTP_RESP_200, buffer, ret) == 0);

        ret = send(sock, TEST_HTTP_GET_REQ1, (int)strlen(TEST_HTTP_GET_REQ1), 0);
        assert(ret == strlen(TEST_HTTP_GET_REQ1));
        memset(buffer, 0, sizeof(buffer));
        ut_sleep(100);
        assert(recv(sock, buffer, sizeof(buffer), 0) > 0);
        assert(strncmp(buffer, HTTP_GET_RESP_200, ret) == 0);

        printf("keep alive test\n");
        ret = send(sock, TEST_HTTP_GET_REQ1, (int)strlen(TEST_HTTP_GET_REQ1), 0);
        assert(ret == strlen(TEST_HTTP_GET_REQ1));
        memset(buffer, 0, sizeof(buffer));
        ut_sleep(100);
        ret = recv(sock, buffer, sizeof(buffer), 0);
        assert(ret > 0);
        assert(strncmp(buffer, HTTP_GET_RESP_200, ret) == 0);
        ut_close(sock);

        assert(!uv_thread_join(&server_tid));
    }

    {
        printf("normal http proxy test with auth\n");
        uv_thread_t server_tid;
        assert(!uv_thread_create(&server_tid, server_test_thread, "Host: 127.0.0.1:1110"));
        ut_sleep(100);

        sock = ut_connect("127.0.0.1", 8888);
        assert(send(sock, TEST_HTTP_GET_REQ3, (int)strlen(TEST_HTTP_GET_REQ3), 0) == strlen(TEST_HTTP_GET_REQ3));
        memset(buffer, 0, sizeof(buffer));
        ut_sleep(100);

        assert(recv(sock, buffer, sizeof(buffer), 0) > 0);
        assert(strncmp(buffer, HTTP_GET_RESP_200, ret) == 0);
        ut_close(sock);

        assert(!uv_thread_join(&server_tid));
    }

    {
        printf("normal http proxy test with auth\n");
        uv_thread_t server_tid;
        assert(!uv_thread_create(&server_tid, server_test_thread, "Host: 127.0.0.1:1110"));
        ut_sleep(100);

        sock = ut_connect("127.0.0.1", 8888);
        assert(send(sock, TEST_HTTP_GET_REQ3, (int)strlen(TEST_HTTP_GET_REQ3), 0) == strlen(TEST_HTTP_GET_REQ3));
        memset(buffer, 0, sizeof(buffer));
        ut_sleep(100);
        assert(recv(sock, buffer, sizeof(buffer), 0) > 0);
        assert(strncmp(buffer, HTTP_GET_RESP_200, ret) == 0);
        ut_close(sock);

        assert(!uv_thread_join(&server_tid));
    }

    {
        printf("normal http proxy send one by one test\n");
        uv_thread_t server_tid;
        assert(!uv_thread_create(&server_tid, server_test_thread, "Host: 127.0.0.1:1110"));
        ut_sleep(100);

        sock = ut_connect("127.0.0.1", 8888);
        for (int i = 0; i < __CSLEN(TEST_HTTP_GET_REQ3); i++)
        {
            assert(send(sock, TEST_HTTP_GET_REQ3 + i, 1, 0) == 1);
        }
        memset(buffer, 0, sizeof(buffer));
        ut_sleep(100);
        assert(recv(sock, buffer, sizeof(buffer), 0) > 0);
        assert(strncmp(buffer, HTTP_GET_RESP_200, ret) == 0);
        ut_close(sock);

        assert(!uv_thread_join(&server_tid));
    }

    {
        printf("test use hook forbiden access www.baidu.com\n");
        sock = ut_connect("127.0.0.1", 8888);
        ret = send(sock, TEST_HTTP_CONNECT_REQ1, (int)strlen(TEST_HTTP_CONNECT_REQ1), 0);
        assert(ret == strlen(TEST_HTTP_CONNECT_REQ1));
        memset(buffer, 0, sizeof(buffer));
        assert(!recv(sock, buffer, sizeof(buffer), 0));
        ut_close(sock);
    }

    {
        uv_thread_t server_tid;
        assert(!uv_thread_create(&server_tid, server_test_thread, "Host: 127.0.0.1:1110"));
        ut_sleep(100);

        printf("redirect_hook www.hi-asterism.com:80 => 127.0.0.1:1110 test\n");
        sock = ut_connect("127.0.0.1", 8888);
        ret = send(sock, TEST_HTTP_CONNECT_REQ3, (int)strlen(TEST_HTTP_CONNECT_REQ3), 0);
        assert(ret == strlen(TEST_HTTP_CONNECT_REQ3));
        memset(buffer, 0, sizeof(buffer));
        ut_sleep(100);
        ret = recv(sock, buffer, sizeof(buffer), 0);
        assert(ret == strlen(HTTP_CONNECT_RESP_200));
        assert(strncmp(HTTP_CONNECT_RESP_200, buffer, ret) == 0);

        ret = send(sock, TEST_HTTP_GET_REQ1, (int)strlen(TEST_HTTP_GET_REQ1), 0);
        assert(ret == strlen(TEST_HTTP_GET_REQ1));
        memset(buffer, 0, sizeof(buffer));
        ut_sleep(100);
        ret = recv(sock, buffer, sizeof(buffer), 0);
        assert(ret > 0);
        assert(strncmp(buffer, HTTP_GET_RESP_200, ret)== 0);
        ut_close(sock);
    }

    {
        printf("connection idle timeout test\n");
        sock = ut_connect("127.0.0.1", 8888);
        time_t t = time(0);
        ret = recv(sock, buffer, sizeof(buffer), 0);
        assert(!ret);
        assert(time(0) - t >= IDLE_TIMEOUT);
        assert(time(0) - t <= IDLE_TIMEOUT + 1);
        ut_close(sock);
    }

    ut_sleep(100);
    asterism_stop(as);
    ret = uv_thread_join(&tid);
    assert(!ret);
    return ret;
}
#endif