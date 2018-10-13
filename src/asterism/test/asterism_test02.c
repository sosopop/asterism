#include "asterism_test02.h"
#include "../asterism_inner_http.h"
#include "../asterism_core.h"

#ifdef UNIT_TEST

static char *redirect_hook(char *target_addr, void *data)
{
    //printf("remote request %s\n", target_addr);
    if (strcmp(target_addr, "www.baidu.com:80") == 0)
    {
        return 0;
    }
    else if (strcmp(target_addr, "www.hi-asterism.com:80") == 0)
    {
        char *buf = asterism_alloc(sizeof("www.baidu.com:80"));
        memcpy(buf, "www.baidu.com:80", sizeof("www.baidu.com:80"));
        return buf;
    }
    return target_addr;
}

static asterism as = 0;

static void asterism_test_thread(void *arg)
{
    asterism_set_log_level(ASTERISM_LOG_DEBUG);

    int ret = 0;
    as = asterism_create();
    assert(as);
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
    ut_sleep(4000);
    ret = asterism_run(as);
    assert(!ret);

    asterism_destroy(as);
}

#define TEST_HTTP_CONNECT_REQ1              \
    "CONNECT www.baidu.com:80 HTTP/1.1\r\n" \
    "Host: www.baidu.com:80\r\n"            \
    "Proxy-Connection: Keep-Alive\r\n"      \
    "Proxy-Authorization: Basic dGVzdDp0ZXN0\r\n\r\n"

#define TEST_HTTP_CONNECT_REQ2          \
    "CONNECT baidu.com:80 HTTP/1.1\r\n" \
    "Host: baidu.com:80\r\n"            \
    "Proxy-Connection: Keep-Alive\r\n"  \
    "Proxy-Authorization: Basic dGVzdDp0ZXN0\r\n\r\n"

#define TEST_HTTP_CONNECT_REQ3                    \
    "CONNECT www.hi-asterism.com:80 HTTP/1.1\r\n" \
    "Host: www.hi-asterism.com:80\r\n"            \
    "Proxy-Connection: Keep-Alive\r\n"            \
    "Proxy-Authorization: Basic dGVzdDp0ZXN0\r\n\r\n"

#define TEST_HTTP_CONNECT_REQ4          \
    "CONNECT baidu.com:80 HTTP/1.1\r\n" \
    "Host: baidu.com:80\r\n"            \
    "Proxy-Connection: Keep-Alive\r\n\r\n"

#define TEST_HTTP_GET_REQ1  \
    "GET / HTTP/1.1\r\n"    \
    "Host: baidu.com\r\n"   \
    "Range: bytes=0-10\r\n" \
    "Connection: keep-alive\r\n\r\n"

#define TEST_HTTP_GET_REQ2               \
    "GET http://baidu.com/ HTTP/1.1\r\n" \
    "Host: baidu.com\r\n"                \
    "Range: bytes=0-10\r\n"              \
    "Connection: keep-alive\r\n\r\n"

#define TEST_HTTP_GET_REQ3               \
    "GET http://baidu.com/ HTTP/1.1\r\n" \
    "Host: baidu.com\r\n"                \
    "Range: bytes=0-10\r\n"              \
    "Connection: keep-alive\r\n"         \
    "Proxy-Authorization: Basic dGVzdDp0ZXN0\r\n\r\n"

int asterism_test02()
{
    uv_thread_t tid;
    char buffer[1024] = {0};
    int sock = 0;
    int ret = uv_thread_create(&tid, asterism_test_thread, 0);
    assert(!ret);
    ut_sleep(5000);

    printf("test use hook forbiden access www.baidu.com\n");
    sock = ut_connect("127.0.0.1", 8888);
    ret = send(sock, TEST_HTTP_CONNECT_REQ1, (int)strlen(TEST_HTTP_CONNECT_REQ1), 0);
    assert(ret == strlen(TEST_HTTP_CONNECT_REQ1));
    memset(buffer, 0, sizeof(buffer));
    ret = recv(sock, buffer, sizeof(buffer), 0);
    assert(!ret);
    ut_close(sock);

    printf("http tunnel access baidu.com no auth test\n");
    sock = ut_connect("127.0.0.1", 8888);
    ret = send(sock, TEST_HTTP_CONNECT_REQ4, (int)strlen(TEST_HTTP_CONNECT_REQ4), 0);
    assert(ret == strlen(TEST_HTTP_CONNECT_REQ4));
    memset(buffer, 0, sizeof(buffer));
    ut_sleep(1000);
    ret = recv(sock, buffer, sizeof(buffer), 0);
    assert(ret > 0);
    assert(strstr(buffer, "HTTP/1.1 407") == buffer);
    ut_close(sock);

    printf("http tunnel access baidu.com test\n");
    sock = ut_connect("127.0.0.1", 8888);
    ret = send(sock, TEST_HTTP_CONNECT_REQ2, (int)strlen(TEST_HTTP_CONNECT_REQ2), 0);
    assert(ret == strlen(TEST_HTTP_CONNECT_REQ2));
    memset(buffer, 0, sizeof(buffer));
    ut_sleep(1000);
    ret = recv(sock, buffer, sizeof(buffer), 0);
    assert(ret == strlen(HTTP_RESP_200));
    assert(strncmp(HTTP_RESP_200, buffer, ret) == 0);

    ret = send(sock, TEST_HTTP_GET_REQ1, (int)strlen(TEST_HTTP_GET_REQ1), 0);
    assert(ret == strlen(TEST_HTTP_GET_REQ1));
    memset(buffer, 0, sizeof(buffer));
    ut_sleep(1000);
    ret = recv(sock, buffer, sizeof(buffer), 0);
    assert(ret > 0);
    assert(strstr(buffer, "HTTP/1.1 20") == buffer);

    printf("keep alive test\n");
    ret = send(sock, TEST_HTTP_GET_REQ1, (int)strlen(TEST_HTTP_GET_REQ1), 0);
    assert(ret == strlen(TEST_HTTP_GET_REQ1));
    memset(buffer, 0, sizeof(buffer));
    ut_sleep(1000);
    ret = recv(sock, buffer, sizeof(buffer), 0);
    assert(ret > 0);
    assert(strstr(buffer, "HTTP/1.1 20") == buffer);
    ut_close(sock);

    printf("normal http proxy test no auth\n");
    sock = ut_connect("127.0.0.1", 8888);
    ret = send(sock, TEST_HTTP_GET_REQ2, (int)strlen(TEST_HTTP_GET_REQ2), 0);
    assert(ret == strlen(TEST_HTTP_GET_REQ2));
    memset(buffer, 0, sizeof(buffer));
    ut_sleep(1000);
    ret = recv(sock, buffer, sizeof(buffer), 0);
    assert(ret > 0);
    assert(strstr(buffer, "HTTP/1.1 407") == buffer);
    ret = recv(sock, buffer, sizeof(buffer), MSG_PEEK);
    assert(ret == 0);
    ut_close(sock);

    printf("normal http proxy test with auth\n");
    sock = ut_connect("127.0.0.1", 8888);
    ret = send(sock, TEST_HTTP_GET_REQ3, (int)strlen(TEST_HTTP_GET_REQ3), 0);
    assert(ret == strlen(TEST_HTTP_GET_REQ3));
    memset(buffer, 0, sizeof(buffer));
    ut_sleep(1000);
    ret = recv(sock, buffer, sizeof(buffer), 0);
    assert(ret > 0);
    assert(strstr(buffer, "HTTP/1.1 20") == buffer);
    ut_close(sock);

    printf("redirect_hook www.hi-asterism.com:80 => baidu.com test\n");
    sock = ut_connect("127.0.0.1", 8888);
    ret = send(sock, TEST_HTTP_CONNECT_REQ3, (int)strlen(TEST_HTTP_CONNECT_REQ3), 0);
    assert(ret == strlen(TEST_HTTP_CONNECT_REQ3));
    memset(buffer, 0, sizeof(buffer));
    ut_sleep(1000);
    ret = recv(sock, buffer, sizeof(buffer), 0);
    assert(ret == strlen(HTTP_RESP_200));
    assert(strncmp(HTTP_RESP_200, buffer, ret) == 0);

    ret = send(sock, TEST_HTTP_GET_REQ1, (int)strlen(TEST_HTTP_GET_REQ1), 0);
    assert(ret == strlen(TEST_HTTP_GET_REQ1));
    memset(buffer, 0, sizeof(buffer));
    ut_sleep(1000);
    ret = recv(sock, buffer, sizeof(buffer), 0);
    assert(ret > 0);
    assert(strstr(buffer, "BAIDUID") > 0);
    ut_close(sock);

    printf("connection idle timeout test\n");
    sock = ut_connect("127.0.0.1", 8888);
    time_t t = time(0);
    ret = recv(sock, buffer, sizeof(buffer), 0);
    assert(!ret);
    assert(time(0) - t > ASTERISM_CONNECTION_MAX_IDLE_COUNT - 2);
    assert(time(0) - t < ASTERISM_CONNECTION_MAX_IDLE_COUNT + 2);
    ut_close(sock);

    ut_sleep(1000);
    asterism_stop(as);
    ret = uv_thread_join(&tid);
    assert(!ret);
    return ret;
}
#endif