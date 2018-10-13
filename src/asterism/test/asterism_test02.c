#include "asterism_test02.h"

#ifdef UNIT_TEST

static char *redirect_hook(char *target_addr, void *data)
{
    printf("remote request %s\n", target_addr);
    if (strcmp(target_addr, "www.baidu.com:80") == 0)
    {
        return 0;
    }
    else if (strcmp(target_addr, "exit:80") == 0)
    {
        return 0;
    }
    return (char *)target_addr;
}

static void asterism_test_thread(void* arg)
{
    int ret = 0;
    asterism as = asterism_create();
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
    ret = asterism_run(as);
    assert(!ret);

    asterism_destroy(as);
}

#define HTTP_CONNECT_REQ \
"CONNECT www.baidu.com:80 HTTP/1.1\r\n"\
"Host: www.baidu.com:80\r\n"\
"Proxy-Connection: Keep-Alive\r\n"\
"Proxy-Authorization: Basic dGVzdDp0ZXN0\r\n\r\n"

int asterism_test02()
{
    uv_thread_t tid;
    int ret = uv_thread_create(&tid, asterism_test_thread, 0);
    assert(!ret);

    int sock = ut_connect("127.0.0.1", 8888);
    ret = send(sock, HTTP_CONNECT_REQ, strlen(HTTP_CONNECT_REQ), 0);

    char buffer[1024] = {0};
    read(sock, buffer, sizeof(buffer));

    ret = uv_thread_join(&tid);
    assert(!ret);
    return ret;
}
#endif