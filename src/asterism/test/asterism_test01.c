#include "asterism_test01.h"
#include "../asterism_core.h"
#include "../asterism.h"
#include "../asterism_utils.h"
#include <stdlib.h>
#include <assert.h>

int asterism_test01()
{
    int ret = ASTERISM_E_OK;
    asterism_set_log_level(ASTERISM_LOG_DEBUG);
    //test asterism_slist
    struct asterism_slist *route_list = 0;
    route_list = asterism_slist_append(route_list, "test1");
    route_list = asterism_slist_append(route_list, "test2");
    route_list = asterism_slist_append(route_list, "test3");
    struct asterism_slist *temp_route_list = route_list;
    int i = 1;
    while (temp_route_list)
    {
        char *temp_buf = 0;
        asterism_snprintf(&temp_buf, 0, "test%d", i++);
        assert(strcmp(temp_buf, temp_route_list->data) == 0);
        AS_FREE(temp_buf);
        printf("list data: %s\n", temp_route_list->data);
        temp_route_list = temp_route_list->next;
    }
    asterism_slist_free_all(route_list);

    //test asterism string
    struct asterism_str str = asterism_mk_str("test");
    assert(memcmp(str.p, "test", str.len) == 0);
    str = asterism_mk_str_n("test", 3);
    assert(memcmp(str.p, "tes", str.len) == 0);
    assert(asterism_vcmp(&str, "tes") == 0);
    assert(asterism_vcmp(&str, "test") < 0);
    assert(asterism_vcmp(&str, "te") > 0);
    assert(asterism_vcasecmp(&str, "TES") == 0);

    struct asterism_str str1 = asterism_strdup(str);
    assert(asterism_vcasecmp(&str1, "TES") == 0);
    assert(str1.len == 3);
    asterism_free((void *)str1.p);

    str1 = asterism_strdup_nul(str);
    assert(asterism_vcasecmp(&str1, "TES") == 0);
    assert(str1.len == 3);

    assert(str1.p - asterism_strchr(str1, 'e') == -1);
    asterism_free((void *)str1.p);

    str1 = asterism_mk_str("test");
    assert(asterism_strcmp(str1, str1) == 0);
    assert(asterism_strcmp(str1, str) > 0);
    assert(asterism_strncmp(str1, str1, 1) == 0);
    assert(asterism_strncmp(str1, str, 3) == 0);

    str1 = asterism_mk_str(" test ");
    str1 = asterism_strstrip(str1);
    assert(asterism_strcmp(str1, asterism_mk_str("test")) == 0);
    assert(asterism_strcmp(str1, asterism_mk_str(" test ")) > 0);

    //url parse
    struct asterism_str scheme;
    struct asterism_str host;
    unsigned int port;
    asterism_host_type host_type;
    scheme.len = 0;
    host.len = 0;
    ret = asterism_parse_address("http://10.0.0.1:1080", &scheme, &host, &port, &host_type);
    assert(ret == 0 && host_type == ASTERISM_HOST_TYPE_IPV4 && asterism_vcasecmp(&scheme, "http") == 0 && asterism_vcasecmp(&host, "10.0.0.1") == 0 && port == 1080);

    scheme.len = 0;
    host.len = 0;
    ret = asterism_parse_address("tcp://[3ffe:2a00:100:7031::1]:8080", &scheme, &host, &port, &host_type);
    assert(ret == 0 && host_type == ASTERISM_HOST_TYPE_IPV6 && asterism_vcasecmp(&scheme, "tcp") == 0 && asterism_vcasecmp(&host, "3ffe:2a00:100:7031::1") == 0 && port == 8080);

    scheme.len = 0;
    host.len = 0;
    ret = asterism_parse_address("http://www.baidu.com:8080", &scheme, &host, &port, &host_type);
    assert(ret == 0 && host_type == ASTERISM_HOST_TYPE_DOMAIN && asterism_vcasecmp(&scheme, "http") == 0 && asterism_vcasecmp(&host, "www.baidu.com") == 0 && port == 8080);

    scheme.len = 0;
    host.len = 0;
    ret = asterism_parse_address("www.baidu.com:8080", &scheme, &host, &port, &host_type);
    assert(ret == 0 && host_type == ASTERISM_HOST_TYPE_DOMAIN && asterism_str_empty(&scheme) && asterism_vcasecmp(&host, "www.baidu.com") == 0 && port == 8080);

    scheme.len = 0;
    host.len = 0;
    ret = asterism_parse_address("10.0.0.2:1080", &scheme, &host, &port, &host_type);
    assert(ret == 0 && host_type == ASTERISM_HOST_TYPE_IPV4 && asterism_str_empty(&scheme) && asterism_vcasecmp(&host, "10.0.0.2") == 0 && port == 1080);

    //je_malloc_stats_print(0, 0, 0);
    void *mdata = AS_MALLOC(4096);
    size_t t = je_malloc_usable_size(mdata);
    //je_malloc_stats_print(0, 0, 0);
    AS_FREE(mdata);

    int a = GetTickCount();
    for (int i = 0; i < 1000000; i++)
    {
        void *mdata = malloc(4096);
        free(mdata);
    }
    printf("spend: %d\n", GetTickCount() - a);

    a = GetTickCount();
    for (int i = 0; i < 1000000; i++)
    {
        void *mdata = AS_MALLOC(4096);
        AS_FREE(mdata);
    }
    printf("spend: %d\n", GetTickCount() - a);

    //je_malloc_stats_print(0, 0, 0);
    return ret;
}