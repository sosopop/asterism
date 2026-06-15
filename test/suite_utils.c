#include "test_framework.h"
#include "asterism_core.h"
#include "asterism.h"
#include "asterism_utils.h"

static void test_utils_slist(void) {
    struct asterism_slist *route_list = 0;
    route_list = asterism_slist_append(route_list, "test1");
    route_list = asterism_slist_append(route_list, "test2");
    route_list = asterism_slist_append(route_list, "test3");
    
    struct asterism_slist *temp_route_list = route_list;
    int i = 1;
    while (temp_route_list) {
        char *temp_buf = 0;
        asterism_snprintf(&temp_buf, 0, "test%d", i++);
        EXPECT_STR_EQ(temp_buf, temp_route_list->data);
        AS_FREE(temp_buf);
        temp_route_list = temp_route_list->next;
    }
    asterism_slist_free_all(route_list);
}

static void test_utils_string(void) {
    struct asterism_str str = asterism_mk_str("test");
    EXPECT_EQ(memcmp(str.p, "test", str.len), 0);
    
    str = asterism_mk_str_n("test", 3);
    EXPECT_EQ(memcmp(str.p, "tes", str.len), 0);
    EXPECT_EQ(asterism_vcmp(&str, "tes"), 0);
    EXPECT_TRUE(asterism_vcmp(&str, "test") < 0);
    EXPECT_TRUE(asterism_vcmp(&str, "te") > 0);
    EXPECT_EQ(asterism_vcasecmp(&str, "TES"), 0);

    struct asterism_str str1 = asterism_strdup(str);
    EXPECT_EQ(asterism_vcasecmp(&str1, "TES"), 0);
    EXPECT_EQ(str1.len, 3);
    asterism_free((void *)str1.p);

    str1 = asterism_strdup_nul(str);
    EXPECT_EQ(asterism_vcasecmp(&str1, "TES"), 0);
    EXPECT_EQ(str1.len, 3);
    EXPECT_EQ(str1.p - asterism_strchr(str1, 'e'), -1);
    asterism_free((void *)str1.p);

    str1 = asterism_mk_str("test");
    EXPECT_EQ(asterism_strcmp(str1, str1), 0);
    EXPECT_TRUE(asterism_strcmp(str1, str) > 0);
    EXPECT_EQ(asterism_strncmp(str1, str1, 1), 0);
    EXPECT_EQ(asterism_strncmp(str1, str, 3), 0);

    str1 = asterism_mk_str(" test ");
    str1 = asterism_strstrip(str1);
    EXPECT_EQ(asterism_strcmp(str1, asterism_mk_str("test")), 0);
    EXPECT_TRUE(asterism_strcmp(str1, asterism_mk_str(" test ")) > 0);
}

static void test_utils_address_parse(void) {
    struct asterism_str scheme;
    struct asterism_str host;
    unsigned int port;
    asterism_host_type host_type;
    int ret;

    scheme.len = 0;
    host.len = 0;
    ret = asterism_parse_address("http://10.0.0.1:1080", &scheme, &host, &port, &host_type);
    EXPECT_EQ(ret, 0);
    EXPECT_EQ(host_type, ASTERISM_HOST_TYPE_IPV4);
    EXPECT_EQ(asterism_vcasecmp(&scheme, "http"), 0);
    EXPECT_EQ(asterism_vcasecmp(&host, "10.0.0.1"), 0);
    EXPECT_EQ(port, 1080);

    scheme.len = 0;
    host.len = 0;
    ret = asterism_parse_address("tcp://[3ffe:2a00:100:7031::1]:8080", &scheme, &host, &port, &host_type);
    EXPECT_EQ(ret, 0);
    EXPECT_EQ(host_type, ASTERISM_HOST_TYPE_IPV6);
    EXPECT_EQ(asterism_vcasecmp(&scheme, "tcp"), 0);
    EXPECT_EQ(asterism_vcasecmp(&host, "3ffe:2a00:100:7031::1"), 0);
    EXPECT_EQ(port, 8080);

    scheme.len = 0;
    host.len = 0;
    ret = asterism_parse_address("http://www.baidu.com:8080", &scheme, &host, &port, &host_type);
    EXPECT_EQ(ret, 0);
    EXPECT_EQ(host_type, ASTERISM_HOST_TYPE_DOMAIN);
    EXPECT_EQ(asterism_vcasecmp(&scheme, "http"), 0);
    EXPECT_EQ(asterism_vcasecmp(&host, "www.baidu.com"), 0);
    EXPECT_EQ(port, 8080);

    scheme.len = 0;
    host.len = 0;
    ret = asterism_parse_address("www.baidu.com:8080", &scheme, &host, &port, &host_type);
    EXPECT_EQ(ret, 0);
    EXPECT_EQ(host_type, ASTERISM_HOST_TYPE_DOMAIN);
    EXPECT_TRUE(asterism_str_empty(&scheme));
    EXPECT_EQ(asterism_vcasecmp(&host, "www.baidu.com"), 0);
    EXPECT_EQ(port, 8080);

    scheme.len = 0;
    host.len = 0;
    ret = asterism_parse_address("10.0.0.2:1080", &scheme, &host, &port, &host_type);
    EXPECT_EQ(ret, 0);
    EXPECT_EQ(host_type, ASTERISM_HOST_TYPE_IPV4);
    EXPECT_TRUE(asterism_str_empty(&scheme));
    EXPECT_EQ(asterism_vcasecmp(&host, "10.0.0.2"), 0);
    EXPECT_EQ(port, 1080);
}

void register_suite_utils(void) {
    register_test("Utils", "SList", test_utils_slist);
    register_test("Utils", "String", test_utils_string);
    register_test("Utils", "AddressParse", test_utils_address_parse);
}
