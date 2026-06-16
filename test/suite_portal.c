#include "test_framework.h"
#include "test_utils.h"
#include "asterism_portal.h"
#include <stdio.h>
#include <string.h>

static void run_portal_thread(void *arg) {
    asterism as = (asterism)arg;
    asterism_run(as);
}

static void test_portal_parse_rules(void) {
    struct asterism_portal_config_s config;
    memset(&config, 0, sizeof(config));

    // Test with scheme and credentials
    int r = asterism_portal_parse_rule("127.0.0.1:3306#http://admin:admin123@1.2.3.4:8011#192.168.1.100:3306", &config);
    EXPECT_EQ(r, 0);
    if (r == 0) {
        EXPECT_STR_EQ(config.local_host, "127.0.0.1");
        EXPECT_EQ(config.local_port, 3306);
        EXPECT_STR_EQ(config.relay_host, "1.2.3.4");
        EXPECT_EQ(config.relay_port, 8011);
        EXPECT_STR_EQ(config.relay_user, "admin");
        EXPECT_STR_EQ(config.relay_pass, "admin123");
        EXPECT_STR_EQ(config.remote_host, "192.168.1.100");
        EXPECT_EQ(config.remote_port, 3306);
        asterism_portal_free_config(&config);
    }

    // Test without scheme and credentials
    memset(&config, 0, sizeof(config));
    r = asterism_portal_parse_rule("0.0.0.0:1080#1.1.1.1:8080#8.8.8.8:53", &config);
    EXPECT_EQ(r, 0);
    if (r == 0) {
        EXPECT_STR_EQ(config.local_host, "0.0.0.0");
        EXPECT_EQ(config.local_port, 1080);
        EXPECT_STR_EQ(config.relay_host, "1.1.1.1");
        EXPECT_EQ(config.relay_port, 8080);
        EXPECT_TRUE(config.relay_user == NULL);
        EXPECT_TRUE(config.relay_pass == NULL);
        EXPECT_STR_EQ(config.remote_host, "8.8.8.8");
        EXPECT_EQ(config.remote_port, 53);
        asterism_portal_free_config(&config);
    }

    memset(&config, 0, sizeof(config));
    char long_rule[900];
    memset(long_rule, 'a', sizeof(long_rule));
    long_rule[sizeof(long_rule) - 1] = '\0';
    r = asterism_portal_parse_rule(long_rule, &config);
    EXPECT_EQ(r, -1);

    memset(&config, 0, sizeof(config));
    r = asterism_portal_parse_rule("127.0.0.1:3306#127.0.0.1:8080", &config);
    EXPECT_EQ(r, -1);

    memset(&config, 0, sizeof(config));
    r = asterism_portal_parse_rule("udp://127.0.0.1:3306#http://127.0.0.1:8080#127.0.0.1:3306", &config);
    EXPECT_EQ(r, -1);
    EXPECT_TRUE(config.local_host == NULL);
    EXPECT_TRUE(config.remote_host == NULL);

    memset(&config, 0, sizeof(config));
    r = asterism_portal_parse_rule("127.0.0.1:3306#socks5://127.0.0.1:8080#127.0.0.1:3306", &config);
    EXPECT_EQ(r, -1);
    EXPECT_TRUE(config.local_host == NULL);
    EXPECT_TRUE(config.remote_host == NULL);
    EXPECT_TRUE(config.relay_user == NULL);

    char long_host[320];
    memset(long_host, 'a', sizeof(long_host) - 1);
    long_host[sizeof(long_host) - 1] = '\0';
    char invalid_rule[768];
    snprintf(invalid_rule, sizeof(invalid_rule),
             "127.0.0.1:3306#http://127.0.0.1:8080#%s:3306", long_host);
    memset(&config, 0, sizeof(config));
    r = asterism_portal_parse_rule(invalid_rule, &config);
    EXPECT_EQ(r, -1);
    EXPECT_TRUE(config.local_host == NULL);
    EXPECT_TRUE(config.remote_host == NULL);

    char long_credential[520];
    memset(long_credential, 'b', sizeof(long_credential) - 1);
    long_credential[sizeof(long_credential) - 1] = '\0';
    snprintf(invalid_rule, sizeof(invalid_rule),
             "127.0.0.1:3306#http://%s@127.0.0.1:8080#127.0.0.1:3306",
             long_credential);
    memset(&config, 0, sizeof(config));
    r = asterism_portal_parse_rule(invalid_rule, &config);
    EXPECT_EQ(r, -1);
    EXPECT_TRUE(config.local_host == NULL);
    EXPECT_TRUE(config.remote_host == NULL);
    EXPECT_TRUE(config.relay_user == NULL);
}

static void test_portal_forwarding(void) {
    test_env_t *env = test_env_create(NULL, 0);
    EXPECT_TRUE(env != NULL);
    if (!env) return;

    // Start a mock target TCP server
    char expected_req[] = "GET / HTTP/1.1";
    mock_server_args_t mock_args;
    mock_args.port = env->mock_port;
    mock_args.expected_req = expected_req;

    uv_thread_t server_tid;
    int r = uv_thread_create(&server_tid, mock_server_thread, &mock_args);
    EXPECT_EQ(r, 0);
    test_sleep(100);

    // Create Portal asterism instance
    asterism as_portal = asterism_create();
    EXPECT_TRUE(as_portal != 0);

    unsigned short local_port = test_get_free_port();
    char rule[512];
    sprintf(rule, "127.0.0.1:%u#http://test:test@127.0.0.1:%u#127.0.0.1:%u", local_port, env->inner_port, env->mock_port);

    r = asterism_set_option(as_portal, ASTERISM_OPT_PORTAL, rule);
    EXPECT_EQ(r, 0);

    uv_thread_t portal_tid;
    r = uv_thread_create(&portal_tid, run_portal_thread, as_portal);
    EXPECT_EQ(r, 0);
    test_sleep(200);

    // Now connect to local_port
    int sock = test_socket_connect("127.0.0.1", local_port);
    EXPECT_TRUE(sock >= 0);
    if (sock >= 0) {
        // Send request
        int ret = send(sock, expected_req, (int)strlen(expected_req), 0);
        EXPECT_EQ(ret, (int)strlen(expected_req));

        // Wait for response
        char buf[256] = {0};
        test_sleep(200);
        ret = recv(sock, buf, sizeof(buf) - 1, 0);
        EXPECT_TRUE(ret > 0);
        EXPECT_TRUE(strstr(buf, "HTTP/1.1 200 ok") != NULL);

        test_socket_close(sock);
    }

    // Stop portal
    asterism_stop(as_portal);
    uv_thread_join(&portal_tid);
    asterism_destroy(as_portal);

    uv_thread_join(&server_tid);
    test_env_destroy(env);
}

void register_suite_portal(void) {
    register_test("Portal", "ParseRules", test_portal_parse_rules);
    register_test("Portal", "Forwarding", test_portal_forwarding);
}
