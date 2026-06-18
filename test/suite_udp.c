#include "test_framework.h"
#include "test_utils.h"
#include "asterism.h"
#include "asterism_core.h"
#include <stdio.h>
#include <string.h>

// ---------------------------------------------------------------------------
// SOCKS5 UDP request packet builders (RSV(2) FRAG(1) ATYP(1) ADDR PORT DATA)
// ---------------------------------------------------------------------------

static int build_udp_ipv4_packet(unsigned char *out, const char *ip,
                                 unsigned short port, const void *data, int data_len) {
    out[0] = 0; out[1] = 0; out[2] = 0; out[3] = 0x01;
    struct in_addr a;
    uv_inet_pton(AF_INET, ip, &a);
    memcpy(out + 4, &a, 4);
    unsigned short np = htons(port);
    memcpy(out + 8, &np, 2);
    if (data_len) memcpy(out + 10, data, data_len);
    return 10 + data_len;
}

static int build_udp_ipv6_packet(unsigned char *out, const char *ip6,
                                 unsigned short port, const void *data, int data_len) {
    out[0] = 0; out[1] = 0; out[2] = 0; out[3] = 0x04;
    struct in6_addr a6;
    uv_inet_pton(AF_INET6, ip6, &a6);
    memcpy(out + 4, &a6, 16);
    unsigned short np = htons(port);
    memcpy(out + 20, &np, 2);
    if (data_len) memcpy(out + 22, data, data_len);
    return 22 + data_len;
}

static int build_udp_domain_packet(unsigned char *out, const char *domain,
                                   unsigned short port, const void *data, int data_len) {
    unsigned char host_len = (unsigned char)strlen(domain);
    out[0] = 0; out[1] = 0; out[2] = 0; out[3] = 0x03;
    out[4] = host_len;
    memcpy(out + 5, domain, host_len);
    unsigned short np = htons(port);
    memcpy(out + 5 + host_len, &np, 2);
    if (data_len) memcpy(out + 7 + host_len, data, data_len);
    return 7 + host_len + data_len;
}

// Send a prebuilt SOCKS5 UDP datagram to the relay and receive one reply.
// Returns the received length (or <= 0 on timeout/error).
static int udp_xchg(int client, struct sockaddr_in *relay,
                    const unsigned char *pkt, int pkt_len,
                    unsigned char *resp, int resp_cap) {
    if (sendto(client, (const char *)pkt, pkt_len, 0,
               (struct sockaddr *)relay, sizeof(*relay)) != pkt_len)
        return -1;
    struct sockaddr_storage peer;
    socklen_t peer_len = sizeof(peer);
    return recvfrom(client, (char *)resp, resp_cap, 0,
                    (struct sockaddr *)&peer, &peer_len);
}

// Open a SOCKS5 control connection and UDP-associate; returns control fd and
// sets *relay_udp_port, or -1.
static int udp_open_session(test_env_t *env, unsigned short *relay_udp_port) {
    int control = test_socket_connect("127.0.0.1", env->inner_port);
    if (control < 0) return -1;
    if (test_socks5_udp_associate(control, relay_udp_port) != 0) {
        test_socket_close(control);
        return -1;
    }
    return control;
}

static int make_udp_client(struct sockaddr_in *relay, unsigned short relay_port) {
    int udp_client = (int)socket(AF_INET, SOCK_DGRAM, 0);
    if (udp_client < 0) return -1;
    test_set_socket_recv_timeout(udp_client, 5000);
    uv_ip4_addr("127.0.0.1", relay_port, relay);
    return udp_client;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

static void test_udp_ipv4_roundtrip(void) {
    test_env_t *env = test_env_create_ex("socks5", NULL, 0, 0);
    EXPECT_TRUE(env != NULL);
    if (!env) return;
    EXPECT_EQ(asterism_set_option(env->as, ASTERISM_OPT_SOCKS5_UDP, 1), 0);

    unsigned short echo_port = 0;
    int echo = test_create_udp_echo_socket(AF_INET, &echo_port);
    EXPECT_TRUE(echo >= 0);
    if (echo < 0) { test_env_destroy(env); return; }

    udp_echo_args_t echo_args = {echo, 2};
    uv_thread_t echo_tid;
    EXPECT_EQ(uv_thread_create(&echo_tid, test_udp_echo_thread, &echo_args), 0);

    unsigned short relay_port = 0;
    int control = udp_open_session(env, &relay_port);
    EXPECT_TRUE(control >= 0);
    if (control >= 0) {
        struct sockaddr_in relay;
        int udp_client = make_udp_client(&relay, relay_port);
        EXPECT_TRUE(udp_client >= 0);
        if (udp_client >= 0) {
            for (int i = 0; i < 2; i++) {
                unsigned char pkt[64];
                const char *payload = (i == 0) ? "ping" : "pong";
                int pkt_len = build_udp_ipv4_packet(pkt, "127.0.0.1", echo_port, payload, 4);
                unsigned char resp[128] = {0};
                int n = udp_xchg(udp_client, &relay, pkt, pkt_len, resp, sizeof(resp));
                EXPECT_EQ(n, 14);                       // 10-byte header + 4 data
                EXPECT_EQ((unsigned char)resp[3], 0x01); // ATYP IPv4 in reply
                unsigned short rp = 0;
                memcpy(&rp, resp + 8, 2);
                EXPECT_EQ(ntohs(rp), echo_port);        // DST.PORT echoed back
                EXPECT_EQ(memcmp(resp + 10, payload, 4), 0);
            }
            test_socket_close(udp_client);
        }
        test_socket_close(control);
    }
    uv_thread_join(&echo_tid);
    test_socket_close(echo);
    test_env_destroy(env);
}

static void test_udp_domain_and_cache(void) {
    test_env_t *env = test_env_create_ex("socks5", NULL, 0, 0);
    EXPECT_TRUE(env != NULL);
    if (!env) return;
    EXPECT_EQ(asterism_set_option(env->as, ASTERISM_OPT_SOCKS5_UDP, 1), 0);

    unsigned short echo_port = 0;
    int echo = test_create_udp_echo_socket(AF_INET, &echo_port);
    EXPECT_TRUE(echo >= 0);
    if (echo < 0) { test_env_destroy(env); return; }

    udp_echo_args_t echo_args = {echo, 2};
    uv_thread_t echo_tid;
    EXPECT_EQ(uv_thread_create(&echo_tid, test_udp_echo_thread, &echo_args), 0);

    unsigned short relay_port = 0;
    int control = udp_open_session(env, &relay_port);
    EXPECT_TRUE(control >= 0);
    if (control >= 0) {
        struct sockaddr_in relay;
        int udp_client = make_udp_client(&relay, relay_port);
        EXPECT_TRUE(udp_client >= 0);
        if (udp_client >= 0) {
            // First packet resolves "localhost"; second must hit the addr cache.
            for (int i = 0; i < 2; i++) {
                unsigned char pkt[64];
                const char *payload = (i == 0) ? "dns1" : "dns2";
                int pkt_len = build_udp_domain_packet(pkt, "localhost", echo_port, payload, 4);
                unsigned char resp[128] = {0};
                int n = udp_xchg(udp_client, &relay, pkt, pkt_len, resp, sizeof(resp));
                EXPECT_EQ(n, 14);
                EXPECT_EQ(memcmp(resp + 10, payload, 4), 0);
            }
            test_socket_close(udp_client);
        }
        test_socket_close(control);
    }
    uv_thread_join(&echo_tid);
    test_socket_close(echo);
    test_env_destroy(env);
}

static void test_udp_ipv6_roundtrip(void) {
    test_env_t *env = test_env_create_ex("socks5", NULL, 0, 0);
    EXPECT_TRUE(env != NULL);
    if (!env) return;
    EXPECT_EQ(asterism_set_option(env->as, ASTERISM_OPT_SOCKS5_UDP, 1), 0);

    unsigned short echo_port = 0;
    int echo = test_create_udp_echo_socket(AF_INET6, &echo_port);
    if (echo < 0) {
        // No IPv6 loopback in this environment; skip gracefully.
        printf("  [   SKIP   ] IPv6 loopback unavailable\n");
        test_env_destroy(env);
        return;
    }

    udp_echo_args_t echo_args = {echo, 1};
    uv_thread_t echo_tid;
    EXPECT_EQ(uv_thread_create(&echo_tid, test_udp_echo_thread, &echo_args), 0);

    unsigned short relay_port = 0;
    int control = udp_open_session(env, &relay_port);
    EXPECT_TRUE(control >= 0);
    if (control >= 0) {
        struct sockaddr_in relay;
        int udp_client = make_udp_client(&relay, relay_port);
        EXPECT_TRUE(udp_client >= 0);
        if (udp_client >= 0) {
            unsigned char pkt[64];
            int pkt_len = build_udp_ipv6_packet(pkt, "::1", echo_port, "v6!!", 4);
            unsigned char resp[128] = {0};
            int n = udp_xchg(udp_client, &relay, pkt, pkt_len, resp, sizeof(resp));
            EXPECT_EQ(n, 26);                        // 22-byte v6 header + 4 data
            EXPECT_EQ((unsigned char)resp[3], 0x04); // ATYP IPv6 in reply
            EXPECT_EQ(memcmp(resp + 22, "v6!!", 4), 0);
            test_socket_close(udp_client);
        }
        test_socket_close(control);
    }
    uv_thread_join(&echo_tid);
    test_socket_close(echo);
    test_env_destroy(env);
}

static void test_udp_concurrent_associations(void) {
    test_env_t *env = test_env_create_ex("socks5", NULL, 0, 0);
    EXPECT_TRUE(env != NULL);
    if (!env) return;
    EXPECT_EQ(asterism_set_option(env->as, ASTERISM_OPT_SOCKS5_UDP, 1), 0);

    unsigned short echo_port = 0;
    int echo = test_create_udp_echo_socket(AF_INET, &echo_port);
    EXPECT_TRUE(echo >= 0);
    if (echo < 0) { test_env_destroy(env); return; }

    udp_echo_args_t echo_args = {echo, 2};
    uv_thread_t echo_tid;
    EXPECT_EQ(uv_thread_create(&echo_tid, test_udp_echo_thread, &echo_args), 0);

    unsigned short relay_port = 0;
    int control = udp_open_session(env, &relay_port);
    EXPECT_TRUE(control >= 0);
    if (control >= 0) {
        // Two clients with distinct source ports -> distinct agent requestors.
        struct sockaddr_in relay1, relay2;
        int c1 = make_udp_client(&relay1, relay_port);
        int c2 = make_udp_client(&relay2, relay_port);
        EXPECT_TRUE(c1 >= 0 && c2 >= 0);
        if (c1 >= 0 && c2 >= 0) {
            unsigned char p1[64], p2[64], r1[128] = {0}, r2[128] = {0};
            int l1 = build_udp_ipv4_packet(p1, "127.0.0.1", echo_port, "aaaa", 4);
            int l2 = build_udp_ipv4_packet(p2, "127.0.0.1", echo_port, "bbbb", 4);
            int n1 = udp_xchg(c1, &relay1, p1, l1, r1, sizeof(r1));
            int n2 = udp_xchg(c2, &relay2, p2, l2, r2, sizeof(r2));
            EXPECT_EQ(n1, 14);
            EXPECT_EQ(n2, 14);
            EXPECT_EQ(memcmp(r1 + 10, "aaaa", 4), 0);
            EXPECT_EQ(memcmp(r2 + 10, "bbbb", 4), 0);
        }
        if (c1 >= 0) test_socket_close(c1);
        if (c2 >= 0) test_socket_close(c2);
        test_socket_close(control);
    }
    uv_thread_join(&echo_tid);
    test_socket_close(echo);
    test_env_destroy(env);
}

static void test_udp_large_payload(void) {
    test_env_t *env = test_env_create_ex("socks5", NULL, 0, 0);
    EXPECT_TRUE(env != NULL);
    if (!env) return;
    EXPECT_EQ(asterism_set_option(env->as, ASTERISM_OPT_SOCKS5_UDP, 1), 0);

    unsigned short echo_port = 0;
    int echo = test_create_udp_echo_socket(AF_INET, &echo_port);
    EXPECT_TRUE(echo >= 0);
    if (echo < 0) { test_env_destroy(env); return; }

    udp_echo_args_t echo_args = {echo, 1};
    uv_thread_t echo_tid;
    EXPECT_EQ(uv_thread_create(&echo_tid, test_udp_echo_thread, &echo_args), 0);

    const int data_len = 16000;
    unsigned char *payload = (unsigned char *)malloc(data_len);
    unsigned char *pkt = (unsigned char *)malloc(16 + data_len);
    unsigned char *resp = (unsigned char *)malloc(64 + data_len);
    EXPECT_TRUE(payload && pkt && resp);
    if (payload && pkt && resp) {
        for (int i = 0; i < data_len; i++) payload[i] = (unsigned char)(i & 0xff);

        unsigned short relay_port = 0;
        int control = udp_open_session(env, &relay_port);
        EXPECT_TRUE(control >= 0);
        if (control >= 0) {
            struct sockaddr_in relay;
            int udp_client = make_udp_client(&relay, relay_port);
            EXPECT_TRUE(udp_client >= 0);
            if (udp_client >= 0) {
                int pkt_len = build_udp_ipv4_packet(pkt, "127.0.0.1", echo_port, payload, data_len);
                int n = udp_xchg(udp_client, &relay, pkt, pkt_len, resp, 64 + data_len);
                EXPECT_EQ(n, 10 + data_len);
                EXPECT_EQ(memcmp(resp + 10, payload, data_len), 0);
                test_socket_close(udp_client);
            }
            test_socket_close(control);
        }
    }
    free(payload); free(pkt); free(resp);
    uv_thread_join(&echo_tid);
    test_socket_close(echo);
    test_env_destroy(env);
}

// A single bad datagram (target port 0 -> agent rejects synchronously) must be
// dropped without tearing down the shared TCP control channel; a subsequent
// valid datagram on the same association must still round-trip.
static void test_udp_bad_target_keeps_tunnel(void) {
    test_env_t *env = test_env_create_ex("socks5", NULL, 0, 0);
    EXPECT_TRUE(env != NULL);
    if (!env) return;
    EXPECT_EQ(asterism_set_option(env->as, ASTERISM_OPT_SOCKS5_UDP, 1), 0);

    unsigned short echo_port = 0;
    int echo = test_create_udp_echo_socket(AF_INET, &echo_port);
    EXPECT_TRUE(echo >= 0);
    if (echo < 0) { test_env_destroy(env); return; }

    udp_echo_args_t echo_args = {echo, 1};
    uv_thread_t echo_tid;
    EXPECT_EQ(uv_thread_create(&echo_tid, test_udp_echo_thread, &echo_args), 0);

    unsigned short relay_port = 0;
    int control = udp_open_session(env, &relay_port);
    EXPECT_TRUE(control >= 0);
    if (control >= 0) {
        struct sockaddr_in relay;
        int udp_client = make_udp_client(&relay, relay_port);
        EXPECT_TRUE(udp_client >= 0);
        if (udp_client >= 0) {
            unsigned char bad[64], resp[128] = {0};
            int bad_len = build_udp_ipv4_packet(bad, "127.0.0.1", 0, "drop", 4); // port 0
            test_set_socket_recv_timeout(udp_client, 1000);
            int n = udp_xchg(udp_client, &relay, bad, bad_len, resp, sizeof(resp));
            EXPECT_TRUE(n <= 0); // dropped, no reply

            // Tunnel must still be alive: a valid datagram round-trips.
            test_set_socket_recv_timeout(udp_client, 5000);
            unsigned char good[64];
            int good_len = build_udp_ipv4_packet(good, "127.0.0.1", echo_port, "ok!!", 4);
            n = udp_xchg(udp_client, &relay, good, good_len, resp, sizeof(resp));
            EXPECT_EQ(n, 14);
            EXPECT_EQ(memcmp(resp + 10, "ok!!", 4), 0);
            test_socket_close(udp_client);
        }
        test_socket_close(control);
    }
    uv_thread_join(&echo_tid);
    test_socket_close(echo);
    test_env_destroy(env);
}

// An oversized client datagram (> ASTERISM_UDP_BLOCK_SIZE) is dropped at the
// relay; the tunnel survives and a normal datagram still round-trips.
static void test_udp_oversize_dropped(void) {
    test_env_t *env = test_env_create_ex("socks5", NULL, 0, 0);
    EXPECT_TRUE(env != NULL);
    if (!env) return;
    EXPECT_EQ(asterism_set_option(env->as, ASTERISM_OPT_SOCKS5_UDP, 1), 0);

    unsigned short echo_port = 0;
    int echo = test_create_udp_echo_socket(AF_INET, &echo_port);
    EXPECT_TRUE(echo >= 0);
    if (echo < 0) { test_env_destroy(env); return; }

    udp_echo_args_t echo_args = {echo, 1};
    uv_thread_t echo_tid;
    EXPECT_EQ(uv_thread_create(&echo_tid, test_udp_echo_thread, &echo_args), 0);

    const int big_len = ASTERISM_UDP_BLOCK_SIZE + 1000;
    unsigned char *pkt = (unsigned char *)malloc(16 + big_len);
    EXPECT_TRUE(pkt != NULL);
    unsigned short relay_port = 0;
    int control = udp_open_session(env, &relay_port);
    EXPECT_TRUE(control >= 0);
    if (pkt && control >= 0) {
        struct sockaddr_in relay;
        int udp_client = make_udp_client(&relay, relay_port);
        EXPECT_TRUE(udp_client >= 0);
        if (udp_client >= 0) {
            unsigned char resp[128] = {0};
            memset(pkt + 10, 'X', big_len);
            int pkt_len = build_udp_ipv4_packet(pkt, "127.0.0.1", echo_port, pkt + 10, big_len);
            test_set_socket_recv_timeout(udp_client, 1000);
            int n = udp_xchg(udp_client, &relay, pkt, pkt_len, resp, sizeof(resp));
            EXPECT_TRUE(n <= 0); // dropped

            test_set_socket_recv_timeout(udp_client, 5000);
            unsigned char good[64];
            int good_len = build_udp_ipv4_packet(good, "127.0.0.1", echo_port, "fine", 4);
            n = udp_xchg(udp_client, &relay, good, good_len, resp, sizeof(resp));
            EXPECT_EQ(n, 14);
            EXPECT_EQ(memcmp(resp + 10, "fine", 4), 0);
            test_socket_close(udp_client);
        }
        test_socket_close(control);
    }
    free(pkt);
    uv_thread_join(&echo_tid);
    test_socket_close(echo);
    test_env_destroy(env);
}

// UDP ASSOCIATE must be refused when SOCKS5 UDP support is not enabled.
static void test_udp_associate_disabled(void) {
    test_env_t *env = test_env_create_ex("socks5", NULL, 0, 0);
    EXPECT_TRUE(env != NULL);
    if (!env) return;
    // Note: ASTERISM_OPT_SOCKS5_UDP intentionally NOT set.

    int control = test_socket_connect("127.0.0.1", env->inner_port);
    EXPECT_TRUE(control >= 0);
    if (control >= 0) {
        char response[64] = {0};
        test_set_socket_recv_timeout(control, 5000);
        EXPECT_EQ(send(control, "\x05\x01\x02", 3, 0), 3);
        EXPECT_EQ(recv(control, response, sizeof(response), 0), 2);
        EXPECT_EQ(send(control, "\x01\x04test\x04test", 11, 0), 11);
        EXPECT_EQ(recv(control, response, sizeof(response), 0), 2);

        const unsigned char associate[] = {5, 3, 0, 1, 0, 0, 0, 0, 0, 0};
        EXPECT_EQ(send(control, (const char *)associate, sizeof(associate), 0), (int)sizeof(associate));
        int n = recv(control, response, sizeof(response), 0);
        EXPECT_EQ(n, 10);
        EXPECT_EQ((unsigned char)response[0], 0x05);
        EXPECT_EQ((unsigned char)response[1], 0x01); // general failure
        test_socket_close(control);
    }
    test_env_destroy(env);
}

// With UDP idle reaping enabled, an idle association is closed; the old relay
// UDP port stops responding afterwards. Exercises the reaper (and, under ASan,
// guards the deferred-free path).
static void test_udp_idle_reap(void) {
    test_env_t *env = test_env_create_ex("socks5", NULL, 0, 0);
    EXPECT_TRUE(env != NULL);
    if (!env) return;
    EXPECT_EQ(asterism_set_option(env->as, ASTERISM_OPT_SOCKS5_UDP, 1), 0);
    EXPECT_EQ(asterism_set_option(env->as, ASTERISM_OPT_UDP_IDLE_TIMEOUT, 1), 0); // 1s

    unsigned short echo_port = 0;
    int echo = test_create_udp_echo_socket(AF_INET, &echo_port);
    EXPECT_TRUE(echo >= 0);
    if (echo < 0) { test_env_destroy(env); return; }

    udp_echo_args_t echo_args = {echo, 1};
    uv_thread_t echo_tid;
    EXPECT_EQ(uv_thread_create(&echo_tid, test_udp_echo_thread, &echo_args), 0);

    unsigned short relay_port = 0;
    int control = udp_open_session(env, &relay_port);
    EXPECT_TRUE(control >= 0);
    if (control >= 0) {
        struct sockaddr_in relay;
        int udp_client = make_udp_client(&relay, relay_port);
        EXPECT_TRUE(udp_client >= 0);
        if (udp_client >= 0) {
            unsigned char pkt[64], resp[128] = {0};
            int pkt_len = build_udp_ipv4_packet(pkt, "127.0.0.1", echo_port, "live", 4);
            int n = udp_xchg(udp_client, &relay, pkt, pkt_len, resp, sizeof(resp));
            EXPECT_EQ(n, 14);

            // Wait past the UDP idle timeout (reaper ticks once per second).
            test_sleep(3000);

            // The association is gone; the old relay port no longer echoes.
            test_set_socket_recv_timeout(udp_client, 1500);
            n = udp_xchg(udp_client, &relay, pkt, pkt_len, resp, sizeof(resp));
            EXPECT_TRUE(n <= 0);
            test_socket_close(udp_client);
        }
        test_socket_close(control);
    }
    uv_thread_join(&echo_tid);
    test_socket_close(echo);
    test_env_destroy(env);
}

// Unit: SOCKS5 UDP header size for the IPv6 (ATYP 0x04) case.
static void test_udp_header_size_ipv6(void) {
    unsigned char ipv6[23] = {0};
    ipv6[3] = 0x04;
    size_t header_len = 0;
    EXPECT_EQ(asterism_socks5_udp_header_size(ipv6, 22, &header_len), 0);
    EXPECT_EQ(header_len, 22);
    // One byte of payload after the 22-byte header is still valid.
    EXPECT_EQ(asterism_socks5_udp_header_size(ipv6, 23, &header_len), 0);
    EXPECT_EQ(header_len, 22);
    // Truncated IPv6 header is rejected.
    EXPECT_EQ(asterism_socks5_udp_header_size(ipv6, 21, &header_len), -1);
}

void register_suite_udp(void) {
    register_test("UDP", "IPv4Roundtrip", test_udp_ipv4_roundtrip);
    register_test("UDP", "DomainAndCache", test_udp_domain_and_cache);
    register_test("UDP", "IPv6Roundtrip", test_udp_ipv6_roundtrip);
    register_test("UDP", "ConcurrentAssociations", test_udp_concurrent_associations);
    register_test("UDP", "LargePayload", test_udp_large_payload);
    register_test("UDP", "BadTargetKeepsTunnel", test_udp_bad_target_keeps_tunnel);
    register_test("UDP", "OversizeDropped", test_udp_oversize_dropped);
    register_test("UDP", "AssociateDisabled", test_udp_associate_disabled);
    register_test("UDP", "IdleReap", test_udp_idle_reap);
    register_test("UDP", "HeaderSizeIPv6", test_udp_header_size_ipv6);
}
