#include "test_framework.h"
#include "asterism_core.h"
#include "asterism.h"
#include "asterism_outer_tcp.h"
#include "asterism_stream.h"
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

    ret = asterism_parse_address("127.0.0.1:65535", &scheme, &host, &port, &host_type);
    EXPECT_EQ(ret, 0);
    EXPECT_EQ(port, 65535);

    ret = asterism_parse_address(NULL, &scheme, &host, &port, &host_type);
    EXPECT_EQ(ret, -1);
}

static void test_utils_stream_eaten(void) {
    struct asterism_stream_s stream;
    memset(&stream, 0, sizeof(stream));
    memcpy(stream.buffer, "abcdef", 6);
    stream.buffer_len = 6;

    asterism_stream_eaten(&stream, 2);
    EXPECT_EQ(stream.buffer_len, 4);
    EXPECT_EQ(memcmp(stream.buffer, "cdef", 4), 0);

    asterism_stream_eaten(&stream, 4);
    EXPECT_EQ(stream.buffer_len, 0);
}

static void test_utils_base64_decode_bounds(void) {
    char out[5];
    int dec_len = 0;
    int parsed = asterism_base64_decode((const unsigned char *)"dGVzdA==", 8, out, sizeof(out), &dec_len);
    EXPECT_EQ(parsed, 8);
    EXPECT_EQ(dec_len, 4);
    EXPECT_STR_EQ(out, "test");

    char small_buf[4];
    parsed = asterism_base64_decode((const unsigned char *)"dGVzdA==", 8, small_buf, sizeof(small_buf), &dec_len);
    EXPECT_EQ(parsed, -1);

    const unsigned char invalid[] = {0x80, 'A', 'A', 'A'};
    char invalid_out[8];
    parsed = asterism_base64_decode(invalid, (int)sizeof(invalid), invalid_out, sizeof(invalid_out), &dec_len);
    EXPECT_EQ(parsed, -1);

    parsed = asterism_base64_decode((const unsigned char *)"dG=A", 4, invalid_out, sizeof(invalid_out), &dec_len);
    EXPECT_EQ(parsed, -1);
}

static void test_utils_protocol_frames(void) {
    unsigned char frames[16] = {0};
    uint16_t frame_len = 0;

    frames[0] = ASTERISM_TRANS_PROTO_VERSION;
    frames[1] = ASTERISM_TRANS_PROTO_PING;
    asterism_write_be16(frames + 2, sizeof(struct asterism_trans_proto_s));

    EXPECT_EQ(asterism_proto_frame_size(frames, 3, &frame_len), 0);
    EXPECT_EQ(asterism_proto_frame_size(frames, 4, &frame_len), 1);
    EXPECT_EQ(frame_len, sizeof(struct asterism_trans_proto_s));

    asterism_write_be16(frames + 2, 0);
    EXPECT_EQ(asterism_proto_frame_size(frames, 4, &frame_len), -1);

    asterism_write_be16(frames + 2, 8);
    EXPECT_EQ(asterism_proto_frame_size(frames, 4, &frame_len), 0);

    asterism_write_be16(frames + 2, 4);
    memcpy(frames + 4, frames, 4);
    size_t consumed = 0;
    int count = 0;
    while (consumed < 8) {
        EXPECT_EQ(asterism_proto_frame_size(frames + consumed, 8 - consumed, &frame_len), 1);
        consumed += frame_len;
        count++;
    }
    EXPECT_EQ(consumed, 8);
    EXPECT_EQ(count, 2);

    frames[0] = ASTERISM_TRANS_PROTO_VERSION + 1;
    EXPECT_EQ(asterism_proto_frame_size(frames, 4, &frame_len), -1);
}

static void test_utils_connect_ack_bounds(void) {
    unsigned char ack[sizeof(struct asterism_trans_proto_s) + 5] = {0};
    uint32_t handshake_id = 0;
    int success = -1;

    ack[0] = ASTERISM_TRANS_PROTO_VERSION;
    ack[1] = ASTERISM_TRANS_PROTO_CONNECT_ACK;
    asterism_write_be16(ack + 2, (uint16_t)sizeof(ack));
    asterism_write_be32(ack + sizeof(struct asterism_trans_proto_s), 0x12345678);
    ack[sizeof(ack) - 1] = 1;

    EXPECT_EQ(asterism_decode_connect_ack(ack, sizeof(ack) - 1, &handshake_id, &success), -1);
    EXPECT_EQ(asterism_decode_connect_ack(ack, sizeof(ack), &handshake_id, &success), 0);
    EXPECT_EQ(handshake_id, 0x12345678);
    EXPECT_EQ(success, 1);

    ack[sizeof(ack) - 1] = 2;
    EXPECT_EQ(asterism_decode_connect_ack(ack, sizeof(ack), &handshake_id, &success), -1);
}

static void test_utils_socks5_udp_headers(void) {
    const unsigned char ipv4[] = {
        0, 0, 0, 1,
        127, 0, 0, 1,
        0x1f, 0x90,
        'x'
    };
    size_t header_len = 0;
    EXPECT_EQ(asterism_socks5_udp_header_size(ipv4, sizeof(ipv4), &header_len), 0);
    EXPECT_EQ(header_len, 10);

    const unsigned char domain[] = {
        0, 0, 0, 3, 3,
        'a', 'p', 'i',
        0x00, 0x35,
        'x'
    };
    EXPECT_EQ(asterism_socks5_udp_header_size(domain, sizeof(domain), &header_len), 0);
    EXPECT_EQ(header_len, 10);

    EXPECT_EQ(asterism_socks5_udp_header_size(domain, 9, &header_len), -1);

    unsigned char fragmented[sizeof(ipv4)];
    memcpy(fragmented, ipv4, sizeof(ipv4));
    fragmented[2] = 1;
    EXPECT_EQ(asterism_socks5_udp_header_size(fragmented, sizeof(fragmented), &header_len), -1);
}

static void test_utils_public_api_guards(void) {
    EXPECT_EQ(asterism_run(NULL), ASTERISM_E_INVALID_ARGS);
    EXPECT_EQ(asterism_stop(NULL), ASTERISM_E_INVALID_ARGS);
    EXPECT_EQ(asterism_set_option(NULL, ASTERISM_OPT_IDLE_TIMEOUT, 1), ASTERISM_E_INVALID_ARGS);
    EXPECT_STR_EQ(asterism_errno_description((asterism_errno)999), "unknown error");
    asterism_destroy(NULL);
}

void register_suite_utils(void) {
    register_test("Utils", "SList", test_utils_slist);
    register_test("Utils", "String", test_utils_string);
    register_test("Utils", "AddressParse", test_utils_address_parse);
    register_test("Utils", "StreamEaten", test_utils_stream_eaten);
    register_test("Utils", "Base64DecodeBounds", test_utils_base64_decode_bounds);
    register_test("Utils", "ProtocolFrames", test_utils_protocol_frames);
    register_test("Utils", "ConnectAckBounds", test_utils_connect_ack_bounds);
    register_test("Utils", "Socks5UDPHeaders", test_utils_socks5_udp_headers);
    register_test("Utils", "PublicAPIGuards", test_utils_public_api_guards);
}
