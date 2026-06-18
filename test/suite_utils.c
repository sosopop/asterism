#include "test_framework.h"
#include "asterism_core.h"
#include "asterism.h"
#include "asterism_outer_tcp.h"
#include "asterism_stream.h"
#include "asterism_utils.h"
#include "asterism_log.h"

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

/* ---- Part 2 additions: exhaustive branch/condition coverage for pure code ---- */

/* base64: drive every guard and every decode branch with one case each. */
static void test_utils_base64_branches(void) {
    char out[8];
    int dec_len = -1;

    /* Guards in the `if (!s || !dst || dst_size == 0 || len < 0)` chain - one
       sub-condition true per case. */
    EXPECT_EQ(asterism_base64_decode(NULL, 4, out, sizeof(out), &dec_len), -1);
    EXPECT_EQ(asterism_base64_decode((const unsigned char *)"QUJD", 4, NULL, sizeof(out), &dec_len), -1);
    EXPECT_EQ(asterism_base64_decode((const unsigned char *)"QUJD", 4, out, 0, &dec_len), -1);
    EXPECT_EQ(asterism_base64_decode((const unsigned char *)"QUJD", -1, out, sizeof(out), &dec_len), -1);
    /* len not a multiple of 4 */
    EXPECT_EQ(asterism_base64_decode((const unsigned char *)"QUJ", 3, out, sizeof(out), &dec_len), -1);

    /* invalid symbols: a>=64, b>=64, c==255, d==255 (one per case) */
    EXPECT_EQ(asterism_base64_decode((const unsigned char *)"=AAA", 4, out, sizeof(out), &dec_len), -1);
    EXPECT_EQ(asterism_base64_decode((const unsigned char *)"A=AA", 4, out, sizeof(out), &dec_len), -1);
    EXPECT_EQ(asterism_base64_decode((const unsigned char *)"AA-A", 4, out, sizeof(out), &dec_len), -1);
    EXPECT_EQ(asterism_base64_decode((const unsigned char *)"AAA-", 4, out, sizeof(out), &dec_len), -1);
    /* c is pad ('=') but d is not pad */
    EXPECT_EQ(asterism_base64_decode((const unsigned char *)"AA=A", 4, out, sizeof(out), &dec_len), -1);
    /* padding present but not in the final quad */
    EXPECT_EQ(asterism_base64_decode((const unsigned char *)"AA==QUJD", 8, out, sizeof(out), &dec_len), -1);

    /* output bound hit at each of the three writes (3-byte quad "QUJD"="ABC") */
    EXPECT_EQ(asterism_base64_decode((const unsigned char *)"QUJD", 4, out, 1, &dec_len), -1);
    EXPECT_EQ(asterism_base64_decode((const unsigned char *)"QUJD", 4, out, 2, &dec_len), -1);
    EXPECT_EQ(asterism_base64_decode((const unsigned char *)"QUJD", 4, out, 3, &dec_len), -1);

    /* full 3-byte output */
    dec_len = -1;
    EXPECT_EQ(asterism_base64_decode((const unsigned char *)"QUJD", 4, out, sizeof(out), &dec_len), 4);
    EXPECT_EQ(dec_len, 3);
    EXPECT_EQ(memcmp(out, "ABC", 3), 0);

    /* 1-byte remainder ("QQ==" -> "A") and 2-byte remainder ("QUI=" -> "AB") */
    dec_len = -1;
    EXPECT_EQ(asterism_base64_decode((const unsigned char *)"QQ==", 4, out, sizeof(out), &dec_len), 4);
    EXPECT_EQ(dec_len, 1);
    EXPECT_EQ(out[0], 'A');
    dec_len = -1;
    EXPECT_EQ(asterism_base64_decode((const unsigned char *)"QUI=", 4, out, sizeof(out), &dec_len), 4);
    EXPECT_EQ(dec_len, 2);
    EXPECT_EQ(memcmp(out, "AB", 2), 0);

    /* dec_len == NULL path */
    EXPECT_EQ(asterism_base64_decode((const unsigned char *)"QUJD", 4, out, sizeof(out), NULL), 4);
}

static void test_utils_address_parse_branches(void) {
    struct asterism_str scheme; struct asterism_str host;
    unsigned int port; asterism_host_type host_type;
    scheme.len = 0; host.len = 0;

    /* NULL out-params */
    EXPECT_EQ(asterism_parse_address("1.2.3.4:80", &scheme, &host, NULL, &host_type), -1);
    EXPECT_EQ(asterism_parse_address("1.2.3.4:80", &scheme, &host, &port, NULL), -1);

    /* port out of range */
    EXPECT_EQ(asterism_parse_address("1.2.3.4:70000", &scheme, &host, &port, &host_type), -1);

    /* valid terminators after port: ',', whitespace, '\0' */
    EXPECT_EQ(asterism_parse_address("1.2.3.4:80,next", &scheme, &host, &port, &host_type), 0);
    EXPECT_EQ(port, 80);
    EXPECT_EQ(asterism_parse_address("1.2.3.4:80 trailing", &scheme, &host, &port, &host_type), 0);
    /* junk after the port is rejected */
    EXPECT_EQ(asterism_parse_address("1.2.3.4:80x", &scheme, &host, &port, &host_type), -1);

    /* IPv6 without a scheme */
    scheme.len = 0; host.len = 0;
    EXPECT_EQ(asterism_parse_address("[::1]:8080", &scheme, &host, &port, &host_type), 0);
    EXPECT_EQ(host_type, ASTERISM_HOST_TYPE_IPV6);
    EXPECT_TRUE(asterism_str_empty(&scheme));
    EXPECT_EQ(asterism_vcasecmp(&host, "::1"), 0);
    EXPECT_EQ(port, 8080);

    /* neither host:port nor [host]:port matches */
    EXPECT_EQ(asterism_parse_address("noporthere", &scheme, &host, &port, &host_type), -1);
}

static void test_utils_itoa(void) {
    char buf[64];

    memset(buf, 0, sizeof(buf));
    EXPECT_EQ(asterism_itoa(buf, sizeof(buf), 255, 16, 0, 0), 2);
    EXPECT_EQ(memcmp(buf, "ff", 2), 0);

    memset(buf, 0, sizeof(buf));
    EXPECT_EQ(asterism_itoa(buf, sizeof(buf), -42, 10, 0, 0), 3);
    EXPECT_EQ(memcmp(buf, "-42", 3), 0);

    memset(buf, 0, sizeof(buf));
    EXPECT_EQ(asterism_itoa(buf, sizeof(buf), 5, 10, ASTERISM_SNPRINTF_FLAG_ZERO, 4), 4);
    EXPECT_EQ(memcmp(buf, "0005", 4), 0);

    memset(buf, 0, sizeof(buf));
    EXPECT_EQ(asterism_itoa(buf, sizeof(buf), 5, 2, 0, 0), 3);
    EXPECT_EQ(memcmp(buf, "101", 3), 0);

    memset(buf, 0, sizeof(buf));
    EXPECT_EQ(asterism_itoa(buf, sizeof(buf), 0, 10, 0, 0), 1);
    EXPECT_EQ(buf[0], '0');

    /* buf_size smaller than the produced length: returns full length, writes no
       further than buf_size (rest of buf stays zero). */
    memset(buf, 0, sizeof(buf));
    EXPECT_EQ(asterism_itoa(buf, 2, 12345, 10, 0, 0), 5);
    EXPECT_EQ(memcmp(buf, "12", 2), 0);
    EXPECT_EQ(buf[2], 0);

    /* zero-padding capped at sizeof(tmp)-1 (39) */
    memset(buf, 0, sizeof(buf));
    EXPECT_EQ(asterism_itoa(buf, sizeof(buf), 1, 10, ASTERISM_SNPRINTF_FLAG_ZERO, 100), 39);
}

static void test_utils_vsnprintf_grow(void) {
    /* size == 0 forces the `len >= (int)size` reallocation branch. */
    char *buf = NULL;
    int n = asterism_snprintf(&buf, 0, "value=%d", 12345);
    EXPECT_EQ(n, 11);
    EXPECT_TRUE(buf != NULL);
    EXPECT_STR_EQ(buf, "value=12345");
    AS_FREE(buf);

    /* a stack buffer too small to hold the output is replaced by a heap one. */
    char small_buf[8];
    char *p = small_buf;
    n = asterism_snprintf(&p, sizeof(small_buf), "%s", "longer than eight bytes");
    EXPECT_TRUE(n > (int)sizeof(small_buf));
    EXPECT_TRUE(p != small_buf);
    EXPECT_STR_EQ(p, "longer than eight bytes");
    AS_FREE(p);

    /* OOM while growing -> returns -1, leaks nothing (verified by ASan/LSan). */
    char tiny_buf[4];
    char *q = tiny_buf;
    asterism_test_set_alloc_fail(1);
    n = asterism_snprintf(&q, sizeof(tiny_buf), "%s", "this will need a heap buffer");
    asterism_test_reset_alloc_fail();
    EXPECT_EQ(n, -1);
}

static void test_utils_string_more(void) {
    /* asterism_strstr: needle longer than haystack / found / not found */
    EXPECT_TRUE(asterism_strstr(asterism_mk_str("hi"), asterism_mk_str("hello")) == NULL);
    EXPECT_TRUE(asterism_strstr(asterism_mk_str("a-needle-here"), asterism_mk_str("needle")) != NULL);
    EXPECT_TRUE(asterism_strstr(asterism_mk_str("abcdef"), asterism_mk_str("xyz")) == NULL);

    /* asterism_strstrip: all whitespace / only trailing / none */
    struct asterism_str s = asterism_strstrip(asterism_mk_str("   "));
    EXPECT_EQ(s.len, 0);
    s = asterism_strstrip(asterism_mk_str("tail   "));
    EXPECT_EQ(asterism_strcmp(s, asterism_mk_str("tail")), 0);
    s = asterism_strstrip(asterism_mk_str("none"));
    EXPECT_EQ(asterism_strcmp(s, asterism_mk_str("none")), 0);

    /* asterism_strcmp ordering: prefix-shorter, prefix-longer, char< , char> */
    EXPECT_TRUE(asterism_strcmp(asterism_mk_str("ab"), asterism_mk_str("abc")) < 0);
    EXPECT_TRUE(asterism_strcmp(asterism_mk_str("abc"), asterism_mk_str("ab")) > 0);
    EXPECT_TRUE(asterism_strcmp(asterism_mk_str("abc"), asterism_mk_str("abd")) < 0);
    EXPECT_TRUE(asterism_strcmp(asterism_mk_str("abd"), asterism_mk_str("abc")) > 0);

    /* asterism_strncmp truncates both sides to n */
    EXPECT_EQ(asterism_strncmp(asterism_mk_str("abcXX"), asterism_mk_str("abcYY"), 3), 0);
    EXPECT_TRUE(asterism_strncmp(asterism_mk_str("abc"), asterism_mk_str("abd"), 3) < 0);

    /* asterism_strchr not found */
    EXPECT_TRUE(asterism_strchr(asterism_mk_str("abc"), 'z') == NULL);

    /* asterism_str_empty: NULL pointer / zero length / non-empty */
    struct asterism_str e1 = {NULL, 5};
    struct asterism_str e2 = {"x", 0};
    struct asterism_str e3 = asterism_mk_str("x");
    EXPECT_TRUE(asterism_str_empty(&e1));
    EXPECT_TRUE(asterism_str_empty(&e2));
    EXPECT_FALSE(asterism_str_empty(&e3));

    /* asterism_mk_str(NULL) -> empty */
    struct asterism_str nul = asterism_mk_str(NULL);
    EXPECT_TRUE(nul.p == NULL);
    EXPECT_EQ(nul.len, 0);

    /* case-insensitive helpers */
    EXPECT_EQ(asterism_casecmp("AbC", "abc"), 0);
    EXPECT_EQ(asterism_ncasecmp("abc", "abd", 2), 0);
    EXPECT_TRUE(asterism_ncasecmp("abc", "abd", 3) < 0);
}

static void test_utils_mem_helpers(void) {
    /* asterism_dup_mem: NULL src with non-zero size -> NULL; normal copy. */
    EXPECT_TRUE(asterism_dup_mem(NULL, 4) == NULL);
    void *m = asterism_dup_mem("abcd", 4);
    EXPECT_TRUE(m != NULL);
    EXPECT_EQ(memcmp(m, "abcd", 4), 0);
    AS_FREE(m);

    /* asterism_zmalloc returns zeroed memory. */
    unsigned char *z = (unsigned char *)asterism_zmalloc(16);
    EXPECT_TRUE(z != NULL);
    int all_zero = 1;
    for (int i = 0; i < 16; i++) if (z[i] != 0) all_zero = 0;
    EXPECT_TRUE(all_zero);
    AS_FREE(z);

    /* as_strdup2: NULL src with non-zero len -> NULL; normal copy NUL-terminated. */
    EXPECT_TRUE(as_strdup2(NULL, 5) == NULL);
    char *d = as_strdup2("abcde", 5);
    EXPECT_TRUE(d != NULL);
    EXPECT_STR_EQ(d, "abcde");
    AS_FREE(d);

    /* as_strdup(NULL) -> NULL */
    EXPECT_TRUE(as_strdup(NULL) == NULL);
}

static void test_utils_oom_injection(void) {
    /* as_strdup allocation failure */
    asterism_test_set_alloc_fail(1);
    EXPECT_TRUE(as_strdup("hello") == NULL);
    asterism_test_reset_alloc_fail();

    /* as_strdup2 allocation failure */
    asterism_test_set_alloc_fail(1);
    EXPECT_TRUE(as_strdup2("hello", 5) == NULL);
    asterism_test_reset_alloc_fail();

    /* asterism_dup_mem allocation failure */
    asterism_test_set_alloc_fail(1);
    EXPECT_TRUE(asterism_dup_mem("abcd", 4) == NULL);
    asterism_test_reset_alloc_fail();

    /* slist append: first allocation (the strdup) fails */
    asterism_test_set_alloc_fail(1);
    EXPECT_TRUE(asterism_slist_append(NULL, "x") == NULL);
    asterism_test_reset_alloc_fail();

    /* slist append onto a non-empty list: strdup ok (1st), node alloc fails
       (2nd) -> append frees the dup and returns NULL (no leak). */
    struct asterism_slist *base = asterism_slist_append(NULL, "a");
    EXPECT_TRUE(base != NULL);
    asterism_test_set_alloc_fail(2);
    EXPECT_TRUE(asterism_slist_append(base, "b") == NULL);
    asterism_test_reset_alloc_fail();
    asterism_slist_free_all(base);
}

static void test_utils_slist_duplicate(void) {
    struct asterism_slist *src = NULL;
    src = asterism_slist_append(src, "a");
    src = asterism_slist_append(src, "b");
    EXPECT_TRUE(src != NULL);

    struct asterism_slist *dup = asterism_slist_duplicate(src);
    EXPECT_TRUE(dup != NULL);
    EXPECT_STR_EQ(dup->data, "a");
    EXPECT_STR_EQ(dup->next->data, "b");
    asterism_slist_free_all(dup);

    /* duplicate of empty list */
    EXPECT_TRUE(asterism_slist_duplicate(NULL) == NULL);

    /* OOM on the 2nd item's strdup (3rd allocation overall) -> the partial
       output list is freed and NULL returned. */
    asterism_test_set_alloc_fail(3);
    EXPECT_TRUE(asterism_slist_duplicate(src) == NULL);
    asterism_test_reset_alloc_fail();

    asterism_slist_free_all(src);
    /* free_all tolerates NULL */
    asterism_slist_free_all(NULL);
}

static void test_log_levels(void) {
    /* Enable logging, exercise every level + the default switch arm + the
       heap-grow/free path, then the gating early-return, then restore silence. */
    asterism_set_log_level(ASTERISM_LOG_DEBUG);
    asterism_log(ASTERISM_LOG_DEBUG, "debug %d", 1);
    asterism_log(ASTERISM_LOG_INFO, "info %d", 2);
    asterism_log(ASTERISM_LOG_WARN, "warn %d", 3);
    asterism_log(ASTERISM_LOG_ERROR, "error %d", 4);
    asterism_log((asterism_log_level)99, "unknown level");

    /* message longer than the 128-byte stack buffer -> vsnprintf grows onto the
       heap and the result is freed. */
    char big[400];
    memset(big, 'x', sizeof(big) - 1);
    big[sizeof(big) - 1] = 0;
    asterism_log(ASTERISM_LOG_ERROR, "%s", big);

    /* OOM while formatting a long message -> _asterism_log hits its
       `len < 0 || !temp_buf` guard and returns cleanly. */
    asterism_test_set_alloc_fail(1);
    asterism_log(ASTERISM_LOG_ERROR, "%s", big);
    asterism_test_reset_alloc_fail();

    /* gating: with the threshold at ERROR, a DEBUG message is dropped. */
    asterism_set_log_level(ASTERISM_LOG_ERROR);
    asterism_log(ASTERISM_LOG_DEBUG, "should be filtered out");
    asterism_log(ASTERISM_LOG_ERROR, "should be emitted");

    asterism_set_log_level(ASTERISM_LOG_NULL);
}

static void test_utils_frame_header_branches(void) {
    uint16_t frame_len = 0;
    unsigned char frame[8] = {0};

    /* NULL guards */
    EXPECT_EQ(asterism_proto_frame_size(NULL, 4, &frame_len), -1);
    EXPECT_EQ(asterism_proto_frame_size(frame, 4, NULL), -1);

    /* declared length above ASTERISM_MAX_PROTO_SIZE */
    frame[0] = ASTERISM_TRANS_PROTO_VERSION;
    frame[1] = ASTERISM_TRANS_PROTO_PING;
    asterism_write_be16(frame + 2, 40000);
    EXPECT_EQ(asterism_proto_frame_size(frame, 4, &frame_len), -1);

    size_t header_len = 0;
    unsigned char ipv4[10] = {0, 0, 0, 1};

    /* NULL guards + short buffer */
    EXPECT_EQ(asterism_socks5_udp_header_size(NULL, 10, &header_len), -1);
    EXPECT_EQ(asterism_socks5_udp_header_size(ipv4, 10, NULL), -1);
    EXPECT_EQ(asterism_socks5_udp_header_size(ipv4, 3, &header_len), -1);

    /* non-zero reserved bytes */
    unsigned char bad_rsv[10] = {1, 0, 0, 1};
    EXPECT_EQ(asterism_socks5_udp_header_size(bad_rsv, 10, &header_len), -1);

    /* IPv6 ok (22) and truncated */
    unsigned char ipv6[22] = {0, 0, 0, 4};
    EXPECT_EQ(asterism_socks5_udp_header_size(ipv6, 22, &header_len), 0);
    EXPECT_EQ(header_len, 22);
    EXPECT_EQ(asterism_socks5_udp_header_size(ipv6, 21, &header_len), -1);

    /* domain length 0 and domain length exceeding the buffer */
    unsigned char dom_zero[6] = {0, 0, 0, 3, 0, 0};
    EXPECT_EQ(asterism_socks5_udp_header_size(dom_zero, 6, &header_len), -1);
    unsigned char dom_over[6] = {0, 0, 0, 3, 200, 0};
    EXPECT_EQ(asterism_socks5_udp_header_size(dom_over, 6, &header_len), -1);

    /* unknown address type */
    unsigned char bad_atyp[10] = {0, 0, 0, 2};
    EXPECT_EQ(asterism_socks5_udp_header_size(bad_atyp, 10, &header_len), -1);
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
    register_test("Utils", "Base64Branches", test_utils_base64_branches);
    register_test("Utils", "AddressParseBranches", test_utils_address_parse_branches);
    register_test("Utils", "Itoa", test_utils_itoa);
    register_test("Utils", "VsnprintfGrow", test_utils_vsnprintf_grow);
    register_test("Utils", "StringMore", test_utils_string_more);
    register_test("Utils", "MemHelpers", test_utils_mem_helpers);
    register_test("Utils", "OOMInjection", test_utils_oom_injection);
    register_test("Utils", "SListDuplicate", test_utils_slist_duplicate);
    register_test("Utils", "LogLevels", test_log_levels);
    register_test("Utils", "FrameHeaderBranches", test_utils_frame_header_branches);
}
