#ifndef ASTERISM_CORE_H_
#define ASTERISM_CORE_H_
#include <stdint.h>
#include <string.h>
#include <uv.h>
#include "asterism.h"
#include <tree.h>
#include "queue.h"
#include "asterism_utils.h"

struct asterism_portal_list_s;
struct asterism_portal_config_list_s;

#include "asterism_version.h"
#define ASTERISM_NET_BACKLOG 1024

#define ASTREISM_USERNAME_MAX_LEN 128
#define ASTREISM_PASSWORD_MAX_LEN 128

#define ASTERISM_UDP_BLOCK_SIZE 32 * 1024
#define ASTERISM_TCP_BLOCK_SIZE ASTERISM_UDP_BLOCK_SIZE

#define ASTERISM_MAX_HTTP_HEADER_SIZE ASTERISM_TCP_BLOCK_SIZE

#define ASTERISM_MAX_PROTO_SIZE ASTERISM_TCP_BLOCK_SIZE

#define ASTERISM_TRANS_PROTO_VERSION 0x20

#define MAX_HOST_LEN 256

/* Default idle timeout (seconds) for connections with no data transfer.
   Kept generous so that genuinely-in-use but momentarily idle tunnels
   (SSH/RDP/DB sessions) are not reaped; dead peers are detected via TCP
   keepalive (see stream_init). Can be overridden with -T/--idle-timeout
   (0 disables idle reaping entirely). */
#define ASTERISM_CONNECTION_MAX_IDLE_COUNT 300
/* Default idle timeout (seconds) for UDP associations. UDP is connectionless,
   so without reaping a relay/agent UDP socket would live as long as the TCP
   control channel; this bounds idle associations (close to common UDP NAT
   timeouts). Overridable with -t/--udp-idle-timeout (0 disables reaping). */
#define ASTERISM_UDP_MAX_IDLE_COUNT 60
#define ASTERISM_RECONNECT_DELAY 10000
#define ASTERISM_HEARTBEAT_INTERVAL 30000
/* Seconds a tunnel socket may be idle before the OS starts sending TCP
   keepalive probes to detect a dead peer. */
#define ASTERISM_TCP_KEEPALIVE_DELAY 60

/*
payload
user_name_len 2bytes
user_name char*
password_len 2bytes
password char*
*/
#define ASTERISM_TRANS_PROTO_JOIN 1

/*
payload
target_len 2bytes
target char*
handshake_id 4bytes
*/
#define ASTERISM_TRANS_PROTO_CONNECT 2

/*
payload
handshake_id 4bytes
*/
#define ASTERISM_TRANS_PROTO_CONNECT_ACK 3

#define ASTERISM_TRANS_PROTO_PING 4
#define ASTERISM_TRANS_PROTO_PONG 5

/*
payload
source address 4bytes
source port 2bytes
socks5 udp associate remote head
*/
#define ASTERISM_TRANS_PROTO_DATAGRAM_REQUEST 6

/*
payload
source address 4bytes
source port 2bytes
socks5 udp associate remote head
*/
#define ASTERISM_TRANS_PROTO_DATAGRAM_RESPONSE 7

#define as_uv_close(handle, close_cb)\
if (!uv_is_closing(handle)) {uv_close(handle, close_cb);}

typedef void (*as_close)(uv_handle_t *handle);

#define ASTERISM_HANDLE_FIELDS \
    as_close close;

#define ASTERISM_HANDLE_INIT(o, m, cls) \
    o->m.data = o;                      \
    o->close = cls;

#pragma pack(push)
#pragma pack(1)

struct asterism_trans_proto_s
{
    uint8_t version;
    uint8_t cmd;
    uint16_t len;
};

#pragma pack(pop)

static inline uint16_t asterism_read_be16(const void *data)
{
    uint16_t value;
    memcpy(&value, data, sizeof(value));
    return ntohs(value);
}

static inline uint32_t asterism_read_be32(const void *data)
{
    uint32_t value;
    memcpy(&value, data, sizeof(value));
    return ntohl(value);
}

static inline void asterism_write_be16(void *data, uint16_t value)
{
    value = htons(value);
    memcpy(data, &value, sizeof(value));
}

static inline void asterism_write_be32(void *data, uint32_t value)
{
    value = htonl(value);
    memcpy(data, &value, sizeof(value));
}

typedef struct asterism_s asterism_t;

struct asterism_write_req_s
{
    uv_write_t write_req;
    uv_buf_t write_buffer;
};

struct asterism_send_req_s
{
    uv_udp_send_t write_req;
    uv_buf_t write_buffer;
};

struct asterism_handle_s
{
    ASTERISM_HANDLE_FIELDS
};

struct asterism_stream_s;

typedef int (*connect_ack_cb)(struct asterism_stream_s *stream, int success);

struct asterism_handshake_s
{
    unsigned int id;
    struct asterism_stream_s *inner;
    connect_ack_cb conn_ack_cb;
    RB_ENTRY(asterism_handshake_s)
    tree_entry;
};
RB_HEAD(asterism_handshake_tree_s, asterism_handshake_s);

struct asterism_datagram_s;

struct asterism_session_s
{
    char *username;
    char *password;
    //udp
    struct asterism_datagram_s* inner_datagram;
    //tcp
    struct asterism_stream_s* outer;
    RB_ENTRY(asterism_session_s)
    tree_entry;
};
RB_HEAD(asterism_session_tree_s, asterism_session_s);

struct asterism_udp_session_s
{
    struct sockaddr_in source_addr;
    struct asterism_datagram_s* datagram;
    RB_ENTRY(asterism_udp_session_s)
        tree_entry;
};
RB_HEAD(asterism_udp_session_tree_s, asterism_udp_session_s);

struct asterism_s;

struct check_timer_s
{
    ASTERISM_HANDLE_FIELDS
    uv_timer_t timer;
    struct asterism_s *as;
};

struct asterism_s
{
    struct asterism_slist* inner_bind_addrs;
    char *outer_bind_addr;
    char *connect_addr;
    char *username;
    char *password;
    struct asterism_session_tree_s sessions;
    struct asterism_handshake_tree_s handshake_set;
    struct check_timer_s *check_timer;
    unsigned int current_tick_count;
    unsigned int idle_timeout;
    unsigned int udp_idle_timeout;
    unsigned int heartbeat_interval;
    unsigned int reconnect_delay;
    QUEUE conns_queue;
    QUEUE udp_conns_queue;
    asterism_connnect_redirect_hook connect_redirect_hook_cb;
    void *connect_redirect_hook_data;
    uv_loop_t *loop;
    unsigned char stoped : 1;
    unsigned char socks5_udp : 1;
    /* Set once ASTERISM_OPT_IDLE_TIMEOUT has been explicitly configured, so
       an explicit 0 (disable reaping) is distinguishable from "unset". */
    unsigned char idle_timeout_set : 1;
    /* Same for ASTERISM_OPT_UDP_IDLE_TIMEOUT: an explicit 0 disables UDP
       reaping; "unset" falls back to ASTERISM_UDP_MAX_IDLE_COUNT. */
    unsigned char udp_idle_timeout_set : 1;
    asterism_session_policy session_policy;
    char *session_auth_user;
    char *session_auth_pass;
    struct asterism_portal_list_s *portals;
    struct asterism_portal_config_list_s *portal_configs;
};

extern struct asterism_trans_proto_s _global_proto_ping;
extern struct asterism_trans_proto_s _global_proto_pong;

int asterism_core_prepare(struct asterism_s *as);

int asterism_core_destroy(struct asterism_s *as);

int asterism_core_run(struct asterism_s *as);

int asterism_core_stop(struct asterism_s *as);

int asterism_session_compare(struct asterism_session_s *a, struct asterism_session_s *b);

RB_PROTOTYPE(asterism_session_tree_s, asterism_session_s, tree_entry, asterism_session_compare);

int asterism_handshake_compare(struct asterism_handshake_s *a, struct asterism_handshake_s *b);

RB_PROTOTYPE(asterism_handshake_tree_s, asterism_handshake_s, tree_entry, asterism_handshake_compare);


int asterism_udp_session_compare(struct asterism_udp_session_s* a, struct asterism_udp_session_s* b);

RB_PROTOTYPE(asterism_udp_session_tree_s, asterism_udp_session_s, tree_entry, asterism_udp_session_compare);

unsigned int asterism_tunnel_new_handshake_id();

int asterism_proto_frame_size(const void *data, size_t data_len, uint16_t *frame_len);

int asterism_socks5_udp_header_size(
    const unsigned char *data,
    size_t data_len,
    size_t *header_len);

#endif
