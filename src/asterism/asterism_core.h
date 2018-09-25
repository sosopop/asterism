#ifndef ASTERISM_CORE_H_
#define ASTERISM_CORE_H_
#include <stdint.h>
#include <uv.h>
#include "asterism.h"
#include "queue.h"

#define ASTERISM_VERSION "0.0.0.1"
#define ASTERISM_RECONNECT_DELAY 10000
#define ASTERISM_NET_BACKLOG 1024

#define ASTREISM_USERNAME_MAX_LEN 128
#define ASTREISM_PASSWORD_MAX_LEN 128

#define ASTERISM_TCP_BLOCK_SIZE 4 * 1024
#define ASTERISM_MAX_HTTP_HEADER_SIZE 4 * 1024

#define ASTERISM_TRANS_PROTO_VERSION 0x10
#define ASTERISM_TRANS_PROTO_SIGN 'A'

#define ASTERISM_TRANS_PROTO_CONNECT 1
#define ASTERISM_TRANS_PROTO_CONNECT_ACK 2
#define ASTERISM_TRANS_PROTO_DATA 3
#define ASTERISM_TRANS_PROTO_DATA_ACK 4
#define ASTERISM_TRANS_PROTO_DISCONNECT 5
#define ASTERISM_TRANS_PROTO_DISCONNECT_ACK 6
#define ASTERISM_TRANS_PROTO_PING 7
#define ASTERISM_TRANS_PROTO_PONG 8

#define ASTERISM_TRANS_PROTO_WIN_SIZE 8
//#define ASTERISM_TRANS_PROTO_WIN_SIZE 8

#pragma pack(push)
#pragma pack(1)
struct asterism_trans_proto_s
{
    uint8_t version;
    uint8_t sign;
    uint64_t id;
    uint16_t seq;
    uint16_t seq_ack;
    //剩余窗口大小
    uint16_t win_size;
    uint16_t packet_size;
    uint8_t cmd;
    uint8_t payload[1];
};
#pragma pack(pop)

uint64_t asterism_trans_new_id();

struct asterism_route_data
{
    int dummy;
};

struct asterism_s
{
    char *inner_bind_addr;
    char *outer_bind_addr;
    char *connect_addr;
    char *username;
    char *password;
    void *inner_stream;
    void *outer_stream;
    asterism_connnect_redirect_hook connect_redirect_hook_cb;
    uv_loop_t *loop;
};

struct asterism_write_req_s
{
    uv_write_t write_req;
    uv_buf_t write_buffer;
};

/***
 * over tcp virtual link protocol
 * conv_id 4bytes
 * sequence_number 4bytes
 * ack_sequence_number 4bytes
 * free_buffer_size 4bytes
 * package_size 2bytes
 * payload package_size - head_size
 * */

int asterism_core_prepare(struct asterism_s *as);

int asterism_core_destory(struct asterism_s *as);

int asterism_core_run(struct asterism_s *as);

#endif