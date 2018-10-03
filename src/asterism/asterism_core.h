#ifndef ASTERISM_CORE_H_
#define ASTERISM_CORE_H_
#include <stdint.h>
#include <uv.h>
#include "asterism.h"
#include "queue.h"
#include <tree.h>

#define ASTERISM_VERSION "0.0.0.1"
#define ASTERISM_RECONNECT_DELAY 10000
#define ASTERISM_NET_BACKLOG 1024

#define ASTREISM_USERNAME_MAX_LEN 128
#define ASTREISM_PASSWORD_MAX_LEN 128

#define ASTERISM_TCP_BLOCK_SIZE 4 * 1024
#define ASTERISM_MAX_HTTP_HEADER_SIZE 4 * 1024

#define ASTERISM_MAX_PROTO_SIZE 4 * 1024

#define ASTERISM_TRANS_PROTO_VERSION 0x10

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
connect_sign 4bytes
*/
#define ASTERISM_TRANS_PROTO_CONNECT 2

/*
payload
connect_sign 4bytes
*/
#define ASTERISM_TRANS_PROTO_CONNECT_ACK 3

#define ASTERISM_TRANS_PROTO_PING 4
#define ASTERISM_TRANS_PROTO_PONG 5

#pragma pack(push)
#pragma pack(1)

struct asterism_trans_proto_s
{
    uint8_t version;
    uint8_t cmd;
    uint16_t len;
};

#pragma pack(pop)

struct asterism_tunnel_s {
	unsigned int handshake_id;
	void* inner;
	void* outer;
	char inner_buffer[ASTERISM_TCP_BLOCK_SIZE];
	unsigned int inner_buffer_len;
	uv_write_t inner_writer;

	char outer_buffer[ASTERISM_TCP_BLOCK_SIZE];
	unsigned int outer_buffer_len;
	uv_write_t outer_writer;

	void* handshake_queue[2];
};

struct asterism_session_s {
	char* username;
	char* password;
	void* outer;

	void* handshake_queue[2];
	RB_ENTRY(asterism_session_s) tree_entry;
};

RB_HEAD(asterism_session_tree_s, asterism_session_s);

struct asterism_s
{
    char *inner_bind_addr;
    char *outer_bind_addr;
    char *connect_addr;
    char *username;
    char *password;
	struct asterism_session_tree_s sessions;
    asterism_connnect_redirect_hook connect_redirect_hook_cb;
    uv_loop_t *loop;
};

struct asterism_write_req_s
{
    uv_write_t write_req;
    uv_buf_t write_buffer;
};

int asterism_core_prepare(struct asterism_s *as);

int asterism_core_destory(struct asterism_s *as);

int asterism_core_run(struct asterism_s *as);

int asterism_session_compare(struct asterism_session_s* a, struct asterism_session_s* b);

RB_PROTOTYPE(asterism_session_tree_s, asterism_session_s, tree_entry, asterism_session_compare);

unsigned int asterism_tunnel_new_handshake_id();

#endif