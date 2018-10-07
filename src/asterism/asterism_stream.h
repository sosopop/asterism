#ifndef ASTERISM_STREAM_H_
#define ASTERISM_STREAM_H_

#include <uv.h>
#include "asterism_core.h"

#define ASTERISM_TCP_BLOCK_SIZE 4 * 1024

#define ASTERISM_STREAM_FIELDS \
uv_tcp_t socket;\
struct asterism_s* as;\
struct asterism_stream_s* link;\
char buffer[ASTERISM_TCP_BLOCK_SIZE];\
unsigned int buffer_len;\
uv_write_t write_req;\
uv_connect_cb _connect_cb;\
uv_close_cb _close_cb;\
uv_read_cb _read_cb;\
uv_alloc_cb _alloc_cb;\
unsigned char fin_recv : 1;\
unsigned char fin_send : 1;

typedef struct asterism_stream_s asterism_stream_t;

struct asterism_stream_s {
	ASTERISM_STREAM_FIELDS
};

int asterism_stream_connect(
	struct asterism_s* as,
	const char *host,
	unsigned int port,
	uv_connect_cb connect_cb,
	uv_alloc_cb alloc_cb,
	uv_read_cb read_cb,
	uv_close_cb close_cb,
	asterism_stream_t* stream
);

int asterism_stream_accept(
	struct asterism_s* as,
	uv_stream_t *server_stream,
	uv_alloc_cb alloc_cb,
	uv_read_cb read_cb,
	uv_close_cb close_cb,
	asterism_stream_t* stream
);

int asterism_stream_read(
	struct asterism_stream_s* stream
);

void asterism_stream_close(
	struct asterism_stream_s* stream
);

void asterism_stream_end(
	struct asterism_stream_s* stream
);

int asterism_stream_trans(
	struct asterism_stream_s* stream
);

void asterism_stream_eaten(
	struct asterism_stream_s* stream,
	unsigned int eaten
);

#endif // ASTERISM_STREAM_H_