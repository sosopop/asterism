#ifndef ASTERISM_STREAM_H_
#define ASTERISM_STREAM_H_

#include <uv.h>
#include "asterism_core.h"

#define ASTERISM_TCP_BLOCK_SIZE 4 * 1024

#define ASTERISM_STREAM_FIELDS \
uv_tcp_t socket;\
char buffer[ASTERISM_TCP_BLOCK_SIZE];\
unsigned int buffer_len;\
uv_write_t write_req;\
struct asterism_s *as;\
struct asterism_stream_s* link;\
uv_connect_cb connect_cb;\
uv_close_cb close_cb;\
uv_read_cb read_cb;\
void* data;\
unsigned char fin_recv : 1;\
unsigned char fin_send : 1;

struct asterism_stream_s {
	ASTERISM_STREAM_FIELDS
};

struct asterism_stream_s* asterism_stream_connect(
	struct asterism_s *as,
	const char *host,
	unsigned int port,
	uv_connect_cb connect_cb,
	uv_close_cb close_cb,
	uv_read_cb read_cb
);

struct asterism_stream_s* asterism_stream_accept(
	struct asterism_s *as,
	uv_close_cb close_cb,
	uv_read_cb read_cb
);

int asterism_stream_read(
	struct asterism_stream_s* stream
);

void asterism_stream_close(
	struct asterism_stream_s* stream
);

#endif // ASTERISM_STREAM_H_