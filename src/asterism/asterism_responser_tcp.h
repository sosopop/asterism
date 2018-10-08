#ifndef ASTERISM_RESPONSER_TCP_H_
#define ASTERISM_RESPONSER_TCP_H_
#include "asterism.h"
#include "asterism_core.h"
#include "asterism_stream.h"
#include <uv.h>

struct asterism_tcp_responser_s
{
	ASTERISM_HANDLE_FIELDS
	ASTERISM_STREAM_FIELDS
	unsigned int handshake_id;
	char* host_rhs;
	unsigned int port_rhs;
};

int asterism_responser_tcp_init(struct asterism_s *as,
	const char *host, unsigned int port,
	unsigned int handshake_id, struct asterism_stream_s* stream);

#endif