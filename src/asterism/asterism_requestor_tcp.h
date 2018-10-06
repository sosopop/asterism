#ifndef ASTERISM_REQUESTOR_TCP_H_
#define ASTERISM_REQUESTOR_TCP_H_
#include "asterism.h"
#include "asterism_core.h"
#include <uv.h>

struct asterism_tcp_requestor_s
{
	ASTERISM_STREAM_FIELDS
	unsigned int handshake_id;
	char* host_rhs;
	unsigned int port_rhs;
};

int asterism_requestor_tcp_init(struct asterism_s *as,
	const char *host_lhs, unsigned int port_lhs,
	const char *host_rhs, unsigned int port_rhs,
	unsigned int handshake_id, struct asterism_stream_s* stream);

#endif