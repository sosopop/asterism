#ifndef ASTERISM_OUTER_TCP_H_
#define ASTERISM_OUTER_TCP_H_
#include "asterism.h"
#include "asterism_core.h"
#include <uv.h>

struct asterism_tcp_outer_s
{
	uv_tcp_t socket;
	struct asterism_s *as;
};

struct asterism_tcp_incoming_s
{
	ASTERISM_STREAM_FIELDS
	struct asterism_session_s* session;
};

int asterism_outer_tcp_init(
	struct asterism_s *as,
	const char *ip, unsigned int *port);

#endif