#ifndef ASTERISM_REQUESTOR_TCP_H_
#define ASTERISM_REQUESTOR_TCP_H_
#include "asterism.h"
#include "asterism_core.h"
#include <uv.h>

struct asterism_tcp_requestor_s
{
	ASTERISM_STREAM_FIELDS
};

int asterism_requestor_tcp_init(struct asterism_s *as,
	const char *host, unsigned int port, struct asterism_stream_s* stream);

#endif