#ifndef ASTERISM_CONNECTOR_TCP_H_
#define ASTERISM_CONNECTOR_TCP_H_
#include "asterism.h"
#include "asterism_core.h"
#include <uv.h>

#define ASTERISM_TCP_CONNECTOR_TYPE_CMD 0
#define ASTERISM_TCP_CONNECTOR_TYPE_DATA 1

struct asterism_tcp_connector_s
{
	ASTERISM_STREAM_FIELDS
	char* host;
	unsigned int port;
};

int asterism_connector_tcp_init(
	struct asterism_s *as,
	const char *host, unsigned int port);

#endif