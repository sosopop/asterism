#ifndef ASTERISM_CONNECTOR_TCP_H_
#define ASTERISM_CONNECTOR_TCP_H_
#include "asterism.h"
#include "asterism_core.h"
#include "asterism_stream.h"
#include <uv.h>

#define ASTERISM_TCP_CONNECTOR_TYPE_CMD 0
#define ASTERISM_TCP_CONNECTOR_TYPE_DATA 1


struct connector_timer_s;

struct asterism_tcp_connector_s
{
	ASTERISM_HANDLE_FIELDS
	ASTERISM_STREAM_FIELDS
	char* host;
	unsigned int port;
	struct connector_timer_s* heartbeat_timer;
};

struct connector_timer_s
{
	ASTERISM_HANDLE_FIELDS
	uv_timer_t timer;
	struct asterism_tcp_connector_s* connector;
};

int asterism_connector_tcp_init(
	struct asterism_s *as,
	const char *host, unsigned int port);

#endif