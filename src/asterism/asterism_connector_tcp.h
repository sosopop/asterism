#ifndef ASTERISM_CONNECTOR_TCP_H_
#define ASTERISM_CONNECTOR_TCP_H_
#include "asterism.h"
#include "asterism_core.h"
#include <uv.h>

struct asterism_tcp_connector_s
{
	uv_tcp_t socket;
	struct asterism_s *as;
	unsigned int fin_recv : 1;
	unsigned int fin_send : 1;
};

int asterism_connector_tcp_init(
	struct asterism_s *as,
	const char *host, unsigned int port);

#endif