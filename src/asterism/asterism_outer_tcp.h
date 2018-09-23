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
	uv_tcp_t socket;
	struct asterism_s *as;
	unsigned int fin_recv : 1;
	unsigned int fin_send : 1;
};

int asterism_outer_tcp_init(
	struct asterism_s *as,
	const char *ip, unsigned int *port, int ipv6);

#endif