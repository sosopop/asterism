#ifndef ASTERISM_OUTER_TCP_H_
#define ASTERISM_OUTER_TCP_H_
#include "asterism.h"
#include "asterism_core.h"
#include "asterism_buffer.h"
#include <uv.h>

struct asterism_tcp_outer_s
{
	uv_tcp_t socket;
	struct asterism_s *as;
};


#define ASTERISM_TCP_CONNECTION_TYPE_CMD 0
#define ASTERISM_TCP_CONNECTION_TYPE_DATA 1

struct asterism_tcp_incoming_s
{
	uv_tcp_t socket;
	struct asterism_s *as;
	unsigned int fin_recv : 1;
	unsigned int fin_send : 1;
	unsigned int connection_type : 1;
	char* cmd_buffer;
	unsigned short cmd_buffer_len;
};

int asterism_outer_tcp_init(
	struct asterism_s *as,
	const char *ip, unsigned int *port, int ipv6);

#endif