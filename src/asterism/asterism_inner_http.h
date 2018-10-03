#ifndef ASTERISM_INNER_HTTP_H_
#define ASTERISM_INNER_HTTP_H_
#include <uv.h>
#include <http_parser.h>
#include "asterism.h"
#include "asterism_core.h"
#include "asterism_utils.h"

struct asterism_http_inner_s
{
    uv_tcp_t socket;
    struct asterism_s *as;
};

struct asterism_http_incoming_s
{
    uv_tcp_t socket;
    struct asterism_s *as;
    http_parser parser;
    struct asterism_str http_header_field_temp;
    struct asterism_str http_header_value_temp;
    struct asterism_str connect_host;
    struct asterism_str auth_info;
	struct asterism_session_s* session;
	struct asterism_tunnel_s* tunnel;

	char buffer[ASTERISM_TCP_BLOCK_SIZE];
	unsigned int buffer_len;
	struct asterism_write_req_s write_req;

    char *remote_host;
    char *username;
    char *password;
    unsigned int tunnel_connected : 1;
    unsigned int header_parsed : 1;
    unsigned int header_auth_parsed : 1;
    unsigned int fin_recv : 1;
    unsigned int fin_send : 1;
};

int asterism_inner_http_init(
    struct asterism_s *as,
    const char *ip, unsigned int *port, int ipv6);

#endif