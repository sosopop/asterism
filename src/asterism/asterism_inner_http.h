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
	ASTERISM_STREAM_FIELDS

    http_parser parser;
    struct asterism_str http_header_field_temp;
    struct asterism_str http_header_value_temp;
    struct asterism_str connect_host;
    struct asterism_str auth_info;

    unsigned int header_parsed : 1;
    unsigned int header_auth_parsed : 1;
};

int asterism_inner_http_init(
    struct asterism_s *as,
    const char *ip, unsigned int *port);

#endif