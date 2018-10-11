#ifndef ASTERISM_INNER_HTTP_H_
#define ASTERISM_INNER_HTTP_H_
#include <uv.h>
#include <http_parser.h>
#include "asterism.h"
#include "asterism_core.h"
#include "asterism_utils.h"
#include "asterism_stream.h"

#define HTTP_RESP_407                                                \
    "HTTP/1.1 407 Proxy Authentication Required\r\n"                 \
    "Proxy-Authenticate: Basic realm=\"Asterism Authorization\"\r\n" \
    "Content-Length: 0\r\n\r\n"

#define HTTP_RESP_200                                                \
    "HTTP/1.1 200 Connection Established\r\n\r\n"

#define HTTP_PROXY_AUTH_HEAD "Proxy-Authorization"

#define HTTP_PROXY_CONN_HEAD "Proxy-Connection"

#define HTTP_PROXY_PREFIX_HEAD "Proxy-"

#define HTTP_PROTOCOL_TOKEN "http://"

#define HTTP_DEFAULT_PORT ":80"

struct asterism_http_inner_s
{
    ASTERISM_HANDLE_FIELDS
    uv_tcp_t socket;
    struct asterism_s *as;
};

#define HEADER_PARSED_TYPE_NULL 0
#define HEADER_PARSED_TYPE_AUTH 1

struct asterism_http_incoming_s
{
    ASTERISM_HANDLE_FIELDS
    ASTERISM_STREAM_FIELDS

    http_parser parser;
    struct asterism_str http_header_field_temp;
    struct asterism_str http_header_value_temp;
	struct asterism_str connect_url;
	struct asterism_str auth_val_info;
	//not connect
	struct asterism_str auth_key_info;
	struct asterism_str conn_key_info;
	struct asterism_str host_info;

	unsigned int handshake_id;
    unsigned char header_parsed : 1;
	unsigned char header_parsed_type : 2;
	unsigned char is_connect : 1;
};

int asterism_inner_http_init(
    struct asterism_s *as,
    const char *ip, unsigned int *port);

#endif