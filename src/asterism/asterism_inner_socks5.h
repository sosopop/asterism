#ifndef ASTERISM_INNER_SOCKS5_H_
#define ASTERISM_INNER_SOCKS5_H_
#include <uv.h>
#include "asterism.h"
#include "asterism_core.h"
#include "asterism_utils.h"
#include "asterism_stream.h"
#include "s5.h"

typedef enum
{
    SOCKS5_STATUS_HANDSHAKE,
    SOCKS5_STATUS_HANDSHAKE_AUTH,
    SOCKS5_STATUS_CONNECT,
    SOCKS5_STATUS_TRANS
}socks5_status;

struct asterism_socks5_inner_s
{
    ASTERISM_HANDLE_FIELDS
    uv_tcp_t socket;
    struct asterism_s *as;
};

struct asterism_socks5_incoming_s
{
    ASTERISM_HANDLE_FIELDS
    ASTERISM_STREAM_FIELDS

    s5_ctx parser;
    unsigned int handshake_id;
    unsigned char status;
};

int asterism_inner_socks5_init(
    struct asterism_s *as,
    const char *ip, unsigned int *port);

#endif