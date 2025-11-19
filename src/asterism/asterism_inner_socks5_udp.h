#ifndef ASTERISM_INNER_SOCKS5_UDP_H_
#define ASTERISM_INNER_SOCKS5_UDP_H_
#include <uv.h>
#include "asterism.h"
#include "asterism_core.h"
#include "asterism_utils.h"
#include "asterism_datagram.h"
#include "s5.h"

struct asterism_socks5_udp_inner_s
{
    ASTERISM_HANDLE_FIELDS
    ASTERISM_DATAGRAM_FIELDS
    struct asterism_session_s* session;
};

int asterism_inner_socks5_udp_init(
    struct asterism_s* as,
    struct asterism_session_s* session,
    const char* ip, unsigned int* port);

#endif