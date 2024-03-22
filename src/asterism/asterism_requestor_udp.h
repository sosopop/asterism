#ifndef ASTERISM_REQUESTOR_UDP_H_
#define ASTERISM_REQUESTOR_UDP_H_

#include "asterism.h"
#include "asterism_core.h"
#include "asterism_datagram.h"
#include <uv.h>

struct asterism_tcp_connector_s;


struct requestor_getaddrinfo_s {
    struct uv_getaddrinfo_s addrinfo;
    uv_buf_t pendding_buffer;
};

struct asterism_udp_requestor_s
{
    ASTERISM_HANDLE_FIELDS
    ASTERISM_DATAGRAM_FIELDS
    struct sockaddr_in source_addr;
    struct requestor_getaddrinfo_s* addr_req;
    struct asterism_tcp_connector_s* connector;
};

int asterism_requestor_udp_trans(
    struct asterism_tcp_connector_s* connector,
    unsigned char atyp,
    const char* remote_host, unsigned short remote_port, 
    struct sockaddr_in source_addr,
    const unsigned char* data,
    int data_len);

#endif