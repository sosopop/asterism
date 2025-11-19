#ifndef ASTERISM_REQUESTOR_UDP_H_
#define ASTERISM_REQUESTOR_UDP_H_

#include "asterism.h"
#include "asterism_core.h"
#include "asterism_datagram.h"
#include <uv.h>

struct asterism_tcp_connector_s;

struct asterism_udp_addr_cache_s
{
    char domain[MAX_HOST_LEN];
    char ip[INET_ADDRSTRLEN];
    RB_ENTRY(asterism_udp_addr_cache_s)
        tree_entry;
};
RB_HEAD(asterism_udp_addr_cache_tree_s, asterism_udp_addr_cache_s);

struct asterism_udp_requestor_s
{
    ASTERISM_HANDLE_FIELDS
    ASTERISM_DATAGRAM_FIELDS
    struct sockaddr_in source_addr;
    struct uv_getaddrinfo_s* addr_req;
    struct asterism_tcp_connector_s* connector;
    struct asterism_udp_addr_cache_tree_s udp_addr_cache;
};

int asterism_udp_addr_cache_compare(struct asterism_udp_addr_cache_s* a, struct asterism_udp_addr_cache_s* b);

RB_PROTOTYPE(asterism_udp_addr_cache_tree_s, asterism_udp_addr_cache_s, tree_entry, asterism_udp_addr_cache_compare);

int asterism_requestor_udp_trans(
    struct asterism_tcp_connector_s* connector,
    unsigned char atyp,
    const char* remote_host, unsigned short remote_port, 
    struct sockaddr_in source_addr,
    const unsigned char* data,
    int data_len);

#endif