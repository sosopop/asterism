#include "asterism_outer_tcp.h"
#include "asterism_core.h"
#include "asterism_utils.h"

int asterism_outer_tcp_bind(struct asterism_s *as)
{
    int ret = ASTERISM_E_OK;
    //struct sockaddr_in addr;
    struct asterism_tcp_outer *stream = __zero_malloc_st(struct asterism_tcp_outer);
    stream->socket = __zero_malloc_st(uv_tcp_t);

    ret = uv_tcp_init(as->loop, stream->socket);
    if (ret != 0)
        goto cleanup;
    /*
    ret = uv_ip4_addr(ip, *port ? *port : 0, &addr);
    if (ret != 0)
        goto cleanup;
    ret = uv_tcp_bind(net->socket, (const struct sockaddr *)&addr, 0);
    if (ret != 0)
        goto cleanup;
    ret = uv_tcp_nodelay(net->socket, 1);
    if (ret != 0)
        goto cleanup;
    name_len = sizeof(addr);
    ret = uv_tcp_getsockname(net->socket, (struct sockaddr *)&addr, &name_len);
    if (ret != 0)
        goto cleanup;
    *port = ntohs(addr.sin_port);
    ret = uv_listen((uv_stream_t *)net->socket, HDTRANS_NET_BACKLOG, net_accept_cb);
    if (ret != 0)
        goto cleanup;
*/
    as->outer_stream = stream;
cleanup:
    return ret;
}

int asterism_outer_tcp_connect_addr(struct asterism_s *as)
{
    int ret = ASTERISM_E_OK;
    //cleanup:
    return ret;
}