#include "asterism_inner_http.h"
#include "asterism_core.h"
#include "asterism_log.h"
#include "asterism_utils.h"

static struct asterism_http_inner *inner_new(struct asterism_s *as)
{
    struct asterism_http_inner *inner = __zero_malloc_st(struct asterism_http_inner);
    inner->socket = __zero_malloc_st(uv_tcp_t);
    inner->asterism = as;
    return inner;
}

static void inner_delete(struct asterism_http_inner *inner)
{
    free(inner->socket);
    free(inner);
}

static void close_cb(
    uv_handle_t *handle)
{
    int ret = 0;
    struct asterism_http_inner *inner = 0;
    inner = (struct asterism_http_inner *)handle->data;
    inner_delete(inner);
}

void inner_close(
    struct asterism_http_inner *inner)
{
    if (!uv_is_closing((uv_handle_t *)inner->socket))
        uv_close((uv_handle_t *)inner->socket, close_cb);
}

static void accept_cb(
    uv_stream_t *stream,
    int status)
{
    int ret = 0;
    //////////////////////////////////////////////////////////////////////////
    //cleanup:
    if (status != 0 || ret != 0)
    {
        //close(net);
    }
}

int asterism_inner_http_init(
    struct asterism_s *as,
    const char *ip, unsigned int *port, int ipv6)
{
    int ret = ASTERISM_E_OK;
    struct asterism_http_inner *inner = inner_new(as);
    void *addr = 0;
    int name_len = 0;

    ret = uv_tcp_init(as->loop, inner->socket);
    if (ret != 0)
    {
        asterism_log(ASTERISM_LOG_DEBUG, "%s", uv_strerror(ret));
        ret = ASTERISM_E_SOCKET_LISTEN_ERROR;
        goto cleanup;
    }
    if (ipv6)
    {
        addr = __zero_malloc_st(struct sockaddr_in6);
        name_len = sizeof(struct sockaddr_in6);
        ret = uv_ip6_addr(ip, (int)*port, addr);
    }
    else
    {
        addr = __zero_malloc_st(struct sockaddr_in);
        name_len = sizeof(struct sockaddr_in);
        ret = uv_ip4_addr(ip, (int)*port, addr);
    }
    if (ret != 0)
    {
        asterism_log(ASTERISM_LOG_DEBUG, "%s", uv_strerror(ret));
        ret = ASTERISM_E_SOCKET_LISTEN_ERROR;
        goto cleanup;
    }
    ret = uv_tcp_bind(inner->socket, (const struct sockaddr *)addr, 0);
    if (ret != 0)
    {
        asterism_log(ASTERISM_LOG_DEBUG, "%s", uv_strerror(ret));
        ret = ASTERISM_E_SOCKET_LISTEN_ERROR;
        goto cleanup;
    }
    ret = uv_tcp_nodelay(inner->socket, 1);
    if (ret != 0)
    {
        asterism_log(ASTERISM_LOG_DEBUG, "%s", uv_strerror(ret));
        ret = ASTERISM_E_SOCKET_LISTEN_ERROR;
        goto cleanup;
    }
    ret = uv_tcp_getsockname(inner->socket, (struct sockaddr *)addr, &name_len);
    if (ret != 0)
    {
        asterism_log(ASTERISM_LOG_DEBUG, "%s", uv_strerror(ret));
        ret = ASTERISM_E_SOCKET_LISTEN_ERROR;
        goto cleanup;
    }
    if (ipv6)
    {
        *port = ntohs(((struct sockaddr_in6*)addr)->sin6_port);
    }
    else
    {
        *port = ntohs(((struct sockaddr_in*)addr)->sin_port);
    }

    ret = uv_listen((uv_stream_t *)inner->socket, ASTERISM_NET_BACKLOG, accept_cb);
    if (ret != 0)
    {
        asterism_log(ASTERISM_LOG_DEBUG, "%s", uv_strerror(ret));
        ret = ASTERISM_E_SOCKET_LISTEN_ERROR;
        goto cleanup;
    }
cleanup:
    if (ret)
    {
        if (inner->socket->loop)
        {
            inner_close(inner);
        }
        else
        {
            inner_delete(inner);
        }
    }
    return ret;
}