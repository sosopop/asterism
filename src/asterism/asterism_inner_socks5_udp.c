#include "asterism_inner_socks5_udp.h"
#include "asterism_log.h"

static void inner_close_cb(
    uv_handle_t* handle)
{
    struct asterism_socks5_udp_inner_s* obj = __CONTAINER_PTR(struct asterism_socks5_udp_inner_s, socket, handle);
    AS_FREE(obj);
}

static void inner_close(
    uv_handle_t* handle)
{
    as_uv_close(handle, inner_close_cb);
}

static void inner_read_alloc_cb(
    uv_handle_t* handle,
    size_t suggested_size,
    uv_buf_t* buf)
{
    struct asterism_socks5_udp_inner_s* datagram = __CONTAINER_PTR(struct asterism_socks5_udp_inner_s, socket, handle);
    buf->base = datagram->buffer;
    buf->len = ASTERISM_UDP_BLOCK_SIZE;
}

static void inner_read(uv_udp_t* handle,
    ssize_t nread,
    const uv_buf_t* buf,
    const struct sockaddr* addr,
    unsigned flags)
{
    struct asterism_socks5_udp_inner_s* datagram = __CONTAINER_PTR(struct asterism_socks5_udp_inner_s, socket, handle);
    if (nread < 0)
	{
		asterism_log(ASTERISM_LOG_DEBUG, "%s", uv_strerror((int)nread));
		return;
	}
    // uv_udp_recv_stop(handle);
    asterism_log(ASTERISM_LOG_DEBUG, "udp recv %.*s\n", nread, buf->base);
    // trans to remote
    // uv_udp_recv_start(handle, inner_read_alloc_cb, inner_read);
}

int asterism_inner_socks5_udp_init(
    struct asterism_s* as, 
    struct asterism_session_s* session, 
    const char* ip, unsigned int* port)
{
    int ret = ASTERISM_E_OK;
    void* addr = 0;
    int name_len = 0;
    struct asterism_socks5_udp_inner_s* inner = AS_ZMALLOC(struct asterism_socks5_udp_inner_s);
    inner->as = as;
    ASTERISM_HANDLE_INIT(inner, socket, inner_close);
    ret = uv_udp_init(as->loop, &inner->socket);
    if (ret != 0)
    {
        asterism_log(ASTERISM_LOG_DEBUG, "%s", uv_strerror(ret));
        ret = ASTERISM_E_SOCKET_LISTEN_ERROR;
        goto cleanup;
    }
    addr = AS_ZMALLOC(struct sockaddr_in);
    name_len = sizeof(struct sockaddr_in);
    ret = uv_ip4_addr(ip, (int)*port, (struct sockaddr_in*)addr);
    if (ret != 0)
    {
        asterism_log(ASTERISM_LOG_DEBUG, "%s", uv_strerror(ret));
        ret = ASTERISM_E_SOCKET_LISTEN_ERROR;
        goto cleanup;
    }
    ret = uv_udp_bind(&inner->socket, (const struct sockaddr*)addr, 0);
    if (ret != 0)
    {
        asterism_log(ASTERISM_LOG_DEBUG, "%s", uv_strerror(ret));
        ret = ASTERISM_E_SOCKET_LISTEN_ERROR;
        goto cleanup;
    }
    ret = uv_udp_getsockname(&inner->socket, (struct sockaddr*)addr, &name_len);
    if (ret != 0)
    {
        asterism_log(ASTERISM_LOG_DEBUG, "%s", uv_strerror(ret));
        ret = ASTERISM_E_SOCKET_LISTEN_ERROR;
        goto cleanup;
    }

    *port = ntohs(((struct sockaddr_in*)addr)->sin_port);

    ret = uv_udp_recv_start(&inner->socket, inner_read_alloc_cb, inner_read);
    if (ret != 0)
    {
        asterism_log(ASTERISM_LOG_DEBUG, "%s", uv_strerror(ret));
        ret = ASTERISM_E_SOCKET_LISTEN_ERROR;
        goto cleanup;
    }

    session->inner_udp = (struct asterism_datagram_s*)inner;
cleanup:
    if (addr)
    {
        AS_FREE(addr);
    }
    if (ret)
    {
        inner_close((uv_handle_t*)&inner->socket);
    }
    return ret;
}
