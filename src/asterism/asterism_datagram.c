#include "asterism_datagram.h"
#include "asterism_log.h"

int asterism_datagram_init(
    struct asterism_s* as,
    unsigned int crypt, 
    uv_alloc_cb alloc_cb, 
    uv_udp_recv_cb read_cb,
    uv_close_cb close_cb, 
    struct asterism_datagram_s* datagram)
{
    int ret = 0;

    ASTERISM_HANDLE_INIT(datagram, socket, asterism_datagram_close);

    datagram->as = as;
    datagram->active_tick_count = as->current_tick_count;
    datagram->_close_cb = close_cb;
    datagram->_alloc_cb = alloc_cb;
    datagram->_recv_cb = read_cb;

    ret = uv_udp_init(as->loop, &datagram->socket);
    if (ret != 0)
    {
        asterism_log(ASTERISM_LOG_DEBUG, "%s", uv_strerror(ret));
        ret = ASTERISM_E_SOCKET_LISTEN_ERROR;
        goto cleanup;
    }
cleanup:
    return ret;
}

static void datagram_read_alloc_cb(
    uv_handle_t* handle,
    size_t suggested_size,
    uv_buf_t* buf)
{
    struct asterism_datagram_s* datagram = __CONTAINER_PTR(struct asterism_datagram_s, socket, handle);
    if (datagram->_alloc_cb)
    {
        datagram->_alloc_cb(handle, suggested_size, buf);
    }
    else
    {
        buf->base = datagram->buffer;
        buf->len = ASTERISM_UDP_BLOCK_SIZE;
    }
}

static void inner_read(uv_udp_t* handle,
    ssize_t nread,
    const uv_buf_t* buf,
    const struct sockaddr* addr,
    unsigned flags)
{
    struct asterism_datagram_s* datagram = __CONTAINER_PTR(struct asterism_datagram_s, socket, handle);
    if (nread <= 0)
    {
        asterism_log(ASTERISM_LOG_DEBUG, "%s", uv_strerror((int)nread));
        return;
    }
    datagram->active_tick_count = datagram->as->current_tick_count;
    if (datagram->_recv_cb) {
        datagram->_recv_cb(handle, nread, buf, addr, flags);
    }
}

int asterism_datagram_read(
    struct asterism_datagram_s* datagram)
{
    return uv_udp_recv_start(&datagram->socket, datagram_read_alloc_cb, inner_read);
}

static void inner_close_cb(
    uv_handle_t* handle)
{
    struct asterism_datagram_s* obj = __CONTAINER_PTR(struct asterism_datagram_s, socket, handle);
    if (obj->_close_cb)
    {
        obj->_close_cb(handle);
    }
}

void asterism_datagram_close(
    uv_handle_t* handle)
{
    as_uv_close(handle, inner_close_cb);
}

int asterism_datagram_write(
    uv_udp_send_t* req,
    struct asterism_datagram_s* datagram, 
    const uv_buf_t* bufs, 
    uv_udp_send_cb cb)
{
    return 0;
}
