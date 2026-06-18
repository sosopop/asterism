#include "asterism_datagram.h"
#include "asterism_log.h"

int asterism_datagram_init(
    struct asterism_s* as,
    uv_alloc_cb alloc_cb,
    uv_udp_recv_cb read_cb,
    uv_close_cb close_cb,
    struct asterism_datagram_s* datagram)
{
    if (!as || !as->loop || !datagram || !close_cb)
        return ASTERISM_E_INVALID_ARGS;

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
    QUEUE_INSERT_TAIL(&as->udp_conns_queue, &datagram->queue);
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
    struct asterism_s* as = datagram->as;
    if (nread <= 0)
    {
        // nread == 0 is an empty datagram / "no more data" marker, not an
        // error. Only log real errors: uv_strerror() on code 0 strdups an
        // "unknown error" string that libuv never frees (LeakSanitizer flags
        // it). Valid negative UV codes map to static strings, so no leak.
        if (nread < 0)
            asterism_log(ASTERISM_LOG_DEBUG, "%s", uv_strerror((int)nread));
        return;
    }

    QUEUE_REMOVE(&datagram->queue);
    QUEUE_INSERT_TAIL(&as->udp_conns_queue, &datagram->queue);
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

int asterism_datagram_stop_read(
    struct asterism_datagram_s* datagram)
{
    return uv_udp_recv_stop(&datagram->socket);
}

static void datagram_free_if_done(struct asterism_datagram_s* obj)
{
    // Free only once the uv handle has finished closing AND no in-flight
    // cross-stream write still holds a back-pointer to this datagram.
    if (obj->uv_closing && obj->pending_writes == 0)
    {
        AS_FREE(obj);
    }
}

static void inner_close_cb(
    uv_handle_t* handle)
{
    struct asterism_datagram_s* obj = __CONTAINER_PTR(struct asterism_datagram_s, socket, handle);
    QUEUE_REMOVE(&obj->queue);

    obj->uv_closing = 1;

    // The derived close callback now only clears back-pointers; it must not
    // free the struct. Memory ownership lives here so the free can be deferred
    // until pending_writes drops to zero.
    if (obj->_close_cb)
    {
        obj->_close_cb(handle);
    }

    asterism_log(ASTERISM_LOG_DEBUG, "udp connection is closing %p", handle);

    datagram_free_if_done(obj);
}

void asterism_datagram_close(
    uv_handle_t* handle)
{
    as_uv_close(handle, inner_close_cb);
}

void asterism_datagram_write_ref(
    struct asterism_datagram_s* datagram)
{
    datagram->pending_writes++;
}

void asterism_datagram_write_unref(
    struct asterism_datagram_s* datagram)
{
    if (datagram->pending_writes)
        datagram->pending_writes--;
    datagram_free_if_done(datagram);
}

int asterism_datagram_is_closing(
    struct asterism_datagram_s* datagram)
{
    return datagram->uv_closing;
}

static void datagram_send_cb(
    uv_udp_send_t* req,
    int status)
{
    struct asterism_send_req_s* send_req = (struct asterism_send_req_s*)req;
    if (status != 0)
    {
        asterism_log(ASTERISM_LOG_DEBUG, "%s", uv_strerror(status));
    }
    AS_SFREE(send_req->write_buffer.base);
    AS_FREE(send_req);
}

int asterism_datagram_write(
    struct asterism_datagram_s* datagram,
    const uv_buf_t* buf,
    const struct sockaddr* peer)
{
    int ret = 0;
    struct asterism_send_req_s* req = AS_ZMALLOC(struct asterism_send_req_s);
    if (!req)
        return ASTERISM_E_FAILED;
    req->write_buffer = *buf;
    req->write_buffer.base = __DUP_MEM(buf->base, buf->len);
    if (buf->len && !req->write_buffer.base)
    {
        AS_FREE(req);
        return ASTERISM_E_FAILED;
    }
    ret = uv_udp_send((uv_udp_send_t*)req, &datagram->socket, &req->write_buffer, 1, peer, datagram_send_cb);
    if (ret != 0)
    {
        AS_SFREE(req->write_buffer.base);
        AS_FREE(req);
    }
    return ret;
}
