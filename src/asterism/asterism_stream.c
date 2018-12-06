#include "asterism_stream.h"
#include "asterism_utils.h"
#include "asterism_log.h"
#include "queue.h"

static void stream_shutdown_cb(
    uv_shutdown_t *req,
    int status)
{
    struct asterism_stream_s *stream = (struct asterism_stream_s *)req->data;
    asterism_stream_close((uv_handle_t *)&stream->socket);
    AS_FREE(req);
}

static int stream_end(
    struct asterism_stream_s *stream)
{
    int ret = 0;
    uv_shutdown_t *req = 0;
    //////////////////////////////////////////////////////////////////////////
    req = AS_ZMALLOC(uv_shutdown_t);
    req->data = stream;
    ret = uv_shutdown(req, (uv_stream_t *)&stream->socket, stream_shutdown_cb);
    if (ret != 0)
    {
        asterism_log(ASTERISM_LOG_DEBUG, "%s", uv_strerror((int)ret));
        goto cleanup;
    }
cleanup:
    if (ret != 0)
    {
        if (req)
        {
            AS_FREE(req);
        }
    }
    return ret;
}

static void stream_read_alloc_cb(
    uv_handle_t *handle,
    size_t suggested_size,
    uv_buf_t *buf)
{
    struct asterism_stream_s *stream = __CONTAINER_PTR(struct asterism_stream_s, socket, handle);
    if (stream->_alloc_cb)
    {
        stream->_alloc_cb(handle, suggested_size, buf);
    }
    else
    {
        buf->base = stream->buffer + stream->buffer_len;
        buf->len = ASTERISM_TCP_BLOCK_SIZE - stream->buffer_len;
    }
}

static void stream_read_cb(
    uv_stream_t *stream,
    ssize_t nread,
    const uv_buf_t *buf)
{
    struct asterism_stream_s *stm = __CONTAINER_PTR(struct asterism_stream_s, socket, stream);

    if (nread > 0)
    {
        if (stm->crypt)
        {
            for (int i = 0; i < nread; i++)
            {
                buf->base[i] ^= 'A';
            }
        }
        struct asterism_s *as = stm->as;
        stm->active_tick_count = as->current_tick_count;
        QUEUE_REMOVE(&stm->queue);
        QUEUE_INSERT_TAIL(&as->conns_queue, &stm->queue);

        stm->buffer_len += (unsigned int)nread;
        if (stm->link && stm->auto_trans)
        {
            if (asterism_stream_trans(stm))
            {
                asterism_stream_close((uv_handle_t *)stream);
            }
        }
        else
        {
            stm->_read_cb(stream, nread, buf);
        }
    }
    else if (nread == 0)
    {
        asterism_stream_close((uv_handle_t *)stream);
        return;
    }
    else if (nread == UV_EOF)
    {
        asterism_stream_close((uv_handle_t *)stream);
        if (stm->link)
        {
            stream_end(stm->link);
        }
    }
    else
    {
        asterism_log(ASTERISM_LOG_DEBUG, "%s", uv_strerror((int)nread));
        asterism_stream_close((uv_handle_t *)stream);
    }
}

static void stream_connected(
    uv_connect_t *req,
    int status)
{
    int ret = 0;
    struct asterism_stream_s *stream = (struct asterism_stream_s *)req->data;
    stream->_connect_cb(req, status);
    if (status < 0)
    {
        ret = ASTERISM_E_FAILED;
        goto cleanup;
    }
cleanup:
    if (ret != 0)
    {
        asterism_stream_close((uv_handle_t *)&stream->socket);
    }
    if (req)
        AS_FREE(req);
}

static void stream_getaddrinfo(
    uv_getaddrinfo_t *req,
    int status,
    struct addrinfo *res)
{
    int ret = ASTERISM_E_OK;
    uv_connect_t *connect_req = 0;
    struct asterism_stream_s *stream = (struct asterism_stream_s *)req->data;
    char addr[17] = {'\0'};
    if (!stream)
    {
        goto cleanup;
    }
    stream->addr_req = 0;
    if (status != 0)
    {
        ret = status;
        goto cleanup;
    }
    //only support ipv4
    ret = uv_ip4_name((struct sockaddr_in *)res->ai_addr, addr, 16);
    if (ret != 0)
    {
        goto cleanup;
    }
    connect_req = (uv_connect_t *)AS_MALLOC(sizeof(uv_connect_t));
    connect_req->data = stream;
    ret = uv_tcp_connect(connect_req, (uv_tcp_t *)&stream->socket, res->ai_addr, stream_connected);
    if (ret != 0)
    {
        goto cleanup;
    }
cleanup:
    if (res)
        uv_freeaddrinfo(res);
    if (req)
        AS_FREE(req);
    if (ret != 0 && stream)
        asterism_stream_close((uv_handle_t *)&stream->socket);
}

static void stream_close_cb(
    uv_handle_t *handle)
{
    struct asterism_stream_s *stream = __CONTAINER_PTR(struct asterism_stream_s, socket, handle);

    QUEUE_REMOVE(&stream->queue);

    if (stream->link)
    {
        asterism_stream_close((uv_handle_t *)&stream->link->socket);
        stream->link->link = 0;
    }
    stream->_close_cb((uv_handle_t *)&stream->socket);

    asterism_log(ASTERISM_LOG_DEBUG, "tcp connection is closing %p", handle);
}

void asterism_stream_close(uv_handle_t *handle)
{
    if (!uv_is_closing(handle))
    {
        struct asterism_stream_s *stream = __CONTAINER_PTR(struct asterism_stream_s, socket, handle);
        if (stream->addr_req)
        {
            stream->addr_req->data = 0;
            uv_cancel((uv_req_t *)stream->addr_req);
            stream->addr_req = 0;
        }
        uv_close(handle, stream_close_cb);
    }
}

int asterism_stream_end(
    struct asterism_stream_s *stream)
{
    return stream_end(stream);
}

static int stream_init(
    asterism_stream_t *stream,
    struct asterism_s *as)
{
    stream->as = as;
    ASTERISM_HANDLE_INIT(stream, socket, asterism_stream_close);

    QUEUE_INSERT_TAIL(&as->conns_queue, &stream->queue);
    int ret = uv_tcp_init(as->loop, (uv_tcp_t *)&stream->socket);
    if (ret != 0)
    {
        asterism_log(ASTERISM_LOG_DEBUG, "%s", uv_strerror(ret));
        return ret;
    }

    stream->active_tick_count = as->current_tick_count;
    asterism_log(ASTERISM_LOG_DEBUG, "tcp init %p", stream);
    return ret;
}

int asterism_stream_connect(
    struct asterism_s *as,
    const char *host,
    unsigned int port,
    unsigned int auto_trans,
    unsigned int crypt,
    uv_connect_cb connect_cb,
    uv_alloc_cb alloc_cb,
    uv_read_cb read_cb,
    uv_close_cb close_cb,
    asterism_stream_t *stream)
{
    int ret = stream_init(stream, as);
    if (ret != 0)
    {
        return ret;
    }

    stream->auto_trans = auto_trans;
    stream->crypt = crypt;
    stream->_connect_cb = connect_cb;
    stream->_close_cb = close_cb;
    stream->_read_cb = read_cb;
    stream->_alloc_cb = alloc_cb;

    stream->addr_req = (uv_getaddrinfo_t *)AS_MALLOC(sizeof(uv_getaddrinfo_t));
    stream->addr_req->data = stream;

    char port_str[10] = {0};
    asterism_itoa(port_str, sizeof(port_str), port, 10, 0, 0);
    ret = uv_getaddrinfo(as->loop, stream->addr_req, stream_getaddrinfo, host, port_str, 0);
    if (ret != 0)
    {
        asterism_log(ASTERISM_LOG_DEBUG, "%s", uv_strerror(ret));
        goto cleanup;
    }
    ret = 0;
cleanup:
    if (ret)
    {
        AS_SFREE(stream->addr_req);
        stream->addr_req = 0;
    }
    return ret;
}

int asterism_stream_accept(
    struct asterism_s *as,
    uv_stream_t *server_stream,
    unsigned int auto_trans,
    unsigned int crypt,
    uv_alloc_cb alloc_cb,
    uv_read_cb read_cb,
    uv_close_cb close_cb,
    asterism_stream_t *stream)
{
    int ret = stream_init(stream, as);
    if (ret != 0)
    {
        return ret;
    }

    stream->auto_trans = auto_trans;
    stream->crypt = crypt;
    stream->_alloc_cb = alloc_cb;
    stream->_read_cb = read_cb;
    stream->_close_cb = close_cb;

    ret = uv_accept(server_stream, (uv_stream_t *)&stream->socket);
    if (ret != 0)
    {
        ret = ASTERISM_E_FAILED;
        goto cleanup;
    }
cleanup:
    return ret;
}

int asterism_stream_read(
    struct asterism_stream_s *stream)
{
    int ret = uv_read_start((uv_stream_t *)&stream->socket, stream_read_alloc_cb, stream_read_cb);
    if (ret != 0)
    {
        asterism_log(ASTERISM_LOG_DEBUG, "%s", uv_strerror(ret));
        goto cleanup;
    }
cleanup:
    return ret;
}

int asterism_stream_write(
    uv_write_t *req,
    struct asterism_stream_s *stream,
    const uv_buf_t *bufs,
    uv_write_cb cb)
{
    if (stream->crypt)
    {
        int len = bufs->len;
        char *base = bufs->base;
        for (int i = 0; i < len; i++)
        {
            base[i] ^= 'A';
        }
    }
    return uv_write(req, (uv_stream_t *)&stream->socket, bufs, 1, cb);
}

static void link_write_cb(
    uv_write_t *req,
    int status)
{
    struct asterism_stream_s *stream = (struct asterism_stream_s *)req->data;
    if (status != 0)
    {
        asterism_stream_close((uv_handle_t *)&stream->socket);
        return;
    }
    if (stream->link)
        stream->link->active_tick_count = stream->as->current_tick_count;

    if (asterism_stream_read(stream))
    {
        asterism_stream_close((uv_handle_t *)&stream->socket);
    }
}

int asterism_stream_trans(
    struct asterism_stream_s *stream)
{
    int ret = 0;
    memset(&stream->link->write_req, 0, sizeof(stream->link->write_req));
    stream->link->write_req.data = stream;
    uv_buf_t _buf;
    _buf.base = stream->buffer;
    _buf.len = stream->buffer_len;
    stream->buffer_len = 0;

    ret = asterism_stream_write(&stream->link->write_req, (struct asterism_stream_s *)stream->link, &_buf, link_write_cb);
    if (ret)
    {
        goto cleanup;
    }
    ret = uv_read_stop((uv_stream_t *)&stream->socket);
    if (ret)
    {
        goto cleanup;
    }
cleanup:
    return ret;
}

void asterism_stream_set_autotrans(struct asterism_stream_s *stream, unsigned int enable)
{
    stream->auto_trans = enable;
}

void asterism_stream_eaten(struct asterism_stream_s *stream, unsigned int eaten)
{
    if (eaten == stream->buffer_len)
    {
        stream->buffer_len = 0;
    }
    else if (eaten <= stream->buffer_len)
    {
        memmove(stream->buffer, stream->buffer + eaten, eaten);
        stream->buffer_len -= eaten;
    }
}
