#include "asterism_datagram.h"

int asterism_datagram_init(
    struct asterism_s* as,
    unsigned int crypt, 
    uv_alloc_cb alloc_cb, 
    uv_read_cb read_cb, 
    uv_close_cb close_cb, 
    struct asterism_datagram_s* datagram)
{
    int ret = 0;
    return 0;
}

int asterism_datagram_read(
    struct asterism_datagram_s* datagram)
{
    return 0;
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
    struct asterism_datagram_s* datagram)
{
    as_uv_close((uv_handle_t*)&datagram->socket, inner_close_cb);
}

int asterism_datagram_write(
    uv_write_t* req, 
    struct asterism_datagram_s* datagram, 
    const uv_buf_t* bufs, 
    uv_write_cb cb)
{
    return 0;
}
