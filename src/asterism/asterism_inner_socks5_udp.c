#include "asterism_inner_socks5_udp.h"
#include "asterism_log.h"
#include "asterism_stream.h"

static void inner_close_cb(
    uv_handle_t* handle)
{
    struct asterism_socks5_udp_inner_s* obj = __CONTAINER_PTR(struct asterism_socks5_udp_inner_s, socket, handle);
    if (obj->session) 
    {
        obj->session->inner_datagram = 0;
        obj->session = 0;
    }
    AS_FREE(obj);
}

static void outer_write_cb(
	uv_write_t* req,
	int status)
{
	struct asterism_write_req_s* write_req = (struct asterism_write_req_s*)req;
    struct asterism_socks5_udp_inner_s* datagram = (struct asterism_socks5_udp_inner_s*)write_req->write_req.data;
	if (status != 0)
	{
		asterism_log(ASTERISM_LOG_DEBUG, "%s", uv_strerror(status));
	}
	AS_FREE(write_req->write_buffer.base);
    AS_FREE(write_req);

    asterism_datagram_read((struct asterism_datagram_s*)datagram);
}

static void inner_read_cb(uv_udp_t* handle,
    ssize_t nread,
    const uv_buf_t* buf,
    const struct sockaddr* addr,
    unsigned flags)
{
    struct asterism_socks5_udp_inner_s* datagram = __CONTAINER_PTR(struct asterism_socks5_udp_inner_s, socket, handle);
    struct asterism_stream_s* stream = datagram->session->outer;
    struct asterism_write_req_s* req = 0;
    if (addr->sa_family != AF_INET || nread < 10)
	{
        asterism_log(ASTERISM_LOG_DEBUG, "udp recv invalid data");
		return;
	}

    unsigned int datagram_size = sizeof(struct asterism_trans_proto_s) +
        4 + 2 + (int)nread;
    if (datagram_size > ASTERISM_UDP_BLOCK_SIZE)
    {
        asterism_log(ASTERISM_LOG_DEBUG, "udp exceed max size");
        return;
    }

    // asterism_log(ASTERISM_LOG_DEBUG, "udp recv %.*s", nread, buf->base);

    // trans to remote
    struct asterism_trans_proto_s* connect_data =
        (struct asterism_trans_proto_s*)AS_MALLOC(datagram_size);

    connect_data->version = ASTERISM_TRANS_PROTO_VERSION;
    connect_data->cmd = ASTERISM_TRANS_PROTO_DATAGRAM_REQUEST;

    /*
    payload
    source address 4bytes
    source port 2bytes
    socks5 udp packet
    */
    connect_data->len = htons((unsigned int)datagram_size);

    const struct sockaddr_in* addr_in = (const struct sockaddr_in*)addr;
    uint32_t address = addr_in->sin_addr.s_addr;
    uint16_t port = addr_in->sin_port;

    memcpy(connect_data + 1, &address, sizeof(address));
    memcpy((char*)(connect_data + 1) + 4, &port, sizeof(port));
    memcpy((char*)(connect_data + 1) + 6, buf->base, nread);

    req = AS_ZMALLOC(struct asterism_write_req_s);

    req->write_buffer.base = (char*)connect_data;
    req->write_buffer.len = datagram_size;
    req->write_req.data = datagram;

    int write_ret = asterism_stream_write((uv_write_t*)req, (struct asterism_stream_s*)datagram->session->outer, &req->write_buffer, outer_write_cb);
    if (write_ret != 0)
    {
        AS_FREE(req->write_buffer.base);
        AS_FREE(req);
        return;
    }
    asterism_datagram_stop_read((struct asterism_datagram_s*)datagram);
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
    ret = asterism_datagram_init(as, 0, 0, inner_read_cb, inner_close_cb, (struct asterism_datagram_s*)inner);

    inner->session = session;

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

    ret = asterism_datagram_read((struct asterism_datagram_s*)inner);
    if (ret != 0)
    {
        asterism_log(ASTERISM_LOG_DEBUG, "%s", uv_strerror(ret));
        ret = ASTERISM_E_SOCKET_LISTEN_ERROR;
        goto cleanup;
    }

    session->inner_datagram = (struct asterism_datagram_s*)inner;
cleanup:
    if (addr)
    {
        AS_FREE(addr);
    }
    if (ret)
    {
        asterism_datagram_close((uv_handle_t*)&inner->socket);
    }
    return ret;
}
