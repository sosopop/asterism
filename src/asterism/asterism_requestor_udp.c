#include "asterism_requestor_udp.h"
#include "asterism_connector_tcp.h"
#include "asterism_log.h"


struct requestor_getaddrinfo_s {
    struct uv_getaddrinfo_s addrinfo;
    uv_buf_t pendding_buffer;
    char domain[MAX_HOST_LEN];
};

static void requestor_close_cb(
    uv_handle_t* handle)
{
    struct asterism_udp_requestor_s* obj = __CONTAINER_PTR(struct asterism_udp_requestor_s, socket, handle);
    if (obj) {
        if (obj->connector) {
            struct asterism_udp_session_s sefilter;
            sefilter.source_addr = obj->source_addr;
            struct asterism_udp_session_s* session = RB_FIND(asterism_udp_session_tree_s, &obj->connector->udp_sessions, &sefilter);
            if (session)
            {
                session->datagram = 0;
            }
        }

        struct requestor_getaddrinfo_s* addr_req = (struct requestor_getaddrinfo_s*)obj->addr_req;
        if (addr_req)
        {
            addr_req->addrinfo.data = 0;
            uv_cancel((uv_req_t*)addr_req);
            obj->addr_req = 0;
        }

        struct asterism_udp_addr_cache_s* h = 0;
        struct asterism_udp_addr_cache_s* _h = 0;

        RB_FOREACH_SAFE(h, asterism_udp_addr_cache_tree_s, &obj->udp_addr_cache, _h)
        {
            RB_REMOVE(asterism_udp_addr_cache_tree_s, &obj->udp_addr_cache, h);
            AS_FREE(h);
        }
        RB_INIT(&obj->udp_addr_cache);

		AS_FREE(obj);
    }
}

static void udp_response_cb(
    uv_write_t* req,
    int status)
{
    struct asterism_write_req_s* write_req = (struct asterism_write_req_s*)req;
    struct asterism_udp_requestor_s* requestor = (struct asterism_udp_requestor_s*)req->data;
    int ret = -1;
    if (status != 0)
	{
		asterism_log(ASTERISM_LOG_DEBUG, "%s", uv_strerror(status));
		goto cleanup;
	}
    ret = asterism_datagram_read((struct asterism_datagram_s*)requestor);
    if (ret != 0)
        goto cleanup;

cleanup:
    free(write_req->write_buffer.base);
    free(write_req);
    if (ret != 0)
	{
		asterism_datagram_close((uv_handle_t*)&requestor->socket);
	}
}

static void requestor_read_cb(uv_udp_t* handle,
    ssize_t nread,
    const uv_buf_t* buf,
    const struct sockaddr* addr,
    unsigned flags)
{
    int ret = -1;
    struct asterism_udp_requestor_s* requestor = __CONTAINER_PTR(struct asterism_udp_requestor_s, socket, handle);
    struct asterism_tcp_connector_s* connector = requestor->connector;
    const struct sockaddr_in* addr_in = (const struct sockaddr_in*)addr;
    struct asterism_trans_proto_s* trans_buffer = 0;
    struct asterism_write_req_s* write_req = 0;
    // asterism_trans_proto_s size, source ip(4), source port(2), socks5 udp associate remote head(10), recv data
    ssize_t packet_len = sizeof(struct asterism_trans_proto_s) + 4 + 2 + 10 + nread;
    if (packet_len > ASTERISM_UDP_BLOCK_SIZE)
	{
		goto cleanup;
	}

    if (nread <= 0)
        goto cleanup;
    if (addr_in->sin_family != AF_INET)
        goto cleanup;

    trans_buffer = (struct asterism_trans_proto_s*)AS_MALLOC(packet_len);
    trans_buffer->version = ASTERISM_TRANS_PROTO_VERSION;
    trans_buffer->cmd = ASTERISM_TRANS_PROTO_DATAGRAM_RESPONSE;
    trans_buffer->len = ntohs((uint16_t)packet_len);

    //source ip, source port
    uint32_t source_ip = requestor->source_addr.sin_addr.s_addr;
    uint16_t source_port = requestor->source_addr.sin_port;
    memcpy(trans_buffer + 1, &source_ip, sizeof(source_ip));
    memcpy((char*)(trans_buffer + 1) + 4, &source_port, sizeof(source_port));

    uint32_t remote_ip = addr_in->sin_addr.s_addr;
    uint16_t remote_port = addr_in->sin_port;

    //Ð´Èësocks5 udp associate remote head
    //+---- + ------ + ------ + ---------- + ---------- + ---------- +
    //| RSV |  FRAG  |  ATYP  |  DST.ADDR  |  DST.PORT  |    DATA    |
    //+---- + ------ + ------ + ---------- + ---------- + ---------- +
    //|  2  |    1   |    1   |  Variable  |      2     |  Variable  |
    //+---- + ------ + ------ + ---------- + ---------- + ---------- +

    char* socks5_udp_head = (char*)(trans_buffer + 1) + 4 + 2;

    //RSV
    socks5_udp_head[0] = 0;
    socks5_udp_head[1] = 0;

    //FRAG
    socks5_udp_head[2] = 0;

    //ATYP
    socks5_udp_head[3] = 0x01; // IPv4

    //DST.ADDR
    memcpy(socks5_udp_head + 4, &remote_ip, sizeof(remote_ip));

    //DST.PORT  
    memcpy(socks5_udp_head + 8, &remote_port, sizeof(remote_port));

    //DATA
    memcpy(socks5_udp_head + 10, buf->base, nread);

    //trans to connector
    write_req = AS_ZMALLOC(struct asterism_write_req_s);
    write_req->write_buffer.base = (char*)trans_buffer;
    write_req->write_buffer.len = (uint16_t)packet_len;
    write_req->write_req.data = requestor;
    ret = asterism_stream_write(&write_req->write_req, (struct asterism_stream_s*)connector, &write_req->write_buffer, udp_response_cb);
    if (ret != 0)
    {
        AS_FREE(write_req->write_buffer.base);
        AS_FREE(write_req);
        goto cleanup;
    }

    ret = asterism_datagram_stop_read((struct asterism_datagram_s*)requestor);
    if (ret != 0)
		goto cleanup;

    ret = 0;
cleanup:
    ;
}

static void requestor_write_cb(
	uv_udp_send_t* req,
	int status)
{
    struct asterism_write_req_s* write_req = (struct asterism_write_req_s*)req;
	struct asterism_udp_requestor_s* requestor = (struct asterism_udp_requestor_s*)req->data;
	if (status != 0)
	{
		asterism_log(ASTERISM_LOG_DEBUG, "%s", uv_strerror(status));
	}
    AS_FREE(write_req->write_buffer.base);
	AS_FREE(write_req);
}

static int requestor_write(
    struct asterism_udp_requestor_s* requestor,
    struct sockaddr_in remote_addr,
    uv_buf_t buf)
{
	int ret = 0;
    struct asterism_write_req_s* req = AS_ZMALLOC(struct asterism_write_req_s);
	req->write_req.data = requestor;
    req->write_buffer = buf;
    req->write_buffer.base = __DUP_MEM(buf.base, buf.len);
	ret = uv_udp_send((uv_udp_send_t*)req, &requestor->socket, &buf, 1, (const struct sockaddr*)&remote_addr, requestor_write_cb);
	if (ret != 0)
	{
        AS_SFREE(req->write_buffer.base);
        AS_FREE(req);
	}
	return ret;
}

static void requestor_getaddrinfo(
    uv_getaddrinfo_t* req,
    int status,
    struct addrinfo* res)
{
    int ret = ASTERISM_E_OK;
    struct asterism_udp_requestor_s* requestor = (struct asterism_udp_requestor_s*)req->data;
    struct requestor_getaddrinfo_s* addr_req = (struct requestor_getaddrinfo_s*)req;

    char addr[INET_ADDRSTRLEN] = { '\0' };
    if (!requestor)
    {
        goto cleanup;
    }
    requestor->addr_req = 0;
    if (status != 0)
    {
        ret = status;
        goto cleanup;
    }
    //only support ipv4
    if(res->ai_family != AF_INET)
	{
		ret = -1;
		goto cleanup;
	}
    ret = uv_ip4_name((struct sockaddr_in*)res->ai_addr, addr, 16);
    if (ret != 0)
    {
        goto cleanup;
    }

    struct asterism_udp_addr_cache_s* cache = AS_ZMALLOC(struct asterism_udp_addr_cache_s);
    strcpy(cache->domain, addr_req->domain);
    strcpy(cache->ip, addr);
    RB_INSERT(asterism_udp_addr_cache_tree_s, &requestor->udp_addr_cache, cache);

    if(addr_req->pendding_buffer.base)
	{
        struct sockaddr_in remtoe_addr = *(struct sockaddr_in*)res->ai_addr;
		ret = requestor_write(requestor, remtoe_addr, addr_req->pendding_buffer);
		if (ret != 0)
		{
			goto cleanup;
		}
	}
cleanup:
    if (addr_req->pendding_buffer.base) {
		AS_FREE(addr_req->pendding_buffer.base);
        addr_req->pendding_buffer.base = 0;
    }
    if (res)
        uv_freeaddrinfo(res);
    if (req)
        AS_FREE(req);
}

static int requestor_send(
    struct asterism_udp_requestor_s* requestor,
    unsigned char atyp,
    const char* remote_host, unsigned short remote_port,
    struct sockaddr_in source_addr,
    const unsigned char* data,
    int data_len)
{
    int ret = -1;

    // ipv4
    if (atyp == 1)
    {
        struct sockaddr_in remote_addr;
        ret = uv_ip4_addr(remote_host, (int)remote_port, (struct sockaddr_in*)&remote_addr);
        if (ret != 0)
        {
            goto cleanup;
        }
        ret = requestor_write(requestor, remote_addr, uv_buf_init((char*)data, data_len));
        if (ret != 0)
        {
            goto cleanup;
        }
    }
    else if (atyp == 3)
    {
        struct asterism_udp_addr_cache_s filter;
        strcpy(filter.domain, remote_host);
        struct asterism_udp_addr_cache_s* cache = RB_FIND(asterism_udp_addr_cache_tree_s, &requestor->udp_addr_cache, &filter);
        if (cache)
        {
            struct sockaddr_in remote_addr;
            ret = uv_ip4_addr(cache->ip, (int)remote_port, (struct sockaddr_in*)&remote_addr);
            if (ret != 0)
            {
                goto cleanup;
            }
            ret = requestor_write(requestor, remote_addr, uv_buf_init((char*)data, data_len));
            if (ret != 0)
            {
                goto cleanup;
            }
        }
        else
        {
            struct requestor_getaddrinfo_s* addr_req = (struct requestor_getaddrinfo_s*)AS_MALLOC(sizeof(struct requestor_getaddrinfo_s));
            addr_req->addrinfo.data = requestor;
            addr_req->pendding_buffer = uv_buf_init((char*)__DUP_MEM(data, data_len), data_len);
            strcpy(addr_req->domain, remote_host);
            requestor->addr_req = (struct uv_getaddrinfo_s*)addr_req;

            char port_str[10] = { 0 };
            asterism_itoa(port_str, sizeof(port_str), remote_port, 10, 0, 0);
            ret = uv_getaddrinfo(requestor->as->loop, (uv_getaddrinfo_t*)requestor->addr_req, requestor_getaddrinfo, remote_host, port_str, 0);
            if (ret != 0)
            {
                asterism_log(ASTERISM_LOG_DEBUG, "%s", uv_strerror(ret));
                goto cleanup;
            }
        }
    }
    else
    {
        goto cleanup;
    }

    ret = 0;
cleanup:
    return ret;
}

static int requestor_init(
    struct asterism_tcp_connector_s* connector,
    unsigned char atyp,
    const char* remote_host, unsigned short remote_port,
    struct sockaddr_in source_addr,
    const unsigned char* data,
    int data_len)
{
    int ret = -1;
    struct asterism_udp_requestor_s* requestor = AS_ZMALLOC(struct asterism_udp_requestor_s);
    ret = asterism_datagram_init(connector->as, 0, 0, requestor_read_cb, requestor_close_cb, (struct asterism_datagram_s*)requestor);
    if (ret != 0)
        goto cleanup;

    requestor->connector = connector;
    requestor->source_addr = source_addr;

    ret = requestor_send(requestor, atyp, remote_host, remote_port, source_addr, data, data_len);
    if (ret != 0)
        goto cleanup;

    ret = asterism_datagram_read((struct asterism_datagram_s*)requestor);
    if (ret != 0)
		goto cleanup;

    ret = 0;
cleanup:
    if (ret != 0)
	{
		if (requestor)
		{
            asterism_datagram_close((uv_handle_t*)&requestor->socket);
		}
    }
    else {
        struct asterism_udp_session_s* session = AS_ZMALLOC(struct asterism_udp_session_s);;
        session->datagram = (struct asterism_datagram_s*)requestor;
        session->source_addr = source_addr;
		RB_INSERT(asterism_udp_session_tree_s, &connector->udp_sessions, session);
    }
    return ret;
}

int asterism_udp_addr_cache_compare(struct asterism_udp_addr_cache_s* a, struct asterism_udp_addr_cache_s* b)
{
    return strcmp(a->domain, b->domain);
}

RB_GENERATE(asterism_udp_addr_cache_tree_s, asterism_udp_addr_cache_s, tree_entry, asterism_udp_addr_cache_compare);

int asterism_requestor_udp_trans(
    struct asterism_tcp_connector_s* connector,
    unsigned char atyp,
    const char* remote_host, unsigned short remote_port,
    struct sockaddr_in source_addr,
    const unsigned char* data,
    int data_len)
{
    int ret = 0;

    struct asterism_udp_session_s sefilter;
    sefilter.source_addr = source_addr;
    struct asterism_udp_session_s* session = RB_FIND(asterism_udp_session_tree_s, &connector->udp_sessions, &sefilter);
    if (session == 0) {
        ret = requestor_init(connector, atyp, remote_host, remote_port, source_addr, data, data_len);
        if (ret != 0)
			goto cleanup;
    }
	else
	{
        struct asterism_udp_requestor_s* requestor = (struct asterism_udp_requestor_s*)session->datagram;
        if (requestor->addr_req)
		{
			goto cleanup;
		}

        ret = requestor_send(requestor, atyp, remote_host, remote_port, source_addr, data, data_len);
        if (ret != 0)
        {
            goto cleanup;
        }
	}
cleanup:
    return ret;
}
