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
                RB_REMOVE(asterism_udp_session_tree_s, &obj->connector->udp_sessions, session);
                AS_FREE(session);
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

        // Do not free here: the datagram layer owns the struct and frees it
        // once no in-flight write still references it (see asterism_datagram.c).
    }
}

static void udp_response_cb(
    uv_write_t* req,
    int status)
{
    struct asterism_write_req_s* write_req = (struct asterism_write_req_s*)req;
    struct asterism_udp_requestor_s* requestor = (struct asterism_udp_requestor_s*)req->data;
    int ret = 0;

    AS_FREE(write_req->write_buffer.base);
    AS_FREE(write_req);

    // This write held a reference to the requestor datagram. If it was closed
    // (e.g. by the UDP idle reaper) while the write was in flight, only drop
    // the reference (which may free it) and never touch the closed socket.
    if (asterism_datagram_is_closing((struct asterism_datagram_s*)requestor))
    {
        asterism_datagram_write_unref((struct asterism_datagram_s*)requestor);
        return;
    }

    if (status != 0)
    {
        asterism_log(ASTERISM_LOG_DEBUG, "%s", uv_strerror(status));
        ret = -1;
    }
    else
    {
        ret = asterism_datagram_read((struct asterism_datagram_s*)requestor);
    }

    if (ret != 0)
    {
        asterism_datagram_close((uv_handle_t*)&requestor->socket);
    }
    asterism_datagram_write_unref((struct asterism_datagram_s*)requestor);
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
    struct asterism_trans_proto_s* trans_buffer = 0;
    struct asterism_write_req_s* write_req = 0;
    if (nread <= 0 || !addr)
        goto cleanup;

    int is6 = (addr->sa_family == AF_INET6);
    if (addr->sa_family != AF_INET && !is6)
        goto cleanup;

    // SOCKS5 UDP header: RSV(2)+FRAG(1)+ATYP(1)+ADDR+PORT(2) -> 10 (v4) / 22 (v6)
    size_t s5head_len = is6 ? (4 + 16 + 2) : (4 + 4 + 2);

    // trans payload: src addr(4) + src port(2) + socks5 udp head + data
    ssize_t packet_len = sizeof(struct asterism_trans_proto_s) + 4 + 2 + (ssize_t)s5head_len + nread;
    if (packet_len > ASTERISM_UDP_BLOCK_SIZE)
        goto cleanup;

    trans_buffer = (struct asterism_trans_proto_s*)AS_MALLOC(packet_len);
    if (!trans_buffer)
        goto cleanup;
    trans_buffer->version = ASTERISM_TRANS_PROTO_VERSION;
    trans_buffer->cmd = ASTERISM_TRANS_PROTO_DATAGRAM_RESPONSE;
    trans_buffer->len = htons((uint16_t)packet_len);

    // source ip, source port (the SOCKS5 client; always IPv4)
    uint32_t source_ip = requestor->source_addr.sin_addr.s_addr;
    uint16_t source_port = requestor->source_addr.sin_port;
    memcpy(trans_buffer + 1, &source_ip, sizeof(source_ip));
    memcpy((char*)(trans_buffer + 1) + 4, &source_port, sizeof(source_port));

    // socks5 udp associate remote head
    //+---- + ------ + ------ + ---------- + ---------- + ---------- +
    //| RSV |  FRAG  |  ATYP  |  DST.ADDR  |  DST.PORT  |    DATA    |
    //+---- + ------ + ------ + ---------- + ---------- + ---------- +
    char* socks5_udp_head = (char*)(trans_buffer + 1) + 4 + 2;
    socks5_udp_head[0] = 0; // RSV
    socks5_udp_head[1] = 0;
    socks5_udp_head[2] = 0; // FRAG
    if (is6)
    {
        const struct sockaddr_in6* a6 = (const struct sockaddr_in6*)addr;
        socks5_udp_head[3] = 0x04; // ATYP IPv6
        memcpy(socks5_udp_head + 4, &a6->sin6_addr, 16);
        memcpy(socks5_udp_head + 20, &a6->sin6_port, 2);
    }
    else
    {
        const struct sockaddr_in* a4 = (const struct sockaddr_in*)addr;
        socks5_udp_head[3] = 0x01; // ATYP IPv4
        memcpy(socks5_udp_head + 4, &a4->sin_addr.s_addr, 4);
        memcpy(socks5_udp_head + 8, &a4->sin_port, 2);
    }
    memcpy(socks5_udp_head + s5head_len, buf->base, nread); // DATA

    // trans to connector
    write_req = AS_ZMALLOC(struct asterism_write_req_s);
    if (!write_req)
    {
        AS_FREE(trans_buffer);
        goto cleanup;
    }
    write_req->write_buffer.base = (char*)trans_buffer;
    write_req->write_buffer.len = (uint16_t)packet_len;
    write_req->write_req.data = requestor;
    ret = asterism_stream_write(&write_req->write_req, (struct asterism_stream_s*)connector, &write_req->write_buffer, udp_response_cb);
    if (ret != 0)
    {
        AS_SFREE(write_req->write_buffer.base);
        AS_FREE(write_req);
        goto cleanup;
    }

    // udp_response_cb will dereference this requestor after the TCP write
    // completes; hold a reference so it survives an intervening close.
    asterism_datagram_write_ref((struct asterism_datagram_s*)requestor);

    ret = asterism_datagram_stop_read((struct asterism_datagram_s*)requestor);
    if (ret != 0)
        goto cleanup;

    ret = 0;
cleanup:
    ;
}

static int requestor_write(
    struct asterism_udp_requestor_s* requestor,
    const struct sockaddr* remote_addr,
    uv_buf_t buf)
{
    return asterism_datagram_write((struct asterism_datagram_s*)requestor, &buf, remote_addr);
}

static void requestor_getaddrinfo(
    uv_getaddrinfo_t* req,
    int status,
    struct addrinfo* res)
{
    int ret = ASTERISM_E_OK;
    struct asterism_udp_requestor_s* requestor = (struct asterism_udp_requestor_s*)req->data;
    struct requestor_getaddrinfo_s* addr_req = (struct requestor_getaddrinfo_s*)req;

    char addr[INET6_ADDRSTRLEN] = { '\0' };
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

    // Prefer the first IPv4 result; fall back to the first IPv6.
    struct addrinfo* resolved = res;
    while (resolved && resolved->ai_family != AF_INET)
        resolved = resolved->ai_next;
    if (!resolved)
    {
        resolved = res;
        while (resolved && resolved->ai_family != AF_INET6)
            resolved = resolved->ai_next;
    }
    if (!resolved)
    {
        ret = -1;
        goto cleanup;
    }

    int family = resolved->ai_family;
    if (family == AF_INET6)
        ret = uv_ip6_name((struct sockaddr_in6*)resolved->ai_addr, addr, sizeof(addr));
    else
        ret = uv_ip4_name((struct sockaddr_in*)resolved->ai_addr, addr, sizeof(addr));
    if (ret != 0)
    {
        goto cleanup;
    }

    struct asterism_udp_addr_cache_s* cache = AS_ZMALLOC(struct asterism_udp_addr_cache_s);
    if (!cache)
    {
        ret = ASTERISM_E_FAILED;
        goto cleanup;
    }
    strcpy(cache->domain, addr_req->domain);
    strcpy(cache->ip, addr);
    cache->family = family;
    RB_INSERT(asterism_udp_addr_cache_tree_s, &requestor->udp_addr_cache, cache);

    if (addr_req->pendding_buffer.base)
    {
        // ai_addr already carries the requested port from getaddrinfo.
        struct sockaddr_storage remote_addr;
        memcpy(&remote_addr, resolved->ai_addr, resolved->ai_addrlen);
        ret = requestor_write(requestor, (const struct sockaddr*)&remote_addr, addr_req->pendding_buffer);
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
    struct sockaddr_storage remote_addr;

    // ipv4 literal
    if (atyp == 1)
    {
        ret = uv_ip4_addr(remote_host, (int)remote_port, (struct sockaddr_in*)&remote_addr);
        if (ret != 0)
        {
            goto cleanup;
        }
        ret = requestor_write(requestor, (const struct sockaddr*)&remote_addr, uv_buf_init((char*)data, data_len));
        if (ret != 0)
        {
            goto cleanup;
        }
    }
    // ipv6 literal
    else if (atyp == 4)
    {
        ret = uv_ip6_addr(remote_host, (int)remote_port, (struct sockaddr_in6*)&remote_addr);
        if (ret != 0)
        {
            goto cleanup;
        }
        ret = requestor_write(requestor, (const struct sockaddr*)&remote_addr, uv_buf_init((char*)data, data_len));
        if (ret != 0)
        {
            goto cleanup;
        }
    }
    else if (atyp == 3)
    {
        if (!remote_host || strlen(remote_host) >= MAX_HOST_LEN)
            goto cleanup;

        struct asterism_udp_addr_cache_s filter;
        strcpy(filter.domain, remote_host);
        struct asterism_udp_addr_cache_s* cache = RB_FIND(asterism_udp_addr_cache_tree_s, &requestor->udp_addr_cache, &filter);
        if (cache)
        {
            if (cache->family == AF_INET6)
                ret = uv_ip6_addr(cache->ip, (int)remote_port, (struct sockaddr_in6*)&remote_addr);
            else
                ret = uv_ip4_addr(cache->ip, (int)remote_port, (struct sockaddr_in*)&remote_addr);
            if (ret != 0)
            {
                goto cleanup;
            }
            ret = requestor_write(requestor, (const struct sockaddr*)&remote_addr, uv_buf_init((char*)data, data_len));
            if (ret != 0)
            {
                goto cleanup;
            }
        }
        else
        {
            struct requestor_getaddrinfo_s* addr_req = (struct requestor_getaddrinfo_s*)AS_ZMALLOC(struct requestor_getaddrinfo_s);
            if (!addr_req)
                goto cleanup;
            addr_req->addrinfo.data = requestor;
            addr_req->pendding_buffer = uv_buf_init((char*)__DUP_MEM(data, data_len), data_len);
            if (data_len && !addr_req->pendding_buffer.base) {
                AS_FREE(addr_req);
                goto cleanup;
            }
            strcpy(addr_req->domain, remote_host);
            requestor->addr_req = (struct uv_getaddrinfo_s*)addr_req;

            char port_str[10] = { 0 };
            struct addrinfo hints;
            memset(&hints, 0, sizeof(hints));
            hints.ai_family = AF_UNSPEC;
            hints.ai_socktype = SOCK_DGRAM;
            hints.ai_protocol = IPPROTO_UDP;
            asterism_itoa(port_str, sizeof(port_str), remote_port, 10, 0, 0);
            ret = uv_getaddrinfo(
                requestor->as->loop,
                (uv_getaddrinfo_t*)requestor->addr_req,
                requestor_getaddrinfo,
                remote_host,
                port_str,
                &hints);
            if (ret != 0)
            {
                asterism_log(ASTERISM_LOG_DEBUG, "%s", uv_strerror(ret));
                requestor->addr_req = 0;
                AS_SFREE(addr_req->pendding_buffer.base);
                AS_FREE(addr_req);
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
    if (!requestor)
        return ASTERISM_E_FAILED;
    ret = asterism_datagram_init(connector->as, 0, requestor_read_cb, requestor_close_cb, (struct asterism_datagram_s*)requestor);
    if (ret != 0)
    {
        AS_FREE(requestor);
        return ret;
    }

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
        struct asterism_udp_session_s* session = AS_ZMALLOC(struct asterism_udp_session_s);
        if (!session)
        {
            asterism_datagram_close((uv_handle_t*)&requestor->socket);
            return ASTERISM_E_FAILED;
        }
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
        if (!requestor)
        {
            goto cleanup;
        }
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
