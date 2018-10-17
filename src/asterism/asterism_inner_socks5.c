#include "asterism_inner_socks5.h"
#include "asterism_core.h"
#include "asterism_log.h"
#include "asterism_utils.h"

static void inner_close_cb(
    uv_handle_t *handle)
{
    struct asterism_socks5_inner_s *obj = __CONTAINER_PTR(struct asterism_socks5_inner_s, socket, handle);
    AS_FREE(obj);
}

static void inner_close(
    uv_handle_t *handle)
{
    as_uv_close(handle, inner_close_cb);
}

static void incoming_delete(struct asterism_socks5_incoming_s *obj)
{
    AS_FREE(obj);
}

static void incoming_close_cb(
    uv_handle_t *handle)
{
    int ret = 0;
    struct asterism_socks5_incoming_s *obj = __CONTAINER_PTR(struct asterism_socks5_incoming_s, socket, handle);
    if (!obj->link)
    {
        struct asterism_handshake_s fh = {obj->handshake_id};
        struct asterism_handshake_s *handshake = RB_FIND(asterism_handshake_tree_s, &obj->as->handshake_set, &fh);
        if (handshake)
        {
            RB_REMOVE(asterism_handshake_tree_s, &obj->as->handshake_set, handshake);
            AS_FREE(handshake);
        }
    }
    incoming_delete(obj);
    asterism_log(ASTERISM_LOG_DEBUG, "socks5 is closing");
}

static void conn_write_done(uv_write_t *req, int status)
{
    struct asterism_stream_s *stream = (struct asterism_stream_s *)req->data;
    if (status || asterism_stream_read(stream))
    {
        asterism_stream_close((uv_handle_t *)&stream->socket);
    }
}

static int conn_write(struct asterism_stream_s *stream, const void *data, unsigned int len)
{
    uv_buf_t buf;
    buf.base = (char *)data;
    buf.len = len;
    stream->write_req.data = stream;
    return uv_write(&stream->write_req,
                    (uv_stream_t *)&stream->socket,
                    &buf,
                    1,
                    conn_write_done);
}

static int conn_ack_cb(
    struct asterism_stream_s *stream, int success)
{
    int ret = -1;
    uv_write_t *req = 0;
    struct asterism_http_incoming_s *incoming = (struct asterism_http_incoming_s *)stream;
    if (!success)
    {
        ret = conn_write((struct asterism_stream_s *)incoming, "\5\1\0\1\0\0\0\0\0\0", 10) ||
            asterism_stream_end((struct asterism_stream_s *)incoming);
        goto cleanup;
    }
    else
    {
        ret = conn_write((struct asterism_stream_s *)incoming, "\5\0\0\1\0\0\0\0\0\0", 10);
        goto cleanup;
    }
cleanup:
    return ret;
}

static void handshake_write_cb(
    uv_write_t *req,
    int status)
{
    struct asterism_write_req_s *write_req = (struct asterism_write_req_s *)req;
    free(write_req->write_buffer.base);
    free(write_req);
}

static int incoming_parse_connect(
    struct asterism_socks5_incoming_s *incoming,
    ssize_t nread,
    const uv_buf_t *buf)
{
    size_t buffer_len = nread;
    char *buffer = buf->base;
    unsigned int methods;
    int err;
    err = s5_parse(&incoming->parser, (unsigned char **)&buffer, &buffer_len);
    if (err == s5_ok)
    {
        return asterism_stream_read((struct asterism_stream_s *)incoming);
    }
    if (buffer_len != 0)
    {
        return -1;
    }

    if (incoming->status == SOCKS5_STATUS_HANDSHAKE)
    {
        if (err != s5_auth_select)
        {
            return -1;
        }
        methods = s5_auth_methods(&incoming->parser);
        if ((methods & S5_AUTH_PASSWD))
        {
            s5_select_auth(&incoming->parser, S5_AUTH_PASSWD);
            incoming->status = SOCKS5_STATUS_HANDSHAKE_AUTH;
            return conn_write((struct asterism_stream_s *)incoming, "\5\2", 2); /* No auth required. */
        }
        conn_write((struct asterism_stream_s *)incoming, "\5\377", 2); /* No acceptable auth. */
        asterism_stream_end((struct asterism_stream_s *)incoming);
        return 0;
    }
    else if (incoming->status == SOCKS5_STATUS_HANDSHAKE_AUTH)
    {
        if (err != s5_auth_verify)
        {
            return -1;
        }
        struct asterism_session_s sefilter;
        sefilter.username = (char*)incoming->parser.username;
        struct asterism_session_s *session = RB_FIND(asterism_session_tree_s, &incoming->as->sessions, &sefilter);
        if (!session || strcmp(session->password, (char*)incoming->parser.password))
        {
            conn_write((struct asterism_stream_s *)incoming, "\1\1", 2); /* failed. */
            asterism_stream_end((struct asterism_stream_s *)incoming);
            return 0;
        }
        incoming->status = SOCKS5_STATUS_CONNECT;
        conn_write((struct asterism_stream_s *)incoming, "\1\0", 2);
        return 0;
    }
    else if (incoming->status == SOCKS5_STATUS_CONNECT)
    {
        if (err != s5_exec_cmd)
        {
            return -1;
        }
        struct asterism_session_s sefilter;
        sefilter.username = (char*)incoming->parser.username;
        struct asterism_session_s *session = RB_FIND(asterism_session_tree_s, &incoming->as->sessions, &sefilter);
        if (!session || strcmp(session->password, (char*)incoming->parser.password))
        {
            return (conn_write((struct asterism_stream_s *)incoming, "\5\1\0\1\0\0\0\0\0\0", 10) ||
                asterism_stream_end((struct asterism_stream_s *)incoming));
        }
        if (incoming->parser.cmd != s5_cmd_tcp_connect)
        {
            return conn_write((struct asterism_stream_s *)incoming, "\5\1\0\1\0\0\0\0\0\0", 10) ||
                   asterism_stream_end((struct asterism_stream_s *)incoming);
        }

        char addr[MAX_HOST_LEN] = {0};
        if (incoming->parser.atyp == s5_atyp_host)
        {
            strncpy(addr, (char*)incoming->parser.daddr, MAX_HOST_LEN - 10);
        }
        else if (incoming->parser.atyp == s5_atyp_ipv4)
        {
            uv_inet_ntop(AF_INET, (char*)incoming->parser.daddr, addr, MAX_HOST_LEN);
        }
        else if (incoming->parser.atyp == s5_atyp_ipv6)
        {
            uv_inet_ntop(AF_INET6, (char*)incoming->parser.daddr, addr, MAX_HOST_LEN);
        }
        else
        {
            return -1;
        }
        char port[10] = {0};
        sprintf(port, ":%d", incoming->parser.dport);
        strcat(addr, port);

        struct asterism_handshake_s *handshake = AS_ZMALLOC(struct asterism_handshake_s);
        handshake->inner = (struct asterism_stream_s *)incoming;
        handshake->conn_ack_cb = conn_ack_cb;
        handshake->id = asterism_tunnel_new_handshake_id();
        incoming->handshake_id = handshake->id;

        struct asterism_write_req_s *req = AS_ZMALLOC(struct asterism_write_req_s);

        unsigned short host_len = (unsigned short)strlen(addr);

        struct asterism_trans_proto_s *connect_data =
            (struct asterism_trans_proto_s *)AS_MALLOC(sizeof(struct asterism_trans_proto_s) +
                host_len + 2 + 4);

        connect_data->version = ASTERISM_TRANS_PROTO_VERSION;
        connect_data->cmd = ASTERISM_TRANS_PROTO_CONNECT;

        char *off = (char *)connect_data + sizeof(struct asterism_trans_proto_s);
        *(uint32_t *)off = htonl(handshake->id);
        off += 4;

        *(uint16_t *)off = htons((uint16_t)host_len);
        off += 2;
        memcpy(off, addr, host_len);
        off += host_len;

        asterism_log(ASTERISM_LOG_DEBUG, "connect to %s", addr);

        uint16_t packet_len = (uint16_t)(off - (char *)connect_data);
        connect_data->len = htons(packet_len);

        req->write_buffer.base = (char *)connect_data;
        req->write_buffer.len = packet_len;

        int write_ret = uv_write((uv_write_t *)req, (uv_stream_t *)&session->outer->socket, &req->write_buffer, 1, handshake_write_cb);
        if (write_ret != 0)
        {
            free(req->write_buffer.base);
            free(req);
            free(handshake);
            return -1;
        }

        asterism_log(ASTERISM_LOG_DEBUG, "send handshake %d", handshake->id);
        RB_INSERT(asterism_handshake_tree_s, &incoming->as->handshake_set, handshake);
        incoming->status = SOCKS5_STATUS_TRANS;
    }
    return 0;
}

static void incoming_read_cb(
    uv_stream_t *stream,
    ssize_t nread,
    const uv_buf_t *buf)
{

    struct asterism_socks5_incoming_s *incoming = __CONTAINER_PTR(struct asterism_socks5_incoming_s, socket, stream);
    uv_read_stop(stream);
    int ret = incoming_parse_connect(incoming, nread, buf);
    if (ret != 0)
    {
        asterism_stream_close((uv_handle_t *)&incoming->socket);
    }
    else
    {
        asterism_stream_eaten((struct asterism_stream_s *)incoming, incoming->buffer_len);
    }
}

static void inner_accept_cb(
    uv_stream_t *stream,
    int status)
{
    int ret = ASTERISM_E_OK;
    asterism_log(ASTERISM_LOG_DEBUG, "socks5 connection is comming");

    struct asterism_socks5_inner_s *inner = __CONTAINER_PTR(struct asterism_socks5_inner_s, socket, stream);
    struct asterism_socks5_incoming_s *incoming = 0;
    if (status != 0)
    {
        goto cleanup;
    }
    incoming = AS_ZMALLOC(struct asterism_socks5_incoming_s);
    ret = asterism_stream_accept(inner->as, stream, 1, 0,
                                 incoming_read_cb, incoming_close_cb, (struct asterism_stream_s *)incoming);
    if (ret != 0)
    {
        ret = ASTERISM_E_FAILED;
        goto cleanup;
    }
    s5_init(&incoming->parser);

    ret = asterism_stream_read((struct asterism_stream_s *)incoming);
    if (ret != 0)
    {
        ret = ASTERISM_E_FAILED;
        goto cleanup;
    }
cleanup:
    if (ret != 0)
    {
        asterism_stream_close((uv_handle_t *)&incoming->socket);
    }
}

int asterism_inner_socks5_init(
    struct asterism_s *as,
    const char *ip, unsigned int *port)
{
    int ret = ASTERISM_E_OK;
    void *addr = 0;
    int name_len = 0;
    struct asterism_socks5_inner_s *inner = AS_ZMALLOC(struct asterism_socks5_inner_s);
    inner->as = as;
    ASTERISM_HANDLE_INIT(inner, socket, inner_close);
    ret = uv_tcp_init(as->loop, &inner->socket);
    if (ret != 0)
    {
        asterism_log(ASTERISM_LOG_DEBUG, "%s", uv_strerror(ret));
        ret = ASTERISM_E_SOCKET_LISTEN_ERROR;
        goto cleanup;
    }
    addr = AS_ZMALLOC(struct sockaddr_in);
    name_len = sizeof(struct sockaddr_in);
    ret = uv_ip4_addr(ip, (int)*port, (struct sockaddr_in *)addr);
    if (ret != 0)
    {
        asterism_log(ASTERISM_LOG_DEBUG, "%s", uv_strerror(ret));
        ret = ASTERISM_E_SOCKET_LISTEN_ERROR;
        goto cleanup;
    }
    ret = uv_tcp_bind(&inner->socket, (const struct sockaddr *)addr, 0);
    if (ret != 0)
    {
        asterism_log(ASTERISM_LOG_DEBUG, "%s", uv_strerror(ret));
        ret = ASTERISM_E_SOCKET_LISTEN_ERROR;
        goto cleanup;
    }
    ret = uv_tcp_getsockname(&inner->socket, (struct sockaddr *)addr, &name_len);
    if (ret != 0)
    {
        asterism_log(ASTERISM_LOG_DEBUG, "%s", uv_strerror(ret));
        ret = ASTERISM_E_SOCKET_LISTEN_ERROR;
        goto cleanup;
    }

    *port = ntohs(((struct sockaddr_in *)addr)->sin_port);

    ret = uv_listen((uv_stream_t *)&inner->socket, ASTERISM_NET_BACKLOG, inner_accept_cb);
    if (ret != 0)
    {
        asterism_log(ASTERISM_LOG_DEBUG, "%s", uv_strerror(ret));
        ret = ASTERISM_E_SOCKET_LISTEN_ERROR;
        goto cleanup;
    }
cleanup:
    if (addr)
    {
        AS_FREE(addr);
    }
    if (ret)
    {
        asterism_stream_close((uv_handle_t *)&inner->socket);
    }
    return ret;
}