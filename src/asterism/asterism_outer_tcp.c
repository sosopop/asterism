#include "asterism_outer_tcp.h"
#include "asterism_core.h"
#include "asterism_utils.h"
#include "asterism_log.h"
#include "asterism_datagram.h"
#include "asterism_inner_socks5_udp.h"

static void outer_close_cb(
    uv_handle_t *handle)
{
    struct asterism_tcp_outer_s *outer = __CONTAINER_PTR(struct asterism_tcp_outer_s, socket, handle);
    AS_FREE(outer);
}

static void outer_close(
    uv_handle_t *handle)
{
    as_uv_close(handle, outer_close_cb);
}

static void incoming_close_cb(
    uv_handle_t *handle)
{
    int ret = 0;
    struct asterism_tcp_incoming_s *incoming = __CONTAINER_PTR(struct asterism_tcp_incoming_s, socket, handle);
    if (incoming->session)
    {
        asterism_log(ASTERISM_LOG_INFO, "user: %s leave", incoming->session->username);
        RB_REMOVE(asterism_session_tree_s, &incoming->as->sessions, incoming->session);

        //close socks5 comming udp handle
        struct asterism_socks5_udp_inner_s* inner_datagram = (struct asterism_socks5_udp_inner_s*)incoming->session->inner_datagram;
        if (inner_datagram) {
            inner_datagram->session = 0;
            asterism_datagram_close((uv_handle_t*)&inner_datagram->socket);
            incoming->session->inner_datagram = 0;
        }

        if (incoming->session->username)
        {
            AS_SFREE(incoming->session->username);
        }
        if (incoming->session->password)
        {
            AS_SFREE(incoming->session->password);
        }
        AS_SFREE(incoming->session);
    }
    AS_FREE(incoming);
}

static int parse_cmd_join(
    struct asterism_tcp_incoming_s *incoming,
    struct asterism_trans_proto_s *proto)
{
    int offset = sizeof(struct asterism_trans_proto_s);
    unsigned short username_len = 0;
    char *username = 0;
    unsigned short password_len = 0;
    char *password = 0;
    uint16_t proto_len = asterism_read_be16(&proto->len);
    if (proto_len < sizeof(struct asterism_trans_proto_s))
        return -1;

    if (offset + 2 > proto_len)
        return -1;
    username_len = asterism_read_be16((char *)proto + offset);
    offset += 2;

    if (offset + username_len > proto_len)
        return -1;
    username = (char *)((char *)proto + offset);
    offset += username_len;

    if (offset + 2 > proto_len)
        return -1;
    password_len = asterism_read_be16((char *)proto + offset);
    offset += 2;

    if (offset + password_len > proto_len)
        return -1;
    password = (char *)((char *)proto + offset);
    offset += password_len;
    if (offset != proto_len)
        return -1;

    struct asterism_session_s *session = AS_ZMALLOC(struct asterism_session_s);
    if (!session)
        return -1;
    session->username = as_strdup2(username, username_len);
    if (!session->username)
    {
        AS_FREE(session);
        return -1;
    }
    struct asterism_session_s *fs = RB_FIND(asterism_session_tree_s, &incoming->as->sessions, session);
    if (fs)
    {
        AS_SFREE(session->username);
        AS_FREE(session);
        return -1;
    }
    session->password = as_strdup2(password, password_len);
    if (!session->password)
    {
        AS_SFREE(session->username);
        AS_FREE(session);
        return -1;
    }
    session->outer = (struct asterism_stream_s *)incoming;
    incoming->session = session;

    RB_INSERT(asterism_session_tree_s, &incoming->as->sessions, session);

    asterism_log(ASTERISM_LOG_INFO, "user: %s join", session->username);

    return 0;
}

static int parse_cmd_connect_ack(
    struct asterism_tcp_incoming_s *incoming,
    struct asterism_trans_proto_s *proto)
{
    uint32_t id = 0;
    int success = 0;
    uint16_t proto_len = asterism_read_be16(&proto->len);
    if (asterism_decode_connect_ack(proto, proto_len, &id, &success) != 0)
        return -1;

    struct asterism_handshake_s fh = {id};
    struct asterism_handshake_s *handshake = RB_FIND(asterism_handshake_tree_s, &incoming->as->handshake_set, &fh);
    if (!handshake)
    {
        return -1;
    }
    RB_REMOVE(asterism_handshake_tree_s, &incoming->as->handshake_set, handshake);
    incoming->link = handshake->inner;
    incoming->link->link = (struct asterism_stream_s *)incoming;
    connect_ack_cb conn_ack_cb = handshake->conn_ack_cb;
    AS_FREE(handshake);

    return conn_ack_cb(incoming->link, success);
}

int asterism_decode_connect_ack(
    const void *data,
    size_t data_len,
    uint32_t *handshake_id,
    int *success)
{
    if (!handshake_id || !success)
        return -1;

    uint16_t frame_len = 0;
    if (asterism_proto_frame_size(data, data_len, &frame_len) != 1)
        return -1;
    if (frame_len != sizeof(struct asterism_trans_proto_s) + 4 + 1)
        return -1;

    const unsigned char *bytes = (const unsigned char *)data;
    if (bytes[1] != ASTERISM_TRANS_PROTO_CONNECT_ACK)
        return -1;
    if (bytes[sizeof(struct asterism_trans_proto_s) + 4] > 1)
        return -1;

    *handshake_id = asterism_read_be32(bytes + sizeof(struct asterism_trans_proto_s));
    *success = bytes[sizeof(struct asterism_trans_proto_s) + 4];
    return 0;
}

static void write_cmd_pong_cb(
    uv_write_t *req,
    int status)
{
    struct asterism_write_req_s *write_req = (struct asterism_write_req_s *)req;
    struct asterism_tcp_incoming_s *incoming = (struct asterism_tcp_incoming_s *)req->data;

    AS_SFREE(write_req->write_buffer.base);
    AS_FREE(write_req);
}

static int parse_cmd_ping(
    struct asterism_tcp_incoming_s* incoming,
    struct asterism_trans_proto_s* proto)
{
    char* pong_buf = __DUP_MEM((char*)&_global_proto_pong, sizeof(_global_proto_pong));
    if (!pong_buf)
        return ASTERISM_E_FAILED;
    struct asterism_write_req_s* write_req = AS_ZMALLOC(struct asterism_write_req_s);
    if (!write_req)
    {
        AS_FREE(pong_buf);
        return ASTERISM_E_FAILED;
    }
    write_req->write_buffer = uv_buf_init(pong_buf, sizeof(_global_proto_pong));
    write_req->write_req.data = incoming;

    int ret = asterism_stream_write((uv_write_t*)write_req, (struct asterism_stream_s*)incoming, &write_req->write_buffer, write_cmd_pong_cb);
    if (ret)
    {
        AS_FREE(write_req->write_buffer.base);
        AS_FREE(write_req);
        return ret;
    }
    return 0;
}

static void responser_write_cb(
    uv_udp_send_t* req, 
    int status)
{
    struct asterism_send_req_s* write_req = (struct asterism_send_req_s*)req;
    if (status != 0)
    {
        asterism_log(ASTERISM_LOG_DEBUG, "%s", uv_strerror(status));
    }
    AS_SFREE(write_req->write_buffer.base);
    AS_FREE(write_req);
}

static int udp_response_write(
    struct asterism_tcp_incoming_s* incoming,
    struct sockaddr_in source_addr,
    uv_buf_t buf)
{
    int ret = 0;
    struct asterism_session_s* session = incoming->session;
    if (session == 0)
        return -1;
    struct asterism_datagram_s* responser = session->inner_datagram;
    if (responser == 0)
        return -1;

    struct asterism_send_req_s* req = AS_ZMALLOC(struct asterism_send_req_s);
    if (!req)
        return -1;

    req->write_req.data = responser;
    req->write_buffer = buf;
    req->write_buffer.base = __DUP_MEM(buf.base, buf.len);
    if (buf.len && !req->write_buffer.base)
    {
        AS_FREE(req);
        return -1;
    }
    ret = uv_udp_send((uv_udp_send_t*)req, &responser->socket, &req->write_buffer, 1, (const struct sockaddr*)&source_addr, responser_write_cb);
    if (ret != 0)
    {
        AS_SFREE(req->write_buffer.base);
        AS_FREE(req);
    }
    return ret;
}

static int parse_cmd_datagram_response(
    struct asterism_tcp_incoming_s* incoming,
    struct asterism_trans_proto_s* proto)
{
    int ret = -1;
    int offset = sizeof(struct asterism_trans_proto_s);
    int proto_len = asterism_read_be16(&proto->len);
    if (proto_len < (int)sizeof(struct asterism_trans_proto_s))
        goto cleanup;

    struct sockaddr_in source_addr;
    memset(&source_addr, 0, sizeof(source_addr));
    source_addr.sin_family = AF_INET;

    if (offset + 4 > proto_len)
        goto cleanup;
    // Extract the source IPv4 address
    memcpy(&source_addr.sin_addr.s_addr, ((char*)proto) + offset, 4);
    offset += 4;

    if (offset + 2 > proto_len)
        goto cleanup;
    // Extract the source port
    memcpy(&source_addr.sin_port, ((char*)proto) + offset, 2);
    offset += 2;

    // Convert the IP to a string
    char ip_str[INET_ADDRSTRLEN];
    uv_inet_ntop(AF_INET, &source_addr.sin_addr, ip_str, INET_ADDRSTRLEN);

    // Convert the port to host byte order and print both IP and port
    unsigned short port_host_order = ntohs(source_addr.sin_port);
    //asterism_log(ASTERISM_LOG_DEBUG, "parsed source address: ip=%s, port=%u", ip_str, port_host_order);

    // Send the response to the source address
    ret = udp_response_write(incoming, source_addr, uv_buf_init(((char*)proto) + offset, proto_len - offset));
    if (ret != 0)
        goto cleanup;
    ret = 0;
cleanup:
    return ret;
}

static int incoming_parse_cmd_data(
    struct asterism_tcp_incoming_s *incoming,
    uv_buf_t *buf,
    int *eaten)
{
    size_t consumed = 0;
    while (consumed < buf->len)
    {
        uint16_t proto_len = 0;
        int frame_status = asterism_proto_frame_size(
            buf->base + consumed, buf->len - consumed, &proto_len);
        if (frame_status < 0)
            return -1;
        if (frame_status == 0)
            break;

        struct asterism_trans_proto_s *proto =
            (struct asterism_trans_proto_s *)(buf->base + consumed);
        if (proto->cmd == ASTERISM_TRANS_PROTO_JOIN)
        {
            asterism_log(ASTERISM_LOG_DEBUG, "connection join recv");
            if (parse_cmd_join(incoming, proto) != 0)
                return -1;
        }
        else if (proto->cmd == ASTERISM_TRANS_PROTO_CONNECT_ACK)
        {
            asterism_log(ASTERISM_LOG_DEBUG, "connection connect ack recv");
            if (parse_cmd_connect_ack(incoming, proto) != 0)
                return -1;
            // The link is now established. Any bytes following this frame are
            // raw relayed payload (e.g. a server-first banner that TCP
            // coalesced into the same read as the ACK), not control frames.
            // Stop frame parsing and let the caller forward the remainder
            // transparently; parsing it as a control frame would fail and tear
            // down the tunnel, dropping the first packet.
            consumed += proto_len;
            break;
        }
        else if (proto->cmd == ASTERISM_TRANS_PROTO_PING)
        {
            if (proto_len != sizeof(struct asterism_trans_proto_s) ||
                parse_cmd_ping(incoming, proto) != 0)
                return -1;
        }
        else if (proto->cmd == ASTERISM_TRANS_PROTO_DATAGRAM_RESPONSE)
        {
            if (parse_cmd_datagram_response(incoming, proto) != 0)
                return -1;
        }
        else
        {
            return -1;
        }
        consumed += proto_len;
    }
    *eaten += (int)consumed;
    return 0;
}

static void incoming_read_cb(
    uv_stream_t *stream,
    ssize_t nread,
    const uv_buf_t *buf)
{
    struct asterism_tcp_incoming_s *incoming = __CONTAINER_PTR(struct asterism_tcp_incoming_s, socket, stream);
    int eaten = 0;

    uv_buf_t _buf;
    _buf.base = incoming->buffer;
    _buf.len = incoming->buffer_len;
    if (incoming_parse_cmd_data(incoming, &_buf, &eaten) != 0)
    {
        asterism_stream_close((uv_handle_t *)stream);
        return;
    }
    asterism_stream_eaten((struct asterism_stream_s *)incoming, eaten);

    // If a CONNECT_ACK just established the link and the server-first payload
    // was coalesced into this same read, flush the leftover bytes to the
    // linked stream now. Subsequent reads are forwarded automatically in
    // stream_read_cb once both link and auto_trans are set.
    if (incoming->link && incoming->buffer_len > 0)
    {
        if (asterism_stream_trans((struct asterism_stream_s *)incoming) != 0)
        {
            asterism_stream_close((uv_handle_t *)stream);
        }
    }
}

static void outer_accept_cb(
    uv_stream_t *stream,
    int status)
{
    int ret = ASTERISM_E_OK;
    //asterism_log(ASTERISM_LOG_DEBUG, "new tcp connection is comming");

    struct asterism_tcp_outer_s *outer = __CONTAINER_PTR(struct asterism_tcp_outer_s, socket, stream);
    struct asterism_tcp_incoming_s *incoming = 0;
    if (status != 0)
    {
        goto cleanup;
    }
    incoming = AS_ZMALLOC(struct asterism_tcp_incoming_s);
    if (!incoming)
        return;
    ret = asterism_stream_accept(outer->as, stream, 1, 0, incoming_read_cb, incoming_close_cb, (struct asterism_stream_s *)incoming);
    if (ret != 0)
    {
        ret = ASTERISM_E_FAILED;
        goto cleanup;
    }
    ret = asterism_stream_read((struct asterism_stream_s *)incoming);
    if (ret != 0)
    {
        ret = ASTERISM_E_FAILED;
        goto cleanup;
    }
cleanup:
    if (ret != 0)
    {
        if (incoming)
        {
            asterism_stream_close((uv_handle_t *)&incoming->socket);
        }
    }
}

int asterism_outer_tcp_init(
    struct asterism_s *as,
    const char *ip, unsigned int *port)
{
    int ret = ASTERISM_E_OK;
    void *addr = 0;
    int name_len = 0;

    struct asterism_tcp_outer_s *outer = AS_ZMALLOC(struct asterism_tcp_outer_s);
    if (!outer)
        return ASTERISM_E_FAILED;
    outer->as = as;
    ASTERISM_HANDLE_INIT(outer, socket, outer_close);
    ret = uv_tcp_init(as->loop, &outer->socket);
    if (ret != 0)
    {
        asterism_log(ASTERISM_LOG_DEBUG, "%s", uv_strerror(ret));
        ret = ASTERISM_E_SOCKET_LISTEN_ERROR;
        goto cleanup;
    }
    addr = AS_ZMALLOC(struct sockaddr_in);
    if (!addr)
    {
        ret = ASTERISM_E_FAILED;
        goto cleanup;
    }
    name_len = sizeof(struct sockaddr_in);
    ret = uv_ip4_addr(ip, (int)*port, (struct sockaddr_in *)addr);

    if (ret != 0)
    {
        asterism_log(ASTERISM_LOG_DEBUG, "%s", uv_strerror(ret));
        ret = ASTERISM_E_SOCKET_LISTEN_ERROR;
        goto cleanup;
    }
    ret = uv_tcp_bind(&outer->socket, (const struct sockaddr *)addr, 0);
    if (ret != 0)
    {
        asterism_log(ASTERISM_LOG_DEBUG, "%s", uv_strerror(ret));
        ret = ASTERISM_E_SOCKET_LISTEN_ERROR;
        goto cleanup;
    }
    ret = uv_tcp_getsockname(&outer->socket, (struct sockaddr *)addr, &name_len);
    if (ret != 0)
    {
        asterism_log(ASTERISM_LOG_DEBUG, "%s", uv_strerror(ret));
        ret = ASTERISM_E_SOCKET_LISTEN_ERROR;
        goto cleanup;
    }
    *port = ntohs(((struct sockaddr_in *)addr)->sin_port);

    ret = uv_listen((uv_stream_t *)&outer->socket, ASTERISM_NET_BACKLOG, outer_accept_cb);
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
        outer_close((uv_handle_t *)&outer->socket);
    }
    return ret;
}
