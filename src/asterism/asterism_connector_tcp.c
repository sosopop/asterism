#include "asterism_connector_tcp.h"
#include "asterism_requestor_tcp.h"
#include "asterism_core.h"
#include "asterism_utils.h"
#include "asterism_log.h"
#include "asterism_responser_tcp.h"
#include "asterism_requestor_udp.h"

static void connector_delete(
    struct asterism_tcp_connector_s *obj)
{
    if (obj->host)
    {
        AS_FREE(obj->host);
    }

    struct asterism_udp_session_s* h = 0;
    struct asterism_udp_session_s* _h = 0;

    RB_FOREACH_SAFE(h, asterism_udp_session_tree_s, &obj->udp_sessions, _h)
    {
        if (h->datagram) 
        {
            struct asterism_udp_requestor_s* requestor = (struct asterism_udp_requestor_s*)h->datagram;
            requestor->connector = 0;
            asterism_datagram_close((uv_handle_t*)&requestor->socket);
            h->datagram = 0;
        }
        RB_REMOVE(asterism_udp_session_tree_s, &obj->udp_sessions, h);
        AS_FREE(h);
    }
    RB_INIT(&obj->udp_sessions);

    AS_FREE(obj);
}

static void close_hearbeat(uv_handle_t *handle);
static void reconnect_close_cb(uv_handle_t *handle);

static void reconnect_timer_close(uv_handle_t *handle)
{
    as_uv_close(handle, reconnect_close_cb);
}

static void reconnect_timer_cb(
    uv_timer_t *handle)
{
    reconnect_timer_close((uv_handle_t *)handle);
}

static void reconnect_close_cb(
    uv_handle_t *handle)
{
    struct connector_timer_s *timer = __CONTAINER_PTR(struct connector_timer_s, timer, handle);
    struct asterism_tcp_connector_s *connector = timer->connector;

    if (connector->as->stoped != 1)
    {
        asterism_log(ASTERISM_LOG_DEBUG, "connector reconnect");
        asterism_connector_tcp_init(connector->as,
                                    connector->host, connector->port);
    }

    connector_delete(connector);
    AS_FREE(timer);
}

static void connector_close_cb(
    uv_handle_t *handle)
{
    int ret = 0;
    struct asterism_tcp_connector_s *obj = __CONTAINER_PTR(struct asterism_tcp_connector_s, socket, handle);
    if (obj->heartbeat_timer)
    {
        close_hearbeat(handle);
        obj->heartbeat_timer->connector = 0;
    }
    if (obj->as->stoped != 1)
    {
        struct connector_timer_s *timer = AS_ZMALLOC(struct connector_timer_s);
        ASTERISM_HANDLE_INIT(timer, timer, reconnect_timer_close);
        timer->connector = obj;
        unsigned int reconnect_delay = obj->as->reconnect_delay;
        uv_timer_init(obj->as->loop, &timer->timer);
        uv_timer_start(&timer->timer, reconnect_timer_cb, reconnect_delay, reconnect_delay);
    }
    else
    {
        connector_delete(obj);
    }
    asterism_log(ASTERISM_LOG_DEBUG, "connector is closed");
}

static int connector_parse_datagram_request(
    struct asterism_tcp_connector_s* conn,
    struct asterism_trans_proto_s* proto)
{
    int ret = -1;
    int offset = sizeof(struct asterism_trans_proto_s);
    int proto_len = ntohs(proto->len);

    unsigned char atyp;
    struct sockaddr_storage remote_addr_storage;
    struct sockaddr_in* remote_addr;
    char remote_host_str[MAX_HOST_LEN];
    unsigned short remote_port;
    unsigned char remote_host_len;
    unsigned char* data;
    int data_len = 0;

    struct sockaddr_in source_addr;
    memset(&source_addr, 0, sizeof(source_addr));
    source_addr.sin_family = AF_INET;

    remote_host_str[0] = '\0';

    if (offset + 4  > proto_len)
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
    asterism_log(ASTERISM_LOG_DEBUG, "parsed source address: ip=%s, port=%u", ip_str, port_host_order);

    //+---- + ------ + ------ + ---------- + ---------- + ---------- +
    //| RSV |  FRAG  |  ATYP  |  DST.ADDR  |  DST.PORT  |    DATA    |
    //+---- + ------ + ------ + ---------- + ---------- + ---------- +
    //|  2  |    1   |    1   |  Variable  |      2     |  Variable  |
    //+---- + ------ + ------ + ---------- + ---------- + ---------- +

    // Skip RSV and FRAG fields (3 bytes)
    offset += 3;

    if (offset + 1 > proto_len)
        goto cleanup;

    // Extract ATYP
    memcpy(&atyp, ((char*)proto) + offset, 1);
    offset += 1;

    // Handle different ATYP cases
    switch (atyp) {
    case 0x01: // IPv4
        remote_addr = (struct sockaddr_in*)&remote_addr_storage;
        memset(remote_addr, 0, sizeof(struct sockaddr_in));
        remote_addr->sin_family = AF_INET;

        if (offset + 4 + 2 > proto_len)
            goto cleanup;

        memcpy(&remote_addr->sin_addr.s_addr, ((char*)proto) + offset, 4);
        offset += 4;
        memcpy(&remote_addr->sin_port, ((char*)proto) + offset, 2);
        offset += 2;

        uv_inet_ntop(AF_INET, &remote_addr->sin_addr, remote_host_str, INET_ADDRSTRLEN);
        remote_port = ntohs(remote_addr->sin_port);

        // Log the destination address and port
        asterism_log(ASTERISM_LOG_DEBUG, "parsed destination address: ip=%s, port=%u", remote_host_str, remote_port);
        break;

    case 0x03: // Domain name
		// Extract the domain name length
		memcpy(&remote_host_len, ((char*)proto) + offset, 1);
		offset += 1;

		if (offset + remote_host_len + 2 > proto_len)
			goto cleanup;
        if (remote_host_len > MAX_HOST_LEN - 1)
            goto cleanup;

		// Extract the domain name
		memcpy(remote_host_str, ((char*)proto) + offset, remote_host_len);
        remote_host_str[remote_host_len] = '\0';
		offset += remote_host_len;

		// Extract the port
		memcpy(&remote_port, ((char*)proto) + offset, 2);
        remote_port = ntohs(remote_port);
		offset += 2;

		// Log the destination address and port
		asterism_log(ASTERISM_LOG_DEBUG, "parsed destination address: domain=%s, port=%u", remote_host_str, remote_port);
        break;
    default:
        asterism_log(ASTERISM_LOG_DEBUG, "unknown atyp value: %u", atyp);
        break;
    }

    data = (unsigned char*)((char*)proto + offset);
    data_len = proto_len - offset;

    offset += data_len;

    if (offset != proto_len)
		goto cleanup;

    if (remote_host_str[0] != '\0' && remote_port != 0) {
        ret = asterism_requestor_udp_trans(conn, atyp, remote_host_str, remote_port, source_addr, data, data_len);
    }

    ret = 0;
cleanup:
    return ret;
}

static int connector_parse_connect_data(
    struct asterism_tcp_connector_s *conn,
    struct asterism_trans_proto_s *proto)
{
    int ret = -1;
    int offset = sizeof(struct asterism_trans_proto_s);
    unsigned short host_len = 0;
    char *host = 0;
    char *__host = 0;
    char* target = 0;

    if (offset + 4 > proto->len)
        goto cleanup;
    unsigned int handshake_id = ntohl(*(unsigned int *)((char *)proto + offset));
    offset += 4;

    if (offset + 2 > proto->len)
        goto cleanup;
    host_len = ntohs(*(unsigned short *)((char *)proto + offset));
    offset += 2;

    if (host_len > MAX_HOST_LEN)
        goto cleanup;

    if (offset + host_len > proto->len)
        goto cleanup;

    host = (char *)((char *)proto + offset);
    offset += host_len;

    asterism_log(ASTERISM_LOG_INFO, "connect to: %.*s", (int)host_len, host);

    target = as_strdup2(host, host_len);
    if (conn->as->connect_redirect_hook_cb)
    {
        char *new_target = conn->as->connect_redirect_hook_cb(
            target, conn->as->connect_redirect_hook_data);
        if (new_target == 0)
        {
            goto error;
        }
        else if (target != new_target)
        {
            AS_FREE(target);
            target = new_target;
        }
    }

    struct asterism_str scheme = {0};
    struct asterism_str host_str = {0};
    unsigned int port = 0;
    asterism_host_type host_type;

    if (asterism_parse_address(target, &scheme, &host_str, &port, &host_type) || !host_str.p || !port)
        goto error;

    __host = as_strdup2(host_str.p, host_str.len);

    if (asterism_requestor_tcp_init(conn->as, __host, port, conn->host, conn->port, handshake_id))
        goto error;

    ret = 0;
error:
    if (ret)
    {
        ret = asterism_responser_tcp_init(conn->as, conn->host,
                                          conn->port, handshake_id, 0);
    }
cleanup:
    AS_SFREE(__host);
    AS_SFREE(target);
    return ret;
}

static int connector_parse_cmd_data(
    struct asterism_tcp_connector_s *conn,
    uv_buf_t *buf,
    int *eaten)
{
    if (buf->len < sizeof(struct asterism_trans_proto_s))
        return 0;
    struct asterism_trans_proto_s *proto = (struct asterism_trans_proto_s *)buf->base;
    uint16_t proto_len = ntohs(proto->len);
    if (proto->version != ASTERISM_TRANS_PROTO_VERSION)
        return -1;
    if (proto_len > ASTERISM_MAX_PROTO_SIZE)
        return -1;
    if (proto_len > buf->len)
    {
        return 0;
    }
    if (proto->cmd == ASTERISM_TRANS_PROTO_CONNECT)
    {
        asterism_log(ASTERISM_LOG_DEBUG, "connection connect recv");
        if (connector_parse_connect_data(conn, proto) != 0)
            return -1;
    }
    else if (proto->cmd == ASTERISM_TRANS_PROTO_PONG)
    {
        //asterism_log(ASTERISM_LOG_DEBUG, "connection pong recv");
    }
    else if (proto->cmd == ASTERISM_TRANS_PROTO_DATAGRAM_REQUEST)
    {
		// asterism_log(ASTERISM_LOG_DEBUG, "connection datagram request recv");
		if (connector_parse_datagram_request(conn, proto) != 0)
			return -1;
    }
    else
    {
        return -1;
    }
    *eaten += proto_len;
    unsigned int remain = buf->len - proto_len;
    if (remain)
    {
        uv_buf_t __buf;
        __buf.base = buf->base + proto_len;
        __buf.len = remain;
        return connector_parse_cmd_data(conn, &__buf, eaten);
    }
    return 0;
}

static void connector_read_cb(
    uv_stream_t *stream,
    ssize_t nread,
    const uv_buf_t *buf)
{
    struct asterism_tcp_connector_s *connector = __CONTAINER_PTR(struct asterism_tcp_connector_s, socket, stream);
    int eaten = 0;
    uv_buf_t _buf;
    _buf.base = connector->buffer;
    _buf.len = connector->buffer_len;
    if (connector_parse_cmd_data(connector, &_buf, &eaten) != 0)
    {
        asterism_stream_close((uv_handle_t *)stream);
        return;
    }
    asterism_stream_eaten((struct asterism_stream_s *)connector, eaten);
}

static void heartbeat_close_cb(
    uv_handle_t *handle)
{
    struct connector_timer_s *timer = __CONTAINER_PTR(struct connector_timer_s, timer, handle);
    if (timer->connector) {
        timer->connector->heartbeat_timer = 0;
    }
    AS_FREE(timer);
}

static void close_hearbeat(
    uv_handle_t *handle)
{
    as_uv_close(handle, heartbeat_close_cb);
}

static void connector_send_ping_cb(
    uv_write_t *req,
    int status)
{
    struct asterism_write_req_s *write_req = (struct asterism_write_req_s *)req;
    struct asterism_tcp_connector_s *connector = (struct asterism_tcp_connector_s *)req->data;

    AS_FREE(write_req->write_buffer.base);
    AS_FREE(write_req);
}

static int connector_send_ping(struct asterism_tcp_connector_s *connector)
{
    int ret = 0;

    char* ping_buf = __DUP_MEM((char *)&_global_proto_ping, sizeof(_global_proto_ping));

    struct asterism_write_req_s *write_req = AS_ZMALLOC(struct asterism_write_req_s);
    write_req->write_buffer = uv_buf_init(ping_buf, sizeof(_global_proto_ping));
    write_req->write_req.data = connector;

    ret = asterism_stream_write((uv_write_t*)write_req, (struct asterism_stream_s *)connector, &write_req->write_buffer, connector_send_ping_cb);
    if (ret != 0)
    {
        goto cleanup;
    }
    //asterism_log(ASTERISM_LOG_DEBUG, "connection send ping");
cleanup:
    return ret;
}

static void heartbeat_timeout_cb(
    uv_timer_t *handle)
{
    struct connector_timer_s *timer = __CONTAINER_PTR(struct connector_timer_s, timer, handle);
    if (!timer->connector || uv_is_closing((uv_handle_t *)&timer->connector->socket))
    {
        return;
    }
    int ret = connector_send_ping(timer->connector);
    if (ret != 0)
        asterism_stream_close((uv_handle_t *)handle);
}

static void connector_send_cb(
    uv_write_t *req,
    int status)
{
    struct asterism_write_req_s *write_req = (struct asterism_write_req_s *)req;
    struct asterism_tcp_connector_s *connector = (struct asterism_tcp_connector_s *)req->data;
    int ret = asterism_stream_read((struct asterism_stream_s *)connector);
    if (ret != 0)
    {
        goto cleanup;
    }
    connector->heartbeat_timer = AS_ZMALLOC(struct connector_timer_s);
    ASTERISM_HANDLE_INIT(connector->heartbeat_timer, timer, close_hearbeat);
    connector->heartbeat_timer->connector = connector;
    ret = uv_timer_init(connector->as->loop, &connector->heartbeat_timer->timer);
    if (ret != 0)
    {
        goto cleanup;
    }
    unsigned int heartbeart_interval = connector->as->heartbeart_interval;
    ret = uv_timer_start(&connector->heartbeat_timer->timer, heartbeat_timeout_cb,
                         heartbeart_interval, heartbeart_interval);
    if (ret != 0)
    {
        goto cleanup;
    }
cleanup:
    if (ret != 0)
    {
        if (connector->heartbeat_timer)
            close_hearbeat((uv_handle_t *)&connector->heartbeat_timer->timer);
        asterism_stream_close((uv_handle_t *)&connector->socket);
    }
    free(write_req->write_buffer.base);
    free(write_req);
}

static int connector_send_join(struct asterism_tcp_connector_s *connector)
{
    int ret = 0;
    struct asterism_s *as = connector->as;
    size_t username_len = strlen(as->username);
    size_t password_len = strlen(as->password);

    struct asterism_trans_proto_s *connect_data = (struct asterism_trans_proto_s *)
        malloc(sizeof(struct asterism_trans_proto_s) + username_len + password_len + 2 + 2);
    connect_data->version = ASTERISM_TRANS_PROTO_VERSION;
    connect_data->cmd = ASTERISM_TRANS_PROTO_JOIN;

    char *off = (char *)connect_data + sizeof(struct asterism_trans_proto_s);
    *(uint16_t *)off = htons((uint16_t)username_len);
    off += 2;
    memcpy(off, as->username, username_len);
    off += username_len;

    *(uint16_t *)off = htons((uint16_t)password_len);
    off += 2;
    memcpy(off, as->password, password_len);
    off += password_len;

    uint16_t packet_len = (uint16_t)(off - (char *)connect_data);
    connect_data->len = htons(packet_len);

    struct asterism_write_req_s *write_req = AS_ZMALLOC(struct asterism_write_req_s);
    write_req->write_buffer.base = (char *)connect_data;
    write_req->write_buffer.len = packet_len;
    write_req->write_req.data = connector;
    ret = asterism_stream_write(&write_req->write_req, (struct asterism_stream_s *)connector, &write_req->write_buffer, connector_send_cb);
    if (ret != 0)
    {
        AS_FREE(write_req);
        if (connect_data)
            free(connect_data);
        goto cleanup;
    }
    ret = uv_read_stop((uv_stream_t *)&connector->socket);
    if (ret != 0)
    {
        goto cleanup;
    }
    asterism_log(ASTERISM_LOG_DEBUG, "connection join send");
cleanup:
    return ret;
}

static void connector_connect_cb(
    uv_connect_t *req,
    int status)
{
    int ret = 0;
    if (status != 0)
        return;
    struct asterism_tcp_connector_s *connector = (struct asterism_tcp_connector_s *)req->data;
    ret = connector_send_join(connector);
    if (ret != 0)
    {
        goto cleanup;
    }
cleanup:
    if (ret != 0)
    {
        asterism_stream_close((uv_handle_t *)&connector->socket);
    }
}

int asterism_connector_tcp_init(struct asterism_s *as,
                                const char *host, unsigned int port)
{
    int ret = 0;
    struct asterism_tcp_connector_s *connector = AS_ZMALLOC(struct asterism_tcp_connector_s);
    connector->host = as_strdup(host);
    connector->port = port;
    ret = asterism_stream_connect(as, host, port, 1, 1,
                                  connector_connect_cb, 0, connector_read_cb, connector_close_cb, (struct asterism_stream_s *)connector);
    if (ret)
        goto cleanup;
cleanup:
    if (ret)
    {
        asterism_stream_close((uv_handle_t *)&connector->socket);
    }
    return ret;
}