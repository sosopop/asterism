#include <http_parser.h>
#include "asterism_inner_http.h"
#include "asterism_core.h"
#include "asterism_log.h"
#include "asterism_utils.h"

static void inner_close_cb(
    uv_handle_t *handle)
{
    struct asterism_http_inner_s *obj = __CONTAINER_PTR(struct asterism_http_inner_s, socket, handle);
    AS_FREE(obj);
}

static void inner_close(
    uv_handle_t *handle)
{
    as_uv_close(handle, inner_close_cb);
}

static void incoming_delete(struct asterism_http_incoming_s *obj)
{
    if (obj->last_host_info.p)
    {
        AS_FREE((char *)obj->last_host_info.p);
    }
    AS_FREE(obj);
}

static void incoming_close_cb(
    uv_handle_t *handle)
{
    int ret = 0;
    struct asterism_http_incoming_s *obj = __CONTAINER_PTR(struct asterism_http_incoming_s, socket, handle);
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
    asterism_log(ASTERISM_LOG_DEBUG, "http is closing");
}

static void regular_http_request(
    struct asterism_http_incoming_s *incoming)
{
    //remove proxy headers
    struct asterism_str remove_data[3];
    remove_data[0] = incoming->host_info;
    if (incoming->auth_key_info.p > incoming->conn_key_info.p)
    {
        remove_data[1] = incoming->conn_key_info;
        remove_data[1].len = (sizeof(HTTP_PROXY_PREFIX_HEAD) - 1);
        remove_data[2] = incoming->auth_key_info;
        remove_data[2].len = (incoming->auth_val_info.p + incoming->auth_val_info.len) - incoming->auth_key_info.p + 2;
    }
    else
    {
        remove_data[1] = incoming->auth_key_info;
        remove_data[1].len = (incoming->auth_val_info.p + incoming->auth_val_info.len) - incoming->auth_key_info.p + 2;
        remove_data[2] = incoming->conn_key_info;
        remove_data[2].len = (sizeof(HTTP_PROXY_PREFIX_HEAD) - 1);
    }

    int off = 0;
    int len = incoming->buffer_len;
    char *buffer = incoming->buffer;

    for (int i = 0; i < __ARRAY_SIZE(remove_data); i++)
    {
        if (!remove_data[i].p)
        {
            continue;
        }
        char *remove_buffer = (char *)remove_data[i].p - off;
        int remove_len = (int)remove_data[i].len;
        memmove(remove_buffer, remove_buffer + remove_len, (buffer + len) - (remove_buffer + remove_len));
        off += remove_len;
    }
    incoming->buffer_len = len - off;
}

static void write_connect_ack_cb(
    uv_write_t *req,
    int status)
{
    struct asterism_http_incoming_s *incoming = (struct asterism_http_incoming_s *)req->data;
    if (status)
    {
        goto cleanup;
    }
    int ret = asterism_stream_read((struct asterism_stream_s *)incoming);
    if (ret)
    {
        goto cleanup;
    }
cleanup:
    if (ret || status)
    {
        asterism_stream_close((uv_handle_t *)&incoming->socket);
    }
    free(req);
}

static int conn_ack_cb(
    struct asterism_stream_s *stream, int success)
{
    int ret = -1;
    uv_write_t *req = 0;
    struct asterism_http_incoming_s *incoming = (struct asterism_http_incoming_s *)stream;
    if (!success) 
    {
        goto cleanup;
    }
    if (incoming->parser.method == HTTP_CONNECT)
    {
        req = AS_ZMALLOC(uv_write_t);
        req->data = stream;
        uv_buf_t buf;
        buf.base = HTTP_RESP_200;
        buf.len = sizeof(HTTP_RESP_200) - 1;
        ret = uv_write(req, (uv_stream_t *)&stream->socket, &buf, 1, write_connect_ack_cb);
        if (ret)
        {
            goto cleanup;
        }
    }
    else
    {
        regular_http_request(incoming);
        asterism_stream_set_autotrans(stream, 0);
        ret = asterism_stream_trans(stream);
        if (ret)
        {
            goto cleanup;
        }
    }
    incoming->is_connect = 1;
cleanup:
    if (ret)
    {
        AS_SFREE(req);
        asterism_stream_close((uv_handle_t *)&stream->socket);
    }
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

static int parse_connect(
    struct asterism_http_incoming_s *incoming,
    struct asterism_str host)
{
    if (!host.len)
        return -1;
    if (host.len > MAX_HOST_LEN)
        return -1;
    if (!incoming->auth_val_info.len)
        return 407;
    struct asterism_str base_prefix = asterism_mk_str("Basic ");
    if (asterism_strncmp(incoming->auth_val_info, base_prefix, base_prefix.len) != 0)
        return -1;
    char decode_buffer[128] = {0};
    int deocode_size = sizeof(decode_buffer);
    int parsed = asterism_base64_decode(
        (const unsigned char *)incoming->auth_val_info.p + base_prefix.len,
        (int)(incoming->auth_val_info.len - base_prefix.len),
        decode_buffer,
        &deocode_size);
    if (parsed != incoming->auth_val_info.len - base_prefix.len)
        return -1;
    char *split_pos = strchr(decode_buffer, ':');
    if (!split_pos)
        return 407;
    *split_pos = 0;
    char *username = decode_buffer;
    char *password = split_pos + 1;
    asterism_log(ASTERISM_LOG_DEBUG, "http request username: %s , password: %s", username, password);
    //test exit
    //         if (strcmp(username, "exit") == 0) {
    //             asterism_stop(incoming->as);
    //         }
    struct asterism_session_s sefilter;
    sefilter.username = username;
    struct asterism_session_s *session = RB_FIND(asterism_session_tree_s, &incoming->as->sessions, &sefilter);

    if (!session)
        return 407;
    if (strcmp(session->password, password))
        return 407;

    struct asterism_handshake_s *handshake = AS_ZMALLOC(struct asterism_handshake_s);
    handshake->inner = (struct asterism_stream_s *)incoming;
    handshake->conn_ack_cb = conn_ack_cb;
    handshake->id = asterism_tunnel_new_handshake_id();
    incoming->handshake_id = handshake->id;

    struct asterism_write_req_s *req = AS_ZMALLOC(struct asterism_write_req_s);

    int port_len = 0;

    //if not port, set default 80
    const char *has_port = asterism_strchr(host, ':');
    if (!has_port)
        port_len = 3;
    struct asterism_trans_proto_s *connect_data =
        (struct asterism_trans_proto_s *)malloc(sizeof(struct asterism_trans_proto_s) +
                                                host.len + port_len + 2 + 4);

    connect_data->version = ASTERISM_TRANS_PROTO_VERSION;
    connect_data->cmd = ASTERISM_TRANS_PROTO_CONNECT;

    char *off = (char *)connect_data + sizeof(struct asterism_trans_proto_s);
    *(uint32_t *)off = htonl(handshake->id);
    off += 4;

    *(uint16_t *)off = htons((uint16_t)host.len + port_len);
    off += 2;
    memcpy(off, host.p, host.len);
    off += host.len;
    if (!has_port)
    {
        memcpy(off, HTTP_DEFAULT_PORT, sizeof(HTTP_DEFAULT_PORT) - 1);
        off += (sizeof(HTTP_DEFAULT_PORT) - 1);
    }

    asterism_log(ASTERISM_LOG_DEBUG, "connect to %.*s", host.len, host.p);

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

    if (incoming->parser.method == HTTP_CONNECT)
    {
        asterism_stream_eaten((struct asterism_stream_s *)incoming, incoming->buffer_len);
    }

    asterism_log(ASTERISM_LOG_DEBUG, "send handshake %d", handshake->id);
    RB_INSERT(asterism_handshake_tree_s, &incoming->as->handshake_set, handshake);
    return 0;
}

static int parse_connect_type(
    struct asterism_http_incoming_s *incoming)
{
    return parse_connect(incoming, incoming->connect_url);
}

static int parse_normal_type(
    struct asterism_http_incoming_s *incoming)
{
    struct asterism_str temp = asterism_mk_str_n(HTTP_PROTOCOL_TOKEN, sizeof(HTTP_PROTOCOL_TOKEN) - 1);
    const char *host_start = asterism_strstr(incoming->connect_url, temp);
    if (!host_start)
        return -1;
    incoming->host_info.p = host_start;
    host_start += (sizeof(HTTP_PROTOCOL_TOKEN) - 1);

    temp.p = host_start;
    temp.len = incoming->connect_url.len - (host_start - incoming->connect_url.p);

    const char *host_end = asterism_strchr(temp, '/');
    if (!host_end)
        return -1;

    incoming->host_info.len = host_end - incoming->host_info.p;
    struct asterism_str host = asterism_mk_str_n(host_start, host_end - host_start);

    if (asterism_strcmp(host, incoming->last_host_info))
    {
        if (incoming->last_host_info.p)
        {
            AS_FREE((char *)incoming->last_host_info.p);
        }
        incoming->last_host_info = asterism_strdup(host);
        incoming->is_connect = 0;
        if (incoming->link)
        {
            incoming->link->link = 0;
            asterism_stream_end(incoming->link);
        }
        incoming->link = 0;
    }

    if (incoming->is_connect)
    {
        regular_http_request(incoming);
        return asterism_stream_trans((struct asterism_stream_s *)incoming);
    }

    //asterism_log(ASTERISM_LOG_INFO, "http connect to %.*s", incoming->connect_url.len, incoming->connect_url.p);

    return parse_connect(incoming, host);
}

static int on_url(http_parser *parser, const char *at, size_t length)
{
    struct asterism_http_incoming_s *obj = __CONTAINER_PTR(struct asterism_http_incoming_s, parser, parser);
    if (obj->connect_url.p)
    {
        obj->connect_url.len += length;
    }
    else
    {
        obj->connect_url.p = at;
        obj->connect_url.len += length;
    }
    return 0;
}

static void parse_value(struct asterism_http_incoming_s *obj)
{
    if (obj->header_parsed_type == HEADER_PARSED_TYPE_AUTH)
    {
        obj->auth_val_info = obj->http_header_value_temp;
        obj->header_parsed_type = HEADER_PARSED_TYPE_NULL;
    }
    obj->http_header_value_temp.p = 0;
    obj->http_header_value_temp.len = 0;
}

static void parse_key(struct asterism_http_incoming_s *obj)
{
    if (asterism_vcasecmp(&obj->http_header_field_temp, HTTP_PROXY_AUTH_HEAD) == 0)
    {
        obj->header_parsed_type = HEADER_PARSED_TYPE_AUTH;
        obj->auth_key_info = obj->http_header_field_temp;
    }
    else if (asterism_vcasecmp(&obj->http_header_field_temp, HTTP_PROXY_CONN_HEAD) == 0)
    {
        obj->conn_key_info = obj->http_header_field_temp;
    }
    //asterism_log(ASTERISM_LOG_DEBUG, "on_header_field %.*s", obj->http_header_field_temp.len, obj->http_header_field_temp.p);
    obj->http_header_field_temp.p = 0;
    obj->http_header_field_temp.len = 0;
}

static int on_header_field(http_parser *parser, const char *at, size_t length)
{
    struct asterism_http_incoming_s *obj = __CONTAINER_PTR(struct asterism_http_incoming_s, parser, parser);
    if (obj->http_header_field_temp.p)
    {
        obj->http_header_field_temp.len += length;
    }
    else
    {
        obj->http_header_field_temp.p = at;
        obj->http_header_field_temp.len += length;
    }
    if (obj->http_header_value_temp.p)
    {
        parse_value(obj);
    }
    return 0;
}

static int on_header_value(http_parser *parser, const char *at, size_t length)
{
    struct asterism_http_incoming_s *obj = __CONTAINER_PTR(struct asterism_http_incoming_s, parser, parser);
    if (obj->http_header_value_temp.p)
    {
        obj->http_header_value_temp.len += length;
    }
    else
    {
        obj->http_header_value_temp.p = at;
        obj->http_header_value_temp.len += length;
    }
    if (obj->http_header_field_temp.p)
    {
        parse_key(obj);
    }
    return 0;
}

static int on_headers_complete(http_parser *parser)
{
    struct asterism_http_incoming_s *obj = __CONTAINER_PTR(struct asterism_http_incoming_s, parser, parser);
    obj->header_parsed = 1;
    if (obj->http_header_value_temp.p)
    {
        parse_value(obj);
    }
    return 0;
}

static int on_message_begin(http_parser *parser)
{
    struct asterism_http_incoming_s *obj = __CONTAINER_PTR(struct asterism_http_incoming_s, parser, parser);
    struct asterism_str empty_str = {0, 0};
    obj->http_header_field_temp = empty_str;
    obj->http_header_value_temp = empty_str;
    obj->connect_url = empty_str;
    obj->auth_val_info = empty_str;
    obj->auth_key_info = empty_str;
    obj->conn_key_info = empty_str;
    obj->host_info = empty_str;
    return 0;
}

static int on_message_complete(http_parser *parser)
{
    return 0;
}

static http_parser_settings parser_settings = {
    on_message_begin,
    on_url,
    0,
    on_header_field,
    on_header_value,
    on_headers_complete,
    0,
    on_message_complete,
    0,
    0};

static int incoming_parse_connect(
    struct asterism_http_incoming_s *incoming,
    ssize_t nread,
    const uv_buf_t *buf)
{
    size_t nparsed = http_parser_execute(&incoming->parser, &parser_settings, buf->base, nread);
    if (incoming->parser.http_errno != 0)
    {
        asterism_log(ASTERISM_LOG_DEBUG, "%s", http_errno_description((enum http_errno)incoming->parser.http_errno));
        return -1;
    }
    if (nparsed != nread)
        return -1;
    if (!incoming->header_parsed)
    {
        if (incoming->buffer_len == ASTERISM_MAX_HTTP_HEADER_SIZE)
        {
            return -1;
        }
    }
    else
    {
        if (incoming->parser.method == HTTP_CONNECT)
        {
            return parse_connect_type(incoming);
        }
        else
        {
            return parse_normal_type(incoming);
        }
    }
    return 0;
}

static void resp_auth_write_cb(
    uv_write_t *req,
    int status)
{
    struct asterism_stream_s *stream = (struct asterism_stream_s *)req->data;
    free(req);
    //asterism_stream_end(stream);
}

static void incoming_read_cb(
    uv_stream_t *stream,
    ssize_t nread,
    const uv_buf_t *buf)
{

    struct asterism_http_incoming_s *incoming = __CONTAINER_PTR(struct asterism_http_incoming_s, socket, stream);
    int ret = incoming_parse_connect(incoming, nread, buf);
    if (ret == 0)
    {
        if (incoming->header_parsed)
        {
            uv_read_stop(stream);
        }
        return;
    }
    else if (ret == 407)
    {

        uv_write_t *req = AS_ZMALLOC(uv_write_t);
        req->data = incoming;
        uv_buf_t buf = uv_buf_init((char *)HTTP_RESP_407, sizeof(HTTP_RESP_407) - 1);
        int write_ret = uv_write((uv_write_t *)req, (uv_stream_t *)&incoming->socket, &buf, 1, resp_auth_write_cb);
        if (write_ret != 0)
        {
            free(req);
        }
        //asterism_stream_eaten((struct asterism_stream_s *)incoming, incoming->buffer_len);
        asterism_stream_end((struct asterism_stream_s *)incoming);
    }
    else
    {
        asterism_stream_close((uv_handle_t *)&incoming->socket);
    }
}

static void inner_accept_cb(
    uv_stream_t *stream,
    int status)
{
    int ret = ASTERISM_E_OK;
    asterism_log(ASTERISM_LOG_DEBUG, "http connection is comming");

    struct asterism_http_inner_s *inner = __CONTAINER_PTR(struct asterism_http_inner_s, socket, stream);
    struct asterism_http_incoming_s *incoming = 0;
    if (status != 0)
    {
        goto cleanup;
    }
    incoming = AS_ZMALLOC(struct asterism_http_incoming_s);
    http_parser_init(&incoming->parser, HTTP_REQUEST);
    ret = asterism_stream_accept(inner->as, stream, 1, 0,
                                 incoming_read_cb, incoming_close_cb, (struct asterism_stream_s *)incoming);
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
        asterism_stream_close((uv_handle_t *)&incoming->socket);
    }
}

int asterism_inner_http_init(
    struct asterism_s *as,
    const char *ip, unsigned int *port)
{
    int ret = ASTERISM_E_OK;
    void *addr = 0;
    int name_len = 0;
    struct asterism_http_inner_s *inner = AS_ZMALLOC(struct asterism_http_inner_s);
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