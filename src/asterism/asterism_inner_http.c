#include <http_parser.h>
#include "asterism_inner_http.h"
#include "asterism_core.h"
#include "asterism_log.h"
#include "asterism_utils.h"

static struct asterism_http_inner_s *inner_new(struct asterism_s *as)
{
    struct asterism_http_inner_s *obj = __zero_malloc_st(struct asterism_http_inner_s);
    obj->as = as;
    int ret = uv_tcp_init(as->loop, &obj->socket);
    if (ret != 0)
    {
        asterism_log(ASTERISM_LOG_DEBUG, "%s", uv_strerror(ret));
        ret = ASTERISM_E_SOCKET_LISTEN_ERROR;
        goto cleanup;
    }
cleanup:
    if (ret != 0)
    {
        AS_FREE(obj);
        obj = 0;
    }
    return obj;
}

static void inner_delete(struct asterism_http_inner_s *obj)
{
    AS_FREE(obj);
}

static void inner_close_cb(
    uv_handle_t *handle)
{
    struct asterism_http_inner_s *obj = (struct asterism_http_inner_s *)handle;
    inner_delete(obj);
}

static void inner_close(
    struct asterism_http_inner_s *obj)
{
    if (obj && !uv_is_closing((uv_handle_t *)&obj->socket))
        uv_close((uv_handle_t *)&obj->socket, inner_close_cb);
}

//////////////////////////////////////////////////////////////////////////////////////////////////

static struct asterism_http_incoming_s *incoming_new(struct asterism_s *as)
{
    struct asterism_http_incoming_s *obj = __zero_malloc_st(struct asterism_http_incoming_s);
    obj->as = as;
    int ret = uv_tcp_init(as->loop, &obj->socket);
    if (ret != 0)
    {
        asterism_log(ASTERISM_LOG_DEBUG, "%s", uv_strerror(ret));
        ret = ASTERISM_E_SOCKET_LISTEN_ERROR;
        goto cleanup;
    }
cleanup:
    if (ret != 0)
    {
        AS_FREE(obj);
        obj = 0;
    }
    return obj;
}

static void incoming_delete(struct asterism_http_incoming_s *obj)
{
    if (obj->http_connect_buffer.base)
        AS_FREE(obj->http_connect_buffer.base);
    if (obj->remote_host)
        AS_FREE(obj->remote_host);
    if (obj->username)
        AS_FREE(obj->username);
    if (obj->password)
        AS_FREE(obj->password);
    AS_FREE(obj);
}

static void incoming_close_cb(
    uv_handle_t *handle)
{
    int ret = 0;
    struct asterism_http_incoming_s *obj = (struct asterism_http_incoming_s *)handle;
    incoming_delete(obj);
    asterism_log(ASTERISM_LOG_DEBUG, "http connection is closing");
}

static void incoming_close(
    struct asterism_http_incoming_s *obj)
{
    if (obj && !uv_is_closing((uv_handle_t *)&obj->socket))
        uv_close((uv_handle_t *)&obj->socket, incoming_close_cb);
}

static void incoming_data_read_alloc_cb(
    uv_handle_t *handle,
    size_t suggested_size,
    uv_buf_t *buf)
{
    struct asterism_http_incoming_s *incoming = (struct asterism_http_incoming_s *)handle;
    if (incoming->tunnel_connected)
    {
        buf->len = ASTERISM_TCP_BLOCK_SIZE;
        buf->base = (char *)AS_MALLOC(ASTERISM_TCP_BLOCK_SIZE);
    }
    else
    {
        if (!incoming->http_connect_buffer.base)
        {
            if (incoming->header_parsed)
            {
                incoming_close(incoming);
                return;
            }
            buf->len = ASTERISM_MAX_HTTP_HEADER_SIZE;
            buf->base = (char *)AS_MALLOC(ASTERISM_MAX_HTTP_HEADER_SIZE);
            incoming->http_connect_buffer = *buf;
        }
        else
        {
            buf->len = ASTERISM_MAX_HTTP_HEADER_SIZE - incoming->http_connect_buffer_read;
            buf->base = incoming->http_connect_buffer.base + incoming->http_connect_buffer_read;
        }
    }
}

static int on_url(http_parser *parser, const char *at, size_t length)
{
    struct asterism_http_incoming_s *obj = __container_ptr(struct asterism_http_incoming_s, parser, parser);
    if (obj->connect_host.p)
    {
        obj->connect_host.len += length;
    }
    else
    {
        obj->connect_host.p = at;
        obj->connect_host.len += length;
    }
    return 0;
}

static int on_header_field(http_parser *parser, const char *at, size_t length)
{
    struct asterism_http_incoming_s *obj = __container_ptr(struct asterism_http_incoming_s, parser, parser);
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
        if (obj->header_auth_parsed)
        {
            obj->auth_info = obj->http_header_value_temp;
            obj->header_auth_parsed = 0;
        }
        asterism_log(ASTERISM_LOG_DEBUG, "on_header_value %.*s", obj->http_header_value_temp.len, obj->http_header_value_temp.p);
        obj->http_header_value_temp.p = 0;
        obj->http_header_value_temp.len = 0;
    }
    return 0;
}

static int on_header_value(http_parser *parser, const char *at, size_t length)
{
    struct asterism_http_incoming_s *obj = __container_ptr(struct asterism_http_incoming_s, parser, parser);
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
        if (asterism_vcmp(&obj->http_header_field_temp, "Proxy-Authorization") == 0)
        {
            obj->header_auth_parsed = 1;
        }
        asterism_log(ASTERISM_LOG_DEBUG, "on_header_field %.*s", obj->http_header_field_temp.len, obj->http_header_field_temp.p);
        obj->http_header_field_temp.p = 0;
        obj->http_header_field_temp.len = 0;
    }
    return 0;
}

static int on_message_complete(http_parser *parser)
{
    struct asterism_http_incoming_s *obj = __container_ptr(struct asterism_http_incoming_s, parser, parser);
    obj->header_parsed = 1;
    if (obj->http_header_value_temp.p)
    {
        if (obj->header_auth_parsed)
        {
            obj->auth_info = obj->http_header_value_temp;
            obj->header_auth_parsed = 0;
        }
        asterism_log(ASTERISM_LOG_DEBUG, "on_header_value %.*s", obj->http_header_value_temp.len, obj->http_header_value_temp.p);
        obj->http_header_value_temp.p = 0;
        obj->http_header_value_temp.len = 0;
    }
    if (obj->connect_host.p)
    {
        asterism_log(ASTERISM_LOG_DEBUG, "on_url %.*s", obj->connect_host.len, obj->connect_host.p);
    }
    return 0;
}

static http_parser_settings parser_settings = {
    0,
    on_url,
    0,
    on_header_field,
    on_header_value,
    0,
    0,
    on_message_complete,
    0,
    0};

static void incoming_shutdown_cb(
    uv_shutdown_t *req,
    int status)
{
    struct asterism_http_incoming_s *incoming = (struct asterism_http_incoming_s *)req->data;
    if (status != 0)
    {
        goto cleanup;
    }
    incoming->fin_send = 1;
    if (incoming->fin_recv)
    {
        incoming_close(incoming);
    }
cleanup:
    if (status != 0)
    {
        incoming_close(incoming);
    }
    AS_FREE(req);
}

static int incoming_end(
    struct asterism_http_incoming_s *incoming)
{
    int ret = 0;
    uv_shutdown_t *req = 0;
    //////////////////////////////////////////////////////////////////////////
    req = __zero_malloc_st(uv_shutdown_t);
    req->data = incoming;
    ret = uv_shutdown(req, (uv_stream_t *)&incoming->socket, incoming_shutdown_cb);
    if (ret != 0)
        goto cleanup;
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

static void incoming_read_cb(
    uv_stream_t *stream,
    ssize_t nread,
    const uv_buf_t *buf)
{
    struct asterism_http_incoming_s *incoming = (struct asterism_http_incoming_s *)stream;
    if (nread > 0)
    {
        if (incoming->tunnel_connected)
        {
            //transport
        }
        else
        {
            incoming->http_connect_buffer_read += (unsigned int)nread;
            size_t nparsed = http_parser_execute(&incoming->parser, &parser_settings, buf->base, nread);
            if (incoming->parser.http_errno != 0)
            {
                asterism_log(ASTERISM_LOG_DEBUG, "%s", http_errno_description((enum http_errno)incoming->parser.http_errno));
                incoming_close(incoming);
                goto cleanup;
            }
            if (nparsed != nread)
            {
                incoming_close(incoming);
                goto cleanup;
            }
            if (!incoming->header_parsed &&
                incoming->http_connect_buffer_read == ASTERISM_MAX_HTTP_HEADER_SIZE)
            {
                incoming_close(incoming);
                goto cleanup;
            }
            if (incoming->header_parsed)
            {
                if (incoming->parser.method != HTTP_CONNECT)
                {
                    incoming_close(incoming);
                    goto cleanup;
                }
                if (!incoming->connect_host.len)
                {
                    incoming_close(incoming);
                    goto cleanup;
                }
                if (!incoming->auth_info.len)
                {
                    incoming_close(incoming);
                    goto cleanup;
                }
                incoming->remote_host = (char *)asterism_strdup_nul(incoming->connect_host).p;
                struct asterism_str base_prefix = asterism_mk_str("Basic ");
                if (asterism_strncmp(incoming->auth_info, base_prefix, base_prefix.len) != 0)
                {
                    incoming_close(incoming);
                    goto cleanup;
                }
                char decode_buffer[128] = {0};
                int deocode_size = sizeof(decode_buffer);
                int parsed = asterism_base64_decode(
                    (const unsigned char *)incoming->auth_info.p + base_prefix.len,
                    (int)(incoming->auth_info.len - base_prefix.len),
                    decode_buffer,
                    &deocode_size);
                if (parsed != incoming->auth_info.len - base_prefix.len)
                {
                    incoming_close(incoming);
                    goto cleanup;
                }
                char *split_pos = strchr(decode_buffer, ':');
                if (!split_pos)
                {
                    incoming_close(incoming);
                    goto cleanup;
                }
                *split_pos = 0;
                incoming->username = as_strdup(decode_buffer);
                incoming->password = as_strdup(split_pos + 1);
                asterism_log(ASTERISM_LOG_DEBUG, "username: %s , password: %s", incoming->username, incoming->password);
                asterism_log(ASTERISM_LOG_DEBUG, "header_parsed");
            }
        }
        goto cleanup;
    }
    else if (nread == 0)
    {
        goto cleanup;
    }
    else if (nread == UV_EOF)
    {
        incoming->fin_recv = 1;
        if (incoming->fin_send)
        {
            incoming_close(incoming);
        }
        else
        {
            incoming_end(incoming);
        }
        goto cleanup;
    }
    else
    {
        asterism_log(ASTERISM_LOG_DEBUG, "%s", uv_strerror((int)nread));
        incoming_close(incoming);
    }
cleanup:
    if (buf && buf->base)
        AS_FREE(buf->base);
}

static void inner_accept_cb(
    uv_stream_t *stream,
    int status)
{
    int ret = ASTERISM_E_OK;
    asterism_log(ASTERISM_LOG_DEBUG, "new http connection is comming");

    struct asterism_http_inner_s *inner = (struct asterism_http_inner_s *)stream;
    struct asterism_http_incoming_s *incoming = 0;
    if (status != 0)
    {
        goto cleanup;
    }
    incoming = incoming_new(inner->as);
    if (!incoming)
    {
        goto cleanup;
    }
    http_parser_init(&incoming->parser, HTTP_REQUEST);

    ret = uv_tcp_nodelay(&incoming->socket, 1);
    if (ret != 0)
    {
        ret = ASTERISM_E_FAILED;
        goto cleanup;
    }
    ret = uv_accept((uv_stream_t *)&inner->socket, (uv_stream_t *)&incoming->socket);
    if (ret != 0)
    {
        ret = ASTERISM_E_FAILED;
        goto cleanup;
    }
    ret = uv_read_start((uv_stream_t *)&incoming->socket, incoming_data_read_alloc_cb, incoming_read_cb);
    if (ret != 0)
    {
        ret = ASTERISM_E_FAILED;
        goto cleanup;
    }
cleanup:
    if (ret != 0)
    {
        incoming_close(incoming);
    }
}

int asterism_inner_http_init(
    struct asterism_s *as,
    const char *ip, unsigned int *port, int ipv6)
{
    int ret = ASTERISM_E_OK;
    void *addr = 0;
    int name_len = 0;
    struct asterism_http_inner_s *inner = inner_new(as);
    if (!inner)
    {
        goto cleanup;
    }

    if (ipv6)
    {
        addr = __zero_malloc_st(struct sockaddr_in6);
        name_len = sizeof(struct sockaddr_in6);
        ret = uv_ip6_addr(ip, (int)*port, (struct sockaddr_in6 *)addr);
    }
    else
    {
        addr = __zero_malloc_st(struct sockaddr_in);
        name_len = sizeof(struct sockaddr_in);
        ret = uv_ip4_addr(ip, (int)*port, (struct sockaddr_in *)addr);
    }
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
    ret = uv_tcp_nodelay(&inner->socket, 1);
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
    if (ipv6)
    {
        *port = ntohs(((struct sockaddr_in6 *)addr)->sin6_port);
    }
    else
    {
        *port = ntohs(((struct sockaddr_in *)addr)->sin_port);
    }

    ret = uv_listen((uv_stream_t *)&inner->socket, ASTERISM_NET_BACKLOG, inner_accept_cb);
    if (ret != 0)
    {
        asterism_log(ASTERISM_LOG_DEBUG, "%s", uv_strerror(ret));
        ret = ASTERISM_E_SOCKET_LISTEN_ERROR;
        goto cleanup;
    }
cleanup:
    if (ret)
    {
        inner_close(inner);
    }
    return ret;
}