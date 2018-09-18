#include <http_parser.h>
#include "asterism_inner_http.h"
#include "asterism_core.h"
#include "asterism_log.h"
#include "asterism_utils.h"

static struct asterism_http_inner *inner_new(struct asterism_s *as)
{
    struct asterism_http_inner *inner = __zero_malloc_st(struct asterism_http_inner);
    inner->socket = __zero_malloc_st(uv_tcp_t);
	inner->socket->data = inner;
    return inner;
}

static void inner_delete(struct asterism_http_inner *inner)
{
    free(inner->socket);
    free(inner);
}

static void inner_close_cb(
	uv_handle_t *handle)
{
	int ret = 0;
	struct asterism_http_inner *inner = (struct asterism_http_inner *)handle->data;
	inner_delete(inner);
}

void inner_close(
    struct asterism_http_inner *inner)
{
    if (!uv_is_closing((uv_handle_t *)inner->socket))
        uv_close((uv_handle_t *)inner->socket, inner_close_cb);
}

static void incoming_delete(struct asterism_http_incoming *incoming)
{
	free(incoming->socket);
	free(incoming);
}

static void incoming_close_cb(
	uv_handle_t *handle)
{
	int ret = 0;
	struct asterism_http_incoming* incoming = (struct asterism_http_incoming *)handle->data;
	incoming_delete(incoming);
}

void incoming_close(
	struct asterism_http_incoming* incoming
)
{
	if (!uv_is_closing((uv_handle_t *)incoming->socket))
		uv_close((uv_handle_t *)incoming->socket, incoming_close_cb);
}


static void incoming_data_read_alloc_cb(
	uv_handle_t* handle,
	size_t suggested_size,
	uv_buf_t* buf
)
{
	struct asterism_http_incoming* incoming = (struct asterism_http_incoming *)handle->data;
	//buf->base = net->read_buffer;
	//buf->len = sizeof(net->read_buffer);
}

static void net_data_read_cb(
	uv_stream_t* stream,
	ssize_t nread,
	const uv_buf_t* buf
)
{
	struct asterism_http_incoming* incoming = (struct asterism_http_incoming *)stream->data;
	if (nread > 0) {
		//net->read_cb(net, buf->base, nread, net->user_data);
		return;
	}
	else if (nread == 0) {
		return;
	}
	else if (nread == UV_EOF) {
		/*
		net->fin_recv = 1;
		net->end_cb(net, net->user_data);
		hdtrans_net_end(net);
		if (net->fin_send) {
			hdtrans_net_close(net);
		}*/
		return;
	}
	else {
		asterism_log(ASTERISM_LOG_DEBUG, "%s", uv_strerror((int)nread));
		goto error;
	}
error:
	incoming_close(incoming);
	return;
}

static void accept_cb(
    uv_stream_t *stream,
    int status)
{
    int ret = ASTERISM_E_OK;
    asterism_log(ASTERISM_LOG_DEBUG, "new connection is comming");

	struct asterism_http_inner *inner = (struct asterism_http_inner *)stream->data;

	struct asterism_http_incoming *incoming = 0;

	if (status != 0) {
		//inner_close(inner);
		goto cleanup;
	}

	incoming = __zero_malloc_st(struct asterism_http_incoming);
	incoming->socket = __zero_malloc_st(uv_tcp_t);
	incoming->socket->data = incoming;

	ret = uv_tcp_init(inner->socket->loop, incoming->socket);
	if (ret != 0) {
		ret = ASTERISM_E_FAILED;
		goto cleanup;
	}
	ret = uv_tcp_nodelay(incoming->socket, 1);
	if (ret != 0) {
		ret = ASTERISM_E_FAILED;
		goto cleanup;
	}
	ret = uv_accept((uv_stream_t*)inner->socket, (uv_stream_t*)incoming->socket);
	if (ret != 0) {
		ret = ASTERISM_E_FAILED;
		goto cleanup;
	}
	ret = uv_read_start((uv_stream_t*)incoming->socket, incoming_data_read_alloc_cb, net_data_read_cb);
	if (ret != 0) {
		ret = ASTERISM_E_FAILED;
		goto cleanup;
	}
cleanup:
    if (ret != 0)
    {
		if (incoming)
		{
			if (incoming->socket->loop) {
				incoming_close(incoming);
			}
			else {
				incoming_delete(incoming);
			}
		}
    }
}

int asterism_inner_http_init(
    struct asterism_s *as,
    const char *ip, unsigned int *port, int ipv6)
{
    int ret = ASTERISM_E_OK;
    struct asterism_http_inner *inner = inner_new(as);
    void *addr = 0;
    int name_len = 0;

    ret = uv_tcp_init(as->loop, inner->socket);
    if (ret != 0)
    {
        asterism_log(ASTERISM_LOG_DEBUG, "%s", uv_strerror(ret));
        ret = ASTERISM_E_SOCKET_LISTEN_ERROR;
        goto cleanup;
    }
    if (ipv6)
    {
        addr = __zero_malloc_st(struct sockaddr_in6);
        name_len = sizeof(struct sockaddr_in6);
        ret = uv_ip6_addr(ip, (int)*port, addr);
    }
    else
    {
        addr = __zero_malloc_st(struct sockaddr_in);
        name_len = sizeof(struct sockaddr_in);
        ret = uv_ip4_addr(ip, (int)*port, addr);
    }
    if (ret != 0)
    {
        asterism_log(ASTERISM_LOG_DEBUG, "%s", uv_strerror(ret));
        ret = ASTERISM_E_SOCKET_LISTEN_ERROR;
        goto cleanup;
    }
    ret = uv_tcp_bind(inner->socket, (const struct sockaddr *)addr, 0);
    if (ret != 0)
    {
        asterism_log(ASTERISM_LOG_DEBUG, "%s", uv_strerror(ret));
        ret = ASTERISM_E_SOCKET_LISTEN_ERROR;
        goto cleanup;
    }
    ret = uv_tcp_nodelay(inner->socket, 1);
    if (ret != 0)
    {
        asterism_log(ASTERISM_LOG_DEBUG, "%s", uv_strerror(ret));
        ret = ASTERISM_E_SOCKET_LISTEN_ERROR;
        goto cleanup;
    }
    ret = uv_tcp_getsockname(inner->socket, (struct sockaddr *)addr, &name_len);
    if (ret != 0)
    {
        asterism_log(ASTERISM_LOG_DEBUG, "%s", uv_strerror(ret));
        ret = ASTERISM_E_SOCKET_LISTEN_ERROR;
        goto cleanup;
    }
    if (ipv6)
    {
        *port = ntohs(((struct sockaddr_in6*)addr)->sin6_port);
    }
    else
    {
        *port = ntohs(((struct sockaddr_in*)addr)->sin_port);
    }

    ret = uv_listen((uv_stream_t *)inner->socket, ASTERISM_NET_BACKLOG, accept_cb);
    if (ret != 0)
    {
        asterism_log(ASTERISM_LOG_DEBUG, "%s", uv_strerror(ret));
        ret = ASTERISM_E_SOCKET_LISTEN_ERROR;
        goto cleanup;
    }
cleanup:
    if (ret)
    {
        if (inner->socket->loop)
        {
            inner_close(inner);
        }
        else
        {
            inner_delete(inner);
        }
    }
    return ret;
}