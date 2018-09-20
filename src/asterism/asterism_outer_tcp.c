#include "asterism_outer_tcp.h"
#include "asterism_core.h"
#include "asterism_utils.h"
#include "asterism_log.h"

static struct asterism_tcp_outer_s *outer_new(struct asterism_s *as)
{
	struct asterism_tcp_outer_s *obj = __zero_malloc_st(struct asterism_tcp_outer_s);
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
		free(obj);
		obj = 0;
	}
	return obj;
}

static void outer_delete(struct asterism_tcp_outer_s *obj)
{
	free(obj);
}

static void outer_close_cb(
	uv_handle_t *handle)
{
	struct asterism_tcp_outer_s *obj = (struct asterism_tcp_outer_s *)handle;
	outer_delete(obj);
}

static void outer_close(
	struct asterism_tcp_outer_s *obj)
{
	if (obj && !uv_is_closing((uv_handle_t *)&obj->socket))
		uv_close((uv_handle_t *)&obj->socket, outer_close_cb);
}

static struct asterism_tcp_incoming_s *incoming_new(struct asterism_s *as)
{
	struct asterism_tcp_incoming_s *obj = __zero_malloc_st(struct asterism_tcp_incoming_s);
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
		free(obj);
		obj = 0;
	}
	return obj;
}

static void incoming_delete(struct asterism_tcp_incoming_s *obj)
{
	free(obj);
}

static void incoming_close_cb(
	uv_handle_t *handle)
{
	int ret = 0;
	struct asterism_tcp_incoming_s *obj = (struct asterism_tcp_incoming_s *)handle;
	incoming_delete(obj);
	asterism_log(ASTERISM_LOG_DEBUG, "tcp connection is closing");
}

static void incoming_close(
	struct asterism_tcp_incoming_s *obj)
{
	if (obj && !uv_is_closing((uv_handle_t *)&obj->socket))
		uv_close((uv_handle_t *)&obj->socket, incoming_close_cb);
}

static void incoming_data_read_alloc_cb(
	uv_handle_t *handle,
	size_t suggested_size,
	uv_buf_t *buf)
{
	struct asterism_tcp_incoming_s *incoming = (struct asterism_tcp_incoming_s *)handle;
	buf->base = (char*)malloc(ASTERISM_TCP_BLOCK_SIZE);
	buf->len = ASTERISM_TCP_BLOCK_SIZE;
}

static void incoming_shutdown_cb(
	uv_shutdown_t *req,
	int status)
{
	struct asterism_tcp_incoming_s *incoming = (struct asterism_tcp_incoming_s *)req->data;
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
	free(req);
}

static int incoming_end(
	struct asterism_tcp_incoming_s *incoming)
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
			free(req);
		}
	}
	return ret;
}

static void incoming_read_cb(
	uv_stream_t *stream,
	ssize_t nread,
	const uv_buf_t *buf)
{
	struct asterism_tcp_incoming_s *incoming = (struct asterism_tcp_incoming_s *)stream;
	if (nread > 0)
	{
		free(buf->base);
		return;
	}
	else if (nread == 0)
	{
		return;
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
		return;
	}
	else
	{
		asterism_log(ASTERISM_LOG_DEBUG, "%s", uv_strerror((int)nread));
		goto error;
	}
error:
	incoming_close(incoming);
	return;
}

static void outer_accept_cb(
	uv_stream_t *stream,
	int status)
{
	int ret = ASTERISM_E_OK;
	asterism_log(ASTERISM_LOG_DEBUG, "new tcp connection is comming");

	struct asterism_tcp_outer_s *outer = (struct asterism_tcp_outer_s *)stream;
	struct asterism_tcp_incoming_s *incoming = 0;
	if (status != 0)
	{
		goto cleanup;
	}
	incoming = incoming_new(outer->as);
	if (!incoming)
	{
		incoming_delete(incoming);
		goto cleanup;
	}

	ret = uv_tcp_nodelay(&incoming->socket, 1);
	if (ret != 0)
	{
		ret = ASTERISM_E_FAILED;
		goto cleanup;
	}
	ret = uv_accept((uv_stream_t *)&outer->socket, (uv_stream_t *)&incoming->socket);
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

int asterism_outer_tcp_init(
	struct asterism_s *as,
	const char *ip, unsigned int *port, int ipv6)
{

	int ret = ASTERISM_E_OK;
	void *addr = 0;
	int name_len = 0;
	struct asterism_tcp_outer_s *outer = outer_new(as);
	if (!outer)
	{
		outer_delete(outer);
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
	ret = uv_tcp_bind(&outer->socket, (const struct sockaddr *)addr, 0);
	if (ret != 0)
	{
		asterism_log(ASTERISM_LOG_DEBUG, "%s", uv_strerror(ret));
		ret = ASTERISM_E_SOCKET_LISTEN_ERROR;
		goto cleanup;
	}
	ret = uv_tcp_nodelay(&outer->socket, 1);
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
	if (ipv6)
	{
		*port = ntohs(((struct sockaddr_in6 *)addr)->sin6_port);
	}
	else
	{
		*port = ntohs(((struct sockaddr_in *)addr)->sin_port);
	}

	ret = uv_listen((uv_stream_t *)&outer->socket, ASTERISM_NET_BACKLOG, outer_accept_cb);
	if (ret != 0)
	{
		asterism_log(ASTERISM_LOG_DEBUG, "%s", uv_strerror(ret));
		ret = ASTERISM_E_SOCKET_LISTEN_ERROR;
		goto cleanup;
	}
cleanup:
	if (ret)
	{
		outer_close(outer);
	}
	return ret;
}

int asterism_outer_tcp_connect_addr(struct asterism_s *as)
{
	int ret = ASTERISM_E_OK;
	//cleanup:
	return ret;
}