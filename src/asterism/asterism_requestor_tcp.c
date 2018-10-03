#include "asterism_requestor_tcp.h"
#include "asterism_core.h"
#include "asterism_utils.h"
#include "asterism_log.h"


static struct asterism_tcp_requestor_s *requestor_new(struct asterism_s *as)
{
	struct asterism_tcp_requestor_s *obj = __zero_malloc_st(struct asterism_tcp_requestor_s);
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

static void requestor_delete(struct asterism_tcp_requestor_s *obj)
{
	AS_FREE(obj);
}

static void requestor_close_cb(
	uv_handle_t *handle)
{
	int ret = 0;
	struct asterism_tcp_requestor_s *obj = (struct asterism_tcp_requestor_s *)handle;
	requestor_delete(obj);
	asterism_log(ASTERISM_LOG_DEBUG, "tcp connection is closing");
}

static void requestor_close(
	struct asterism_tcp_requestor_s *obj)
{
	if (obj && !uv_is_closing((uv_handle_t *)&obj->socket))
		uv_close((uv_handle_t *)&obj->socket, requestor_close_cb);
}

static void requestor_data_read_alloc_cb(
	uv_handle_t *handle,
	size_t suggested_size,
	uv_buf_t *buf)
{
	struct asterism_tcp_requestor_s *requestor = (struct asterism_tcp_requestor_s *)handle;
	buf->base = requestor->buffer;
	buf->len = ASTERISM_TCP_BLOCK_SIZE;

	// 	buf->len = ASTERISM_TCP_BLOCK_SIZE;
	// 	buf->base = incoming->tunnel->inner_buffer;
	// 	incoming->tunnel->inner_buffer_len = 0;
}

static void requestor_shutdown_cb(
	uv_shutdown_t *req,
	int status)
{
	struct asterism_tcp_requestor_s *requestor = (struct asterism_tcp_requestor_s *)req->data;
	if (status != 0)
	{
		goto cleanup;
	}
	requestor->fin_send = 1;
	if (requestor->fin_recv)
	{
		requestor_close(requestor);
	}
cleanup:
	if (status != 0)
	{
		requestor_close(requestor);
	}
	AS_FREE(req);
}

static int requestor_end(
	struct asterism_tcp_requestor_s *requestor)
{
	int ret = 0;
	uv_shutdown_t *req = 0;
	//////////////////////////////////////////////////////////////////////////
	req = __zero_malloc_st(uv_shutdown_t);
	req->data = requestor;
	ret = uv_shutdown(req, (uv_stream_t *)&requestor->socket, requestor_shutdown_cb);
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

static void requestor_read_cb(
	uv_stream_t *stream,
	ssize_t nread,
	const uv_buf_t *buf)
{
	struct asterism_tcp_requestor_s *requestor = (struct asterism_tcp_requestor_s *)stream;
	if (nread > 0)
	{
	}
	else if (nread == 0)
	{
		return;
	}
	else if (nread == UV_EOF)
	{
		requestor->fin_recv = 1;
		if (requestor->fin_send)
		{
			requestor_close(requestor);
		}
		else
		{
			requestor_end(requestor);
		}
	}
	else
	{
		asterism_log(ASTERISM_LOG_DEBUG, "%s", uv_strerror((int)nread));
		requestor_close(requestor);
	}
}

static void requestor_connected(
	uv_connect_t *req,
	int status)
{
	int ret = 0;
	struct asterism_tcp_requestor_s *requestor = (struct asterism_tcp_requestor_s *)req->data;
	if (status < 0)
	{
		ret = ASTERISM_E_FAILED;
		goto cleanup;
	}
	ret = uv_read_start((uv_stream_t *)&requestor->socket, requestor_data_read_alloc_cb, requestor_read_cb);
	if (ret != 0)
	{
		ret = ASTERISM_E_FAILED;
		goto cleanup;
	}

cleanup:
	if (ret != 0)
	{
		requestor_close(requestor);
	}
	if (req)
		AS_FREE(req);
}

static void requestor_getaddrinfo(
	uv_getaddrinfo_t *req,
	int status,
	struct addrinfo *res)
{
	int ret = ASTERISM_E_OK;
	uv_connect_t *connect_req = 0;
	struct asterism_tcp_requestor_s *requestor = (struct asterism_tcp_requestor_s *)req->data;
	char addr[17] = { '\0' };
	if (status < 0)
	{
		goto cleanup;
	}
	//only support ipv4
	ret = uv_ip4_name((struct sockaddr_in *)res->ai_addr, addr, 16);
	if (ret != 0)
	{
		goto cleanup;
	}
	connect_req = (uv_connect_t *)AS_MALLOC(sizeof(uv_connect_t));
	connect_req->data = requestor;
	ret = uv_tcp_connect(connect_req, &requestor->socket, res->ai_addr, requestor_connected);
	if (ret != 0)
	{
		goto cleanup;
	}
cleanup:
	if (ret != 0)
		requestor_close(requestor);
	if (res)
		uv_freeaddrinfo(res);
	if (req)
		AS_FREE(req);
}

int asterism_requestor_tcp_init(struct asterism_s *as,
	const char *host, unsigned int port, struct asterism_stream_s* stream)
{
	int ret = ASTERISM_E_OK;
	struct addrinfo hints;
	uv_getaddrinfo_t *addr_info = 0;

	struct asterism_tcp_requestor_s *requestor = requestor_new(as);
	if (!requestor)
	{
		ret = ASTERISM_E_FAILED;
		goto cleanup;
	}
	addr_info = (uv_getaddrinfo_t *)AS_MALLOC(sizeof(uv_getaddrinfo_t));
	addr_info->data = requestor;
	hints.ai_family = PF_INET;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_protocol = IPPROTO_TCP;
	hints.ai_flags = 0;

	char port_str[10] = { 0 };
	asterism_itoa(port_str, sizeof(port_str), port, 10, 0, 0);
	ret = uv_getaddrinfo(as->loop, addr_info, requestor_getaddrinfo, host, port_str, &hints);
	if (ret != 0)
	{
		ret = ASTERISM_E_FAILED;
		goto cleanup;
	}
	requestor->link = stream;
	stream->link = requestor;
cleanup:
	if (ret)
	{
		if (addr_info)
			AS_FREE(addr_info);
		requestor_close(requestor);
	}
	return ret;
}
