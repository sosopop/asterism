#include "asterism_connector_tcp.h"
#include "asterism_core.h"
#include "asterism_utils.h"
#include "asterism_log.h"

static struct asterism_tcp_connector_s *connector_new(struct asterism_s *as)
{
	struct asterism_tcp_connector_s *obj = __zero_malloc_st(struct asterism_tcp_connector_s);
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

static void connector_delete(struct asterism_tcp_connector_s *obj)
{
	AS_FREE(obj);
}

static void connector_close_cb(
	uv_handle_t *handle)
{
	int ret = 0;
	struct asterism_tcp_connector_s *obj = (struct asterism_tcp_connector_s *)handle;
	connector_delete(obj);
	asterism_log(ASTERISM_LOG_DEBUG, "tcp connection is closing");
}

static void connector_close(
	struct asterism_tcp_connector_s *obj)
{
	if (obj && !uv_is_closing((uv_handle_t *)&obj->socket))
		uv_close((uv_handle_t *)&obj->socket, connector_close_cb);
}

static void connector_data_read_alloc_cb(
	uv_handle_t *handle,
	size_t suggested_size,
	uv_buf_t *buf)
{
	struct asterism_tcp_connector_s *connector = (struct asterism_tcp_connector_s *)handle;
	buf->base = (char *)AS_MALLOC(ASTERISM_TCP_BLOCK_SIZE);
	buf->len = ASTERISM_TCP_BLOCK_SIZE;
}

static void connector_shutdown_cb(
	uv_shutdown_t *req,
	int status)
{
	struct asterism_tcp_connector_s *connector = (struct asterism_tcp_connector_s *)req->data;
	if (status != 0)
	{
		goto cleanup;
	}
	connector->fin_send = 1;
	if (connector->fin_recv)
	{
		connector_close(connector);
	}
cleanup:
	if (status != 0)
	{
		connector_close(connector);
	}
	AS_FREE(req);
}

static int connector_end(
	struct asterism_tcp_connector_s *connector)
{
	int ret = 0;
	uv_shutdown_t *req = 0;
	//////////////////////////////////////////////////////////////////////////
	req = __zero_malloc_st(uv_shutdown_t);
	req->data = connector;
	ret = uv_shutdown(req, (uv_stream_t *)&connector->socket, connector_shutdown_cb);
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

static void connector_read_cb(
	uv_stream_t *stream,
	ssize_t nread,
	const uv_buf_t *buf)
{
	struct asterism_tcp_connector_s *connector = (struct asterism_tcp_connector_s *)stream;
	if (nread > 0)
	{
		goto cleanup;
	}
	else if (nread == 0)
	{
		goto cleanup;
	}
	else if (nread == UV_EOF)
	{
		connector->fin_recv = 1;
		if (connector->fin_send)
		{
			connector_close(connector);
		}
		else
		{
			connector_end(connector);
		}
		goto cleanup;
	}
	else
	{
		asterism_log(ASTERISM_LOG_DEBUG, "%s", uv_strerror((int)nread));
		connector_close(connector);
	}
cleanup:
	if (buf && buf->base)
		AS_FREE(buf->base);
}

static void connector_connected(
	uv_connect_t *req,
	int status)
{
	int ret = 0;
	struct asterism_tcp_connector_s *connector = (struct asterism_tcp_connector_s *)req->data;
	if (status < 0)
	{
		ret = ASTERISM_E_FAILED;
		goto cleanup;
	}
	ret = uv_read_start((uv_stream_t *)&connector->socket, connector_data_read_alloc_cb, connector_read_cb);
	if (ret != 0)
	{
		ret = ASTERISM_E_FAILED;
		goto cleanup;
	}
cleanup:
	if (ret != 0)
	{
		connector_close(connector);
	}
	if (req)
		AS_FREE(req);
}

static void connector_getaddrinfo(
	uv_getaddrinfo_t *req,
	int status,
	struct addrinfo *res)
{
	int ret = ASTERISM_E_OK;
	uv_connect_t *connect_req = 0;
	struct asterism_tcp_connector_s *connector = (struct asterism_tcp_connector_s *)req->data;
	char addr[17] = {'\0'};
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
	connect_req->data = connector;
	ret = uv_tcp_connect(connect_req, &connector->socket, res->ai_addr, connector_connected);
	if (ret != 0)
	{
		goto cleanup;
	}
cleanup:
	if (ret != 0)
		connector_close(connector);
	if (res)
		uv_freeaddrinfo(res);
	if (req)
		AS_FREE(req);
}

int asterism_connector_tcp_init(struct asterism_s *as,
								const char *host, unsigned int port)
{
	int ret = ASTERISM_E_OK;
	struct addrinfo hints;
	uv_getaddrinfo_t *addr_info = 0;

	struct asterism_tcp_connector_s *connector = connector_new(as);
	if (!connector)
	{
		ret = ASTERISM_E_FAILED;
		goto cleanup;
	}
	addr_info = (uv_getaddrinfo_t *)AS_MALLOC(sizeof(uv_getaddrinfo_t));
	addr_info->data = connector;
	hints.ai_family = PF_INET;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_protocol = IPPROTO_TCP;
	hints.ai_flags = 0;

	char port_str[10] = {0};
	asterism_itoa(port_str, sizeof(port_str), port, 10, 0, 0);
	ret = uv_getaddrinfo(as->loop, addr_info, connector_getaddrinfo, host, port_str, &hints);
	if (ret != 0)
	{
		ret = ASTERISM_E_FAILED;
		goto cleanup;
	}
cleanup:
	if (ret)
	{
		if (addr_info)
			AS_FREE(addr_info);
		connector_close(connector);
	}
	return ret;
}