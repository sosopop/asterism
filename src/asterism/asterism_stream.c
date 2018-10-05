#include "asterism_stream.h"
#include "asterism_utils.h"
#include "asterism_log.h"


static void stream_shutdown_cb(
	uv_shutdown_t *req,
	int status)
{
	struct asterism_stream_s *stream = (struct asterism_stream_s *)req->data;
	if (status != 0)
	{
		goto cleanup;
	}
	stream->fin_send = 1;
	if (stream->fin_recv)
	{
		asterism_stream_close(stream);
	}
cleanup:
	if (status != 0)
	{
		asterism_stream_close(stream);
	}
	AS_FREE(req);
}

static int stream_end(
	struct asterism_stream_s *stream)
{
	int ret = 0;
	uv_shutdown_t *req = 0;
	//////////////////////////////////////////////////////////////////////////
	req = __zero_malloc_st(uv_shutdown_t);
	req->data = stream;
	ret = uv_shutdown(req, (uv_stream_t *)&stream->socket, stream_shutdown_cb);
	if (ret != 0) {
		asterism_log(ASTERISM_LOG_DEBUG, "%s", uv_strerror((int)ret));
		goto cleanup;
	}
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

static void stream_read_alloc_cb(
	uv_handle_t *handle,
	size_t suggested_size,
	uv_buf_t *buf)
{
	struct asterism_stream_s *stream = (struct asterism_stream_s *)handle->data;
	buf->base = stream->buffer + stream->buffer_len;
	buf->len = ASTERISM_MAX_PROTO_SIZE - stream->buffer_len;
}

static void stream_read_cb(
	uv_stream_t *stream,
	ssize_t nread,
	const uv_buf_t *buf)
{
	struct asterism_stream_s *stm = (struct asterism_stream_s *)stream;
	if (nread > 0)
	{
		uv_read_stop(stream);
		stm->read_cb(stream, nread, buf);
	}
	else if (nread == 0)
	{
		return;
	}
	else if (nread == UV_EOF)
	{
		stm->fin_recv = 1;
		if (stm->fin_send)
		{
			asterism_stream_close(stm);
		}
		else
		{
			stream_end(stm);
		}
	}
	else
	{
		asterism_log(ASTERISM_LOG_DEBUG, "%s", uv_strerror((int)nread));
		asterism_stream_close(stm);
	}
}

static void stream_connected(
	uv_connect_t *req,
	int status)
{
	int ret = 0;
	struct asterism_stream_s *stream = (struct asterism_stream_s *)req->data;
	if (status < 0)
	{
		ret = ASTERISM_E_FAILED;
		goto cleanup;
	}

	stream->connect_cb(req, status);

	ret = uv_read_start((uv_stream_t *)&stream->socket, stream_read_alloc_cb, stream_read_cb);
	if (ret != 0)
	{
		ret = ASTERISM_E_FAILED;
		goto cleanup;
	}

cleanup:
	if (ret != 0)
	{
		asterism_stream_close(stream);
	}
	if (req)
		AS_FREE(req);
}

static void stream_getaddrinfo(
	uv_getaddrinfo_t *req,
	int status,
	struct addrinfo *res)
{
	int ret = ASTERISM_E_OK;
	uv_connect_t *connect_req = 0;
	struct asterism_stream_s *stream = (struct asterism_stream_s *)req->data;
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
	connect_req->data = stream;
	ret = uv_tcp_connect(connect_req, &stream->socket, res->ai_addr, stream_connected);
	if (ret != 0)
	{
		goto cleanup;
	}
cleanup:
	if (ret != 0)
		asterism_stream_close(stream);
	if (res)
		uv_freeaddrinfo(res);
	if (req)
		AS_FREE(req);
}

static struct asterism_stream_s *stream_new(struct asterism_s *as)
{
	struct asterism_stream_s *stream = __zero_malloc_st(struct asterism_stream_s);
	stream->as = as;
	int ret = uv_tcp_init(as->loop, &stream->socket);
	if (ret != 0)
	{
		asterism_log(ASTERISM_LOG_DEBUG, "%s", uv_strerror(ret));
		goto cleanup;
	}
cleanup:
	if (ret != 0)
	{
		AS_FREE(stream);
		stream = 0;
	}
	return stream;
}

struct asterism_stream_s* asterism_stream_connect(
	struct asterism_s *as, 
	const char *host, 
	unsigned int port, 
	uv_connect_cb connect_cb,
	uv_close_cb close_cb,
	uv_read_cb read_cb
	)
{
	int ret = -1;
	struct asterism_stream_s *stream = stream_new(as);
	if (!stream)
	{
		goto cleanup;
	}
	stream->as = as;
	stream->connect_cb = connect_cb;
	stream->close_cb = close_cb;
	stream->read_cb = read_cb;

	struct addrinfo hints;
	uv_getaddrinfo_t *addr_info = 0;

	addr_info = (uv_getaddrinfo_t *)AS_MALLOC(sizeof(uv_getaddrinfo_t));
	addr_info->data = stream;
	hints.ai_family = PF_INET;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_protocol = IPPROTO_TCP;
	hints.ai_flags = 0;

	char port_str[10] = { 0 };
	asterism_itoa(port_str, sizeof(port_str), port, 10, 0, 0);
	ret = uv_getaddrinfo(as->loop, addr_info, stream_getaddrinfo, host, port_str, &hints);
	if (ret != 0)
	{
		asterism_log(ASTERISM_LOG_DEBUG, "%s", uv_strerror(ret));
		goto cleanup;
	}
	ret = 0;
cleanup:
	if (ret) {
		if (stream) {
			asterism_stream_close(stream);
		}
	}
	return stream;
}

struct asterism_stream_s* asterism_stream_accept(
	struct asterism_s *as,
	uv_close_cb close_cb,
	uv_read_cb read_cb
)
{
	int ret = -1;
	struct asterism_stream_s *stream = stream_new(as);
	if (!stream)
	{
		goto cleanup;
	}
	stream->close_cb = close_cb;
	stream->read_cb = read_cb;
	ret = uv_read_start((uv_stream_t *)&stream->socket, stream_read_alloc_cb, stream_read_cb);
	if (ret != 0)
	{
		asterism_log(ASTERISM_LOG_DEBUG, "%s", uv_strerror(ret));
		goto cleanup;
	}
cleanup:
	if (ret) {
		if (stream) {
			asterism_stream_close(stream);
		}
	}
	return stream;
}

int asterism_stream_read(
	struct asterism_stream_s* stream)
{
	int ret = -1;
	ret = uv_read_start((uv_stream_t *)&stream->socket, stream_read_alloc_cb, stream_read_cb);
	if (ret != 0)
	{
		asterism_log(ASTERISM_LOG_DEBUG, "%s", uv_strerror(ret));
		goto cleanup;
	}
cleanup:
	if (ret) {
		if (stream) {
			asterism_stream_close(stream);
		}
	}
	return ret;
}

static void stream_delete(struct asterism_stream_s *obj)
{
	AS_FREE(obj);
}

static void stream_close_cb(
	uv_handle_t *handle)
{
	int ret = 0;
	struct asterism_stream_s *obj = (struct asterism_stream_s *)handle;
	obj->close_cb((uv_handle_t *)obj);
	stream_delete(obj);
	asterism_log(ASTERISM_LOG_DEBUG, "tcp connection is closing");
}

void asterism_stream_close(
	struct asterism_stream_s* stream)
{
	if (stream && !uv_is_closing((uv_handle_t *)&stream->socket))
		uv_close((uv_handle_t *)&stream->socket, stream_close_cb);
}
