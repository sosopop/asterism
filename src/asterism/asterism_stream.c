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
	ret = uv_shutdown(req, (uv_stream_t *)stream, stream_shutdown_cb);
	if (ret != 0) {
		asterism_log(ASTERISM_LOG_DEBUG, "%s", uv_strerror((int)ret));
		goto cleanup;
	}
	asterism_log(ASTERISM_LOG_DEBUG, "recv end");
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
	struct asterism_stream_s *stream = (struct asterism_stream_s *)handle;
	if (stream->_alloc_cb) {
		stream->_alloc_cb(handle, suggested_size, buf);
	}
	else {
		buf->base = stream->buffer + stream->buffer_len;
		buf->len = ASTERISM_TCP_BLOCK_SIZE - stream->buffer_len;
		if (buf->len == 0) {
			asterism_stream_close(stream);
		}
	}
}

static void stream_read_cb(
	uv_stream_t *stream,
	ssize_t nread,
	const uv_buf_t *buf)
{
	struct asterism_stream_s *stm = (struct asterism_stream_s *)stream;
	if (nread > 0)
	{
		stm->buffer_len += (unsigned int)nread;
		if (stm->trans) {
			if (asterism_stream_trans(stm)) {
				asterism_stream_close(stm);
			}
		}
		else {
			stm->_read_cb(stream, nread, buf);
		}
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
		else {
			if (stm->trans)
			{
				if (stm->link) {
					stream_end(stm->link);
				}
				else {
					asterism_stream_close(stm);
				}
			}
			else
			{
				stream_end(stm);
			}
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

	stream->_connect_cb(req, status);
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
	ret = uv_tcp_connect(connect_req, (uv_tcp_t *)stream, res->ai_addr, stream_connected);
	if (ret != 0)
	{
		goto cleanup;
	}
cleanup:
	if (res)
		uv_freeaddrinfo(res);
	if (req)
		AS_FREE(req);
	if (ret != 0)
		asterism_stream_close(stream);
}

int asterism_stream_connect(
	struct asterism_s* as,
	const char *host,
	unsigned int port,
	uv_connect_cb connect_cb,
	uv_alloc_cb alloc_cb,
	uv_read_cb read_cb,
	uv_close_cb close_cb,
	asterism_stream_t* stream
	)
{
	stream->as = as;
	int ret = uv_tcp_init(as->loop, (uv_tcp_t *)stream);
	if (ret != 0)
	{
		asterism_log(ASTERISM_LOG_DEBUG, "%s", uv_strerror(ret));
		return ret;
	}
	asterism_log(ASTERISM_LOG_DEBUG, "tcp init %p", stream);

	stream->_connect_cb = connect_cb;
	stream->_close_cb = close_cb;
	stream->_read_cb = read_cb;
	stream->_alloc_cb = alloc_cb;

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
		asterism_safefree(addr_info);
	}
	return ret;
}

int asterism_stream_accept(
	struct asterism_s* as,
	uv_stream_t *server_stream,
	uv_alloc_cb alloc_cb,
	uv_read_cb read_cb,
	uv_close_cb close_cb,
	asterism_stream_t* stream
)
{
	stream->as = as;
	int ret = uv_tcp_init(as->loop, (uv_tcp_t *)stream);
	if (ret != 0)
	{
		asterism_log(ASTERISM_LOG_DEBUG, "%s", uv_strerror(ret));
		goto cleanup;
	}
	asterism_log(ASTERISM_LOG_DEBUG, "tcp init %p", stream);

	stream->_alloc_cb = alloc_cb;
	stream->_read_cb = read_cb;
	stream->_close_cb = close_cb;

	ret = uv_accept((uv_stream_t *)server_stream, (uv_stream_t *)stream);
	if (ret != 0)
	{
		ret = ASTERISM_E_FAILED;
		goto cleanup;
	}
cleanup:
	return ret;
}

int asterism_stream_read(
	struct asterism_stream_s* stream)
{
	int ret = uv_read_start((uv_stream_t *)stream, stream_read_alloc_cb, stream_read_cb);
	if (ret != 0)
	{
		asterism_log(ASTERISM_LOG_DEBUG, "%s", uv_strerror(ret));
		goto cleanup;
	}
cleanup:
	return ret;
}

static void stream_close_cb(
	uv_handle_t *handle)
{
	struct asterism_stream_s *stream = (struct asterism_stream_s *)handle;
	if (stream->link) {
		if (stream->trans) {
			asterism_stream_close(stream->link);
		}
		stream->link->link = 0;
	}
	stream->_close_cb((uv_handle_t *)stream);

	asterism_log(ASTERISM_LOG_DEBUG, "tcp connection is closing %p", handle);
}

void asterism_stream_close(
	struct asterism_stream_s* stream)
{
	if (stream && !uv_is_closing((uv_handle_t *)stream))
		uv_close((uv_handle_t *)stream, stream_close_cb);
}

void asterism_stream_set_trans_mode(struct asterism_stream_s* stream)
{
	stream->trans = 1;
}

static void link_write_cb(
	uv_write_t *req,
	int status)
{
	struct asterism_stream_s *stream = (struct asterism_stream_s *)req->data;
	if (asterism_stream_read(stream)) {
		asterism_stream_close(stream);
	}
}

int asterism_stream_trans(
	struct asterism_stream_s* stream)
{
	int ret = 0;
	memset(&stream->link->write_req, 0, sizeof(stream->link->write_req));
	stream->link->write_req.data = stream;
	uv_buf_t _buf;
	_buf.base = stream->buffer;
	_buf.len = stream->buffer_len;
	stream->buffer_len = 0;
	ret = uv_write(&stream->link->write_req, (uv_stream_t *)stream->link, &_buf, 1, link_write_cb);
	if (ret) {
		goto cleanup;
	}
	ret = uv_read_stop((uv_stream_t*)stream);
	if (ret) {
		goto cleanup;
	}
cleanup:
	return ret;
}

void asterism_stream_eaten(struct asterism_stream_s * stream, unsigned int eaten)
{
	if (eaten == stream->buffer_len) {
		stream->buffer_len = 0;
	}
	else if (eaten <= stream->buffer_len) {
		memmove(stream->buffer, stream->buffer + eaten, eaten);
		stream->buffer_len -= eaten;
	}
}
