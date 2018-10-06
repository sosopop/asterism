#include "asterism_requestor_tcp.h"
#include "asterism_core.h"
#include "asterism_utils.h"
#include "asterism_log.h"
#include "asterism_responser_tcp.h"

static void requestor_close_cb(
	uv_handle_t *handle)
{
	struct asterism_tcp_requestor_s *requestor = (struct asterism_tcp_requestor_s *)handle;
	asterism_safefree(requestor->host_rhs);
	AS_FREE(requestor);
	asterism_log(ASTERISM_LOG_DEBUG, "requestor is closing");
}

static void requestor_read_cb(
	uv_stream_t *stream,
	ssize_t nread,
	const uv_buf_t *buf)
{
	struct asterism_tcp_requestor_s *requestor = (struct asterism_tcp_requestor_s *)stream;
	if (asterism_stream_trans((struct asterism_stream_s*)stream)) {
		asterism_stream_close((struct asterism_stream_s*)stream);
		return;
	}
}

static void handshake_write_cb(
	uv_write_t *req,
	int status)
{
	struct asterism_write_req_s *write_req = (struct asterism_write_req_s *)req;
	free(write_req->write_buffer.base);
	free(write_req);
}

static void requestor_connect_cb(
	uv_connect_t *req,
	int status)
{
	int ret = 0;
	asterism_log(ASTERISM_LOG_DEBUG, "request connected");

	struct asterism_tcp_requestor_s *requestor = (struct asterism_tcp_requestor_s *)req->data;
	ret = asterism_responser_tcp_init(requestor->as, requestor->host_rhs, 
		requestor->port_rhs, requestor->handshake_id, (struct asterism_stream_s*)requestor);
	if (ret != 0)
	{
		goto cleanup;
	}
cleanup:
	if (ret != 0)
	{
		asterism_stream_close((struct asterism_stream_s*)requestor);
	}
}

int asterism_requestor_tcp_init(
	struct asterism_s *as,
	const char *host_lhs, unsigned int port_lhs,
	const char *host_rhs, unsigned int port_rhs,
	unsigned int handshake_id,
	struct asterism_stream_s* stream)
{
	int ret = 0;
	struct asterism_tcp_requestor_s *requestor = __zero_malloc_st(struct asterism_tcp_requestor_s);
	ret = asterism_stream_connect(as, host_lhs, port_lhs,
		requestor_connect_cb, 0, requestor_read_cb, requestor_close_cb, (struct asterism_stream_s*)requestor);
	if (ret)
		goto cleanup;
	requestor->host_rhs = as_strdup(host_rhs);
	requestor->port_rhs = port_rhs;
	requestor->handshake_id = handshake_id;
cleanup:
	if (ret)
	{
		asterism_stream_close((struct asterism_stream_s*)requestor);
	}
	return ret;
}
