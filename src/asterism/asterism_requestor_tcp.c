#include "asterism_requestor_tcp.h"
#include "asterism_core.h"
#include "asterism_utils.h"
#include "asterism_log.h"

static void requestor_close_cb(
	uv_handle_t *handle)
{
	struct asterism_tcp_requestor_s *obj = (struct asterism_tcp_requestor_s *)handle;
	AS_FREE(obj);
	asterism_log(ASTERISM_LOG_DEBUG, "tcp connection is closing");
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

static int requestor_connect_ack(
	struct asterism_tcp_requestor_s *requestor) {
	int ret = 0;

	struct asterism_trans_proto_s *connect_data =
		(struct asterism_trans_proto_s *)malloc(sizeof(struct asterism_trans_proto_s) + 4);

	connect_data->version = ASTERISM_TRANS_PROTO_VERSION;
	connect_data->cmd = ASTERISM_TRANS_PROTO_CONNECT_ACK;

	char *off = (char *)connect_data + sizeof(struct asterism_trans_proto_s);
	*(uint32_t *)off = htonl(requestor->handshake_id);
	off += 4;
	uint16_t packet_len = (uint16_t)(off - (char *)connect_data);
	connect_data->len = htons((uint16_t)(packet_len));

	struct asterism_write_req_s* req = __zero_malloc_st(struct asterism_write_req_s);
	req->write_buffer.base = (char *)connect_data;
	req->write_buffer.len = packet_len;

	int write_ret = uv_write((uv_write_t*)req, (uv_stream_t*)requestor->link, &req->write_buffer, 1, handshake_write_cb);
	if (write_ret != 0) {
		free(req->write_buffer.base);
		free(req);
		return -1;
	}

	return ret;
}

static void requestor_connect_cb(
	uv_connect_t *req,
	int status)
{
	int ret = 0;
	struct asterism_tcp_requestor_s *requestor = (struct asterism_tcp_requestor_s *)req->data;
	ret = requestor_connect_ack(requestor);
	if (ret != 0)
	{
		goto cleanup;
	}
	ret = asterism_stream_read((struct asterism_stream_s*)requestor);
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
	const char *host, unsigned int port,
	unsigned int handshake_id,
	struct asterism_stream_s* stream)
{
	int ret = 0;
	struct asterism_tcp_requestor_s *requestor = __zero_malloc_st(struct asterism_tcp_requestor_s);
	ret = asterism_stream_connect(as, host, port, 
		requestor_connect_cb, 0, requestor_read_cb, requestor_close_cb, (struct asterism_stream_s*)requestor);
	if (ret)
		goto cleanup;
	requestor->handshake_id = handshake_id;
	requestor->link = stream;
	stream->link = (struct asterism_stream_s *)requestor;
cleanup:
	if (ret)
	{
		asterism_stream_close((struct asterism_stream_s*)requestor);
	}
	return ret;
}
