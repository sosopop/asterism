#include "asterism_connector_tcp.h"
#include "asterism_requestor_tcp.h"
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

	buf->base = connector->buffer + connector->buffer_len;
	buf->len = ASTERISM_MAX_PROTO_SIZE - connector->buffer_len;
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

static int connector_parse_connect_data(
	struct asterism_tcp_connector_s *conn,
	struct asterism_trans_proto_s* proto)
{
	int ret = -1;
	int offset = sizeof(struct asterism_trans_proto_s);
	unsigned short host_len = 0;
	char* host = 0;
	char* __host = 0;

	if (offset + 4 > proto->len)
		goto cleanup;
	unsigned int handshake_id = ntohl(*(unsigned int*)((char*)proto + offset));
	offset += 4;
	//读取host
	if (offset + 2 > proto->len)
		goto cleanup;
	host_len = ntohs(*(unsigned short*)((char*)proto + offset));
	offset += 2;

	if (host_len > MAX_HOST_LEN)
		goto cleanup;

	if (offset + host_len > proto->len)
		goto cleanup;

	host = (char*)((char*)proto + offset);
	offset += host_len;

	asterism_log(ASTERISM_LOG_DEBUG, "connect to: %.*s", (int)host_len, host);

	char* target = as_strdup2(host, host_len);

	struct asterism_str scheme = {0};
	struct asterism_str host_str = { 0 };
	unsigned int port = 0;
	asterism_host_type host_type;

	if (asterism_parse_address(target, &scheme, &host_str, &port, &host_type) || !host_str.p || !port)
		goto cleanup;

	__host = as_strdup2(host_str.p, host_str.len);

	if (asterism_requestor_tcp_init(conn->as, __host, port, handshake_id, (struct asterism_stream_s*)conn))
		goto cleanup;

	//conn->connection_type = ASTERISM_TCP_CONNECTOR_TYPE_DATA;

	ret = 0;
cleanup:
	asterism_safefree(__host);
	asterism_safefree(target);
	return ret;
}

static int connector_parse_cmd_data(
	struct asterism_tcp_connector_s *conn,
	uv_buf_t *buf,
	int* eaten
)
{
	//长度不够继续获取
	if (buf->len < sizeof(struct asterism_trans_proto_s))
		return 0;
	struct asterism_trans_proto_s* proto = (struct asterism_trans_proto_s*)buf->base;
	uint16_t proto_len = ntohs(proto->len);
	if (proto->version != ASTERISM_TRANS_PROTO_VERSION)
		return -1;
	if (proto_len > ASTERISM_MAX_PROTO_SIZE)
		return -1;
	//长度不够继续获取
	if (proto_len > buf->len) {
		return 0;
	}
	//匹配命令
	if (proto->cmd == ASTERISM_TRANS_PROTO_CONNECT) {
		if (connector_parse_connect_data(conn, proto) != 0)
			return -1;
	}
	else
	{
		return -1;
	}
	*eaten += proto_len;
	unsigned int remain = buf->len - proto_len;
	if (remain) {
		uv_buf_t __buf;
		__buf.base = buf->base + proto_len;
		__buf.len = remain;
		return connector_parse_cmd_data(conn, &__buf, eaten);
	}
	return 0;
}


static void connector_read_cb(
	uv_stream_t *stream,
	ssize_t nread,
	const uv_buf_t *buf);

static void link_write_cb(
	uv_write_t *req,
	int status)
{
	struct asterism_tcp_connector_s *connector = (struct asterism_tcp_connector_s *)req->data;
	if (uv_read_start((uv_stream_t *)&connector->socket, connector_data_read_alloc_cb, connector_read_cb)) {
		connector_close(connector);
	}
}

static void connector_read_cb(
	uv_stream_t *stream,
	ssize_t nread,
	const uv_buf_t *buf)
{
	struct asterism_tcp_connector_s *connector = (struct asterism_tcp_connector_s *)stream;
	if (nread > 0)
	{
		int eaten = 0;
		connector->buffer_len += nread;
		if (connector->connection_type == ASTERISM_TCP_CONNECTOR_TYPE_CMD) {
			uv_buf_t buf;
			buf.base = connector->buffer;
			buf.len = connector->buffer_len;
 			if (connector_parse_cmd_data(connector, &buf, &eaten) != 0) {
 				connector_close(connector);
 				return;
 			}
			int remain = connector->buffer_len - eaten;
			if (eaten > 0) {
				if (remain) {
					memmove(connector->buffer, connector->buffer + eaten, remain);
					connector->buffer_len = remain;
				}
				else {
					connector->buffer_len = 0;
				}
			}
		}

		if (connector->buffer_len) {
			if (connector->connection_type == ASTERISM_TCP_CONNECTOR_TYPE_DATA) {
				memset(&connector->link->write_req, 0, sizeof(connector->link->write_req));
				connector->link->write_req.data = stream;
				uv_buf_t _buf;
				_buf.base = connector->buffer;
				_buf.len = connector->buffer_len;
				connector->buffer_len = 0;
				if (uv_write(&connector->link->write_req, (uv_stream_t *)connector->link, &_buf, 1, link_write_cb)) {
					connector_close(connector);
					return;
				}
				if (uv_read_stop(stream)) {
					connector_close(connector);
					return;
				}
			}
			else if (connector->connection_type != ASTERISM_TCP_CONNECTOR_TYPE_CMD) {
				connector_close(connector);
			}
		}
	}
	else if (nread == 0)
	{
		return;
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
	}
	else
	{
		asterism_log(ASTERISM_LOG_DEBUG, "%s", uv_strerror((int)nread));
		connector_close(connector);
	}
	//if (buf && buf->base)
		//AS_FREE(buf->base);
}

static void connector_send_cb(
	uv_write_t *req,
	int status)
{
	struct asterism_write_req_s *write_req = (struct asterism_write_req_s *)req;
	free(write_req->write_buffer.base);
	free(write_req);
}

#define JOIN_MAX_BUFFER_SIZE 512

static int connector_send_join(struct asterism_tcp_connector_s *connector)
{
	int ret = 0;
	struct asterism_s *as = connector->as;
	struct asterism_trans_proto_s *connect_data = (struct asterism_trans_proto_s *)malloc(JOIN_MAX_BUFFER_SIZE);
	connect_data->version = ASTERISM_TRANS_PROTO_VERSION;
	connect_data->cmd = ASTERISM_TRANS_PROTO_JOIN;

	char *off = (char *)connect_data + sizeof(struct asterism_trans_proto_s);
	size_t username_len = strlen(as->username);
	*(uint16_t *)off = htons((uint16_t)username_len);
	off += 2;
	memcpy(off, as->username, username_len);
	off += username_len;

	size_t password_len = strlen(as->password);
	*(uint16_t *)off = htons((uint16_t)password_len);
	off += 2;
	memcpy(off, as->password, password_len);
	off += password_len;

	uint16_t packet_len = (uint16_t)(off - (char *)connect_data);
	connect_data->len = htons(packet_len);
	struct asterism_write_req_s *write_req = __zero_malloc_st(struct asterism_write_req_s);

//测试粘包
// 	char* new_buffer = (char*)malloc(packet_len * 2);
// 	memcpy(new_buffer, connect_data, packet_len);
// 	memcpy(new_buffer + packet_len, connect_data, packet_len);
// 	write_req->write_buffer.base = new_buffer;
// 	write_req->write_buffer.len = packet_len * 2;

	write_req->write_buffer.base = (char *)connect_data;
	write_req->write_buffer.len = packet_len;
	ret = uv_write(&write_req->write_req, (uv_stream_t *)&connector->socket, &write_req->write_buffer, 1, connector_send_cb);
	if (ret != 0)
	{
		goto cleanup;
	}
cleanup:
	if (ret != 0)
	{
		if (connect_data)
			free(connect_data);
	}
	return ret;
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
	ret = connector_send_join(connector);
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