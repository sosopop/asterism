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
		AS_FREE(obj);
		obj = 0;
	}
	return obj;
}

static void outer_delete(struct asterism_tcp_outer_s *obj)
{
	AS_FREE(obj);
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
		AS_FREE(obj);
		obj = 0;
	}
	return obj;
}

static void incoming_delete(struct asterism_tcp_incoming_s *obj)
{
	AS_FREE(obj);
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
	if (incoming->connection_type == ASTERISM_TCP_CONNECTION_TYPE_CMD) {
		//未知连接状态，则分配命令缓冲区
		if (!incoming->cmd_buffer) {
			incoming->cmd_buffer = (char *)AS_MALLOC(ASTERISM_MAX_PROTO_SIZE);
			incoming->cmd_buffer_len = 0;
		}
		buf->base = incoming->cmd_buffer + incoming->cmd_buffer_len;
		buf->len = ASTERISM_MAX_PROTO_SIZE - incoming->cmd_buffer_len;
		//buf->len = 10;
		//测试分包
	}
	else {
		buf->base = (char *)AS_MALLOC(ASTERISM_TCP_BLOCK_SIZE);
		buf->len = ASTERISM_TCP_BLOCK_SIZE;
	}
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
	AS_FREE(req);
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
			AS_FREE(req);
		}
	}
	return ret;
}

static int parse_cmd_join(
	struct asterism_tcp_incoming_s *incoming, 
	struct asterism_trans_proto_s* proto)
{
	int offset = sizeof(struct asterism_trans_proto_s);
	unsigned short username_len = 0;
	char* username = 0;
	unsigned short password_len = 0;
	char* password = 0;

	//读取用户名密码
	if (offset + 2 > proto->len)
		return -1;
	username_len = ntohs(*(unsigned short*)((char*)proto + offset));
	offset += 2;

	if (offset + username_len > proto->len)
		return -1;
	username = (char*)((char*)proto + offset);
	offset += username_len;

	if (offset + 2 > proto->len)
		return -1;
	password_len = ntohs(*(unsigned short*)((char*)proto + offset));
	offset += 2;

	if (offset + password_len > proto->len)
		return -1;
	password = (char*)((char*)proto + offset);
	offset += password_len;

	//将用户名密码写入到会话列表
	struct asterism_session_s* session = __zero_malloc_st(struct asterism_session_s);
	session->username = as_strdup2(username, username_len);
	struct asterism_session_s* fs = RB_FIND(asterism_session_tree_s, &incoming->as->sessions, session);
	if (fs) {
		AS_FREE(session->username);
		AS_FREE(session);
		return -1;
	}
	session->password = as_strdup2(password, password_len);
	RB_INSERT(asterism_session_tree_s, &incoming->as->sessions, session);
	//确定连接类型
	incoming->connection_type = ASTERISM_TCP_CONNECTION_TYPE_CMD;
	return 0;
}

static int incoming_parse_cmd_data(
	struct asterism_tcp_incoming_s *incoming,
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
	if (proto->cmd == ASTERISM_TRANS_PROTO_JOIN) {
		if (parse_cmd_join(incoming, proto) != 0)
			return -1;
	}
	else if (proto->cmd == ASTERISM_TRANS_PROTO_CONNECT)
	{
	}
	else if (proto->cmd == ASTERISM_TRANS_PROTO_CONNECT_ACK)
	{
	}
	*eaten += proto_len;
	unsigned int remain = buf->len - proto_len;
	if (remain) {
		uv_buf_t __buf;
		__buf.base = buf->base + proto_len;
		__buf.len = remain;
		return incoming_parse_cmd_data(incoming, &__buf, eaten);
	}
	return 0;
}

static void incoming_read_cb(
	uv_stream_t *stream,
	ssize_t nread,
	const uv_buf_t *buf)
{
	struct asterism_tcp_incoming_s *incoming = (struct asterism_tcp_incoming_s *)stream;
	if (nread > 0)
	{
		int eaten = 0;
		if (incoming->connection_type == ASTERISM_TCP_CONNECTION_TYPE_CMD ) {
			incoming->cmd_buffer_len += nread;
			uv_buf_t buf;
			buf.base = incoming->cmd_buffer;
			buf.len = incoming->cmd_buffer_len;
			if (incoming_parse_cmd_data(incoming, &buf, &eaten) != 0) {
				incoming_close(incoming);
				return;
			}
			int remain = incoming->cmd_buffer_len - eaten;
			if (eaten > 0) {
				if (remain) {
					memmove(incoming->cmd_buffer, incoming->cmd_buffer + eaten, remain);
					incoming->cmd_buffer_len = remain;
				}
				else {
					incoming->cmd_buffer_len = 0;
				}
			}
		}
		else if (incoming->connection_type == ASTERISM_TCP_CONNECTION_TYPE_DATA) {

		}
		else {
			incoming_close(incoming);
			return;
		}
		return;
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
	ret = uv_tcp_bind(&outer->socket, (const struct sockaddr *)addr, 0);
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