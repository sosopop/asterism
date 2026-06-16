#include "asterism_portal.h"
#include "asterism_log.h"
#include "asterism_utils.h"
#include <string.h>
#include <ctype.h>

static const char b64_table[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static void asterism_base64_encode(const unsigned char *src, int len, char *dst, int *out_len)
{
    int i = 0, j = 0;
    for (i = 0; i < len; i += 3) {
        unsigned int val = src[i] << 16;
        if (i + 1 < len) val |= src[i + 1] << 8;
        if (i + 2 < len) val |= src[i + 2];
        
        dst[j++] = b64_table[(val >> 18) & 0x3F];
        dst[j++] = b64_table[(val >> 12) & 0x3F];
        dst[j++] = (i + 1 < len) ? b64_table[(val >> 6) & 0x3F] : '=';
        dst[j++] = (i + 2 < len) ? b64_table[val & 0x3F] : '=';
    }
    *out_len = j;
}

static const char *find_bytes(const char *haystack, size_t haystack_len, const char *needle, size_t needle_len)
{
    if (!haystack || !needle || needle_len == 0 || haystack_len < needle_len)
        return NULL;
    for (size_t i = 0; i <= haystack_len - needle_len; i++) {
        if (memcmp(haystack + i, needle, needle_len) == 0)
            return haystack + i;
    }
    return NULL;
}

static int is_connect_200_response(const char *data, size_t len)
{
    const char *line_end = find_bytes(data, len, "\r\n", 2);
    size_t line_len = line_end ? (size_t)(line_end - data) : len;
    if (line_len < sizeof("HTTP/1.1 200") - 1)
        return 0;
    if (memcmp(data, "HTTP/", sizeof("HTTP/") - 1) != 0)
        return 0;

    const char *space = memchr(data, ' ', line_len);
    if (!space || (size_t)(space + 4 - data) > line_len)
        return 0;
    if (memcmp(space + 1, "200", 3) != 0)
        return 0;
    if ((size_t)(space + 4 - data) == line_len)
        return 1;
    return space[4] == ' ' || space[4] == '\t';
}

int asterism_portal_parse_rule(const char *rule_str, struct asterism_portal_config_s *config)
{
    if (!rule_str || !config)
        return -1;
    memset(config, 0, sizeof(*config));

    char *s = as_strdup(rule_str);
    if (!s) return -1;

    char *first_hash = strchr(s, '#');
    if (!first_hash)
        goto fail;
    *first_hash = '\0';
    char *local_part = s;
    char *relay_part = first_hash + 1;

    char *second_hash = strchr(relay_part, '#');
    if (!second_hash)
        goto fail;
    *second_hash = '\0';
    char *remote_part = second_hash + 1;

    // 1. Parse local part
    char local_full[256];
    int written = 0;
    if (strstr(local_part, "://") == NULL) {
        written = snprintf(local_full, sizeof(local_full), "tcp://%s", local_part);
    } else {
        written = snprintf(local_full, sizeof(local_full), "%s", local_part);
    }
    if (written < 0 || (size_t)written >= sizeof(local_full))
        goto fail;

    struct asterism_str scheme, host;
    unsigned int port;
    asterism_host_type host_type;
    if (asterism_parse_address(local_full, &scheme, &host, &port, &host_type) != 0)
        goto fail;
    if (!asterism_str_empty(&scheme) && asterism_vcasecmp(&scheme, "tcp") != 0)
        goto fail;
    config->local_host = as_strdup2(host.p, host.len);
    if (!config->local_host)
        goto fail;
    config->local_port = port;

    // 2. Parse remote part
    char remote_full[256];
    if (strstr(remote_part, "://") == NULL) {
        written = snprintf(remote_full, sizeof(remote_full), "tcp://%s", remote_part);
    } else {
        written = snprintf(remote_full, sizeof(remote_full), "%s", remote_part);
    }
    if (written < 0 || (size_t)written >= sizeof(remote_full))
        goto fail;

    if (asterism_parse_address(remote_full, &scheme, &host, &port, &host_type) != 0)
        goto fail;
    if (!asterism_str_empty(&scheme) && asterism_vcasecmp(&scheme, "tcp") != 0)
        goto fail;
    config->remote_host = as_strdup2(host.p, host.len);
    if (!config->remote_host)
        goto fail;
    config->remote_port = port;

    // 3. Parse relay part
    char relay_full[512];
    if (strstr(relay_part, "://") == NULL) {
        written = snprintf(relay_full, sizeof(relay_full), "http://%s", relay_part);
    } else {
        written = snprintf(relay_full, sizeof(relay_full), "%s", relay_part);
    }
    if (written < 0 || (size_t)written >= sizeof(relay_full))
        goto fail;

    char *scheme_end = strstr(relay_full, "://");
    if (!scheme_end)
        goto fail;
    char *at_sign = strchr(scheme_end + 3, '@');
    char host_port_url[512];

    if (at_sign) {
        size_t cred_len = at_sign - (scheme_end + 3);
        char *cred = as_strdup2(scheme_end + 3, cred_len);
        if (!cred)
            goto fail;
        char *colon = strchr(cred, ':');
        if (colon) {
            *colon = '\0';
            config->relay_user = as_strdup(cred);
            config->relay_pass = as_strdup(colon + 1);
        } else {
            config->relay_user = as_strdup(cred);
            config->relay_pass = as_strdup("");
        }
        free(cred);
        if (!config->relay_user || !config->relay_pass)
            goto fail;

        size_t scheme_len = (scheme_end + 3) - relay_full;
        if (scheme_len + strlen(at_sign + 1) >= sizeof(host_port_url))
            goto fail;
        memcpy(host_port_url, relay_full, scheme_len);
        strcpy(host_port_url + scheme_len, at_sign + 1);
    } else {
        config->relay_user = NULL;
        config->relay_pass = NULL;
        if (strlen(relay_full) >= sizeof(host_port_url))
            goto fail;
        strcpy(host_port_url, relay_full);
    }

    if (asterism_parse_address(host_port_url, &scheme, &host, &port, &host_type) != 0)
        goto fail;
    if (asterism_vcasecmp(&scheme, "http") != 0)
        goto fail;
    config->relay_host = as_strdup2(host.p, host.len);
    if (!config->relay_host)
        goto fail;
    config->relay_port = port;

    free(s);
    return 0;

fail:
    free(s);
    asterism_portal_free_config(config);
    return -1;
}

void asterism_portal_free_config(struct asterism_portal_config_s *config)
{
    if (!config) return;
    if (config->local_host) free(config->local_host);
    if (config->remote_host) free(config->remote_host);
    if (config->relay_host) free(config->relay_host);
    if (config->relay_user) free(config->relay_user);
    if (config->relay_pass) free(config->relay_pass);
    memset(config, 0, sizeof(*config));
}

struct asterism_portal_conn_s
{
    struct asterism_portal_s *portal;
    struct asterism_stream_s local_stream;
    struct asterism_stream_s relay_stream;
    unsigned char local_closed : 1;
    unsigned char relay_closed : 1;
    unsigned char handshake_done : 1;
};

static void on_local_close(uv_handle_t *handle)
{
    struct asterism_stream_s *local_stream = __CONTAINER_PTR(struct asterism_stream_s, socket, handle);
    struct asterism_portal_conn_s *conn = __CONTAINER_PTR(struct asterism_portal_conn_s, local_stream, local_stream);
    
    conn->local_closed = 1;
    if (conn->relay_closed) {
        AS_FREE(conn);
    } else {
        asterism_stream_close((uv_handle_t*)&conn->relay_stream.socket);
    }
}

static void on_relay_close(uv_handle_t *handle)
{
    struct asterism_stream_s *relay_stream = __CONTAINER_PTR(struct asterism_stream_s, socket, handle);
    struct asterism_portal_conn_s *conn = __CONTAINER_PTR(struct asterism_portal_conn_s, relay_stream, relay_stream);
    
    conn->relay_closed = 1;
    if (conn->local_closed) {
        AS_FREE(conn);
    } else {
        asterism_stream_close((uv_handle_t*)&conn->local_stream.socket);
    }
}

static void on_local_read(uv_stream_t *stream, ssize_t nread, const uv_buf_t *buf)
{
    // Dummy read callback before autotrans starts. Should not receive data.
}

static void on_relay_read(uv_stream_t *stream, ssize_t nread, const uv_buf_t *buf)
{
    struct asterism_stream_s *relay_stream = __CONTAINER_PTR(struct asterism_stream_s, socket, stream);
    struct asterism_portal_conn_s *conn = __CONTAINER_PTR(struct asterism_portal_conn_s, relay_stream, relay_stream);
    
    if (nread < 0) {
        asterism_stream_close((uv_handle_t*)stream);
        return;
    }

    const char *hdr_end = find_bytes(relay_stream->buffer, relay_stream->buffer_len, "\r\n\r\n", 4);
    if (hdr_end) {
        if (is_connect_200_response(relay_stream->buffer, relay_stream->buffer_len)) {
            size_t hdr_len = (hdr_end + 4) - relay_stream->buffer;
            asterism_stream_eaten(relay_stream, (unsigned int)hdr_len);
            
            conn->handshake_done = 1;
            conn->local_stream.link = &conn->relay_stream;
            conn->relay_stream.link = &conn->local_stream;
            conn->local_stream.auto_trans = 1;
            conn->relay_stream.auto_trans = 1;

            if (relay_stream->buffer_len > 0) {
                asterism_stream_trans(relay_stream);
            }
            
            asterism_stream_read(&conn->local_stream);
        } else {
            asterism_log(ASTERISM_LOG_DEBUG, "Portal: Relay proxy returned error during CONNECT");
            asterism_stream_close((uv_handle_t*)stream);
        }
    } else {
        if (relay_stream->buffer_len > 4096) {
            asterism_stream_close((uv_handle_t*)stream);
        }
    }
}

static void on_handshake_write_complete(uv_write_t *req, int status)
{
    struct asterism_portal_conn_s *conn = (struct asterism_portal_conn_s *)req->data;
    struct asterism_write_req_s *write_req = (struct asterism_write_req_s *)req;
    AS_FREE(write_req->write_buffer.base);
    AS_FREE(write_req);
    if (status < 0) {
        asterism_stream_close((uv_handle_t*)&conn->relay_stream.socket);
        return;
    }
    asterism_stream_read(&conn->relay_stream);
}

static void on_relay_connected(uv_connect_t *req, int status)
{
    struct asterism_stream_s *relay_stream = (struct asterism_stream_s *)req->data;
    struct asterism_portal_conn_s *conn = __CONTAINER_PTR(struct asterism_portal_conn_s, relay_stream, relay_stream);
    if (status < 0) {
        asterism_stream_close((uv_handle_t*)&conn->local_stream.socket);
        return;
    }

    char req_buf[1024];
    int req_len = 0;
    if (conn->portal->config->relay_user && strlen(conn->portal->config->relay_user) > 0) {
        char creds[512];
        int creds_len = snprintf(creds, sizeof(creds), "%s:%s", conn->portal->config->relay_user, conn->portal->config->relay_pass ? conn->portal->config->relay_pass : "");
        if (creds_len < 0 || (size_t)creds_len >= sizeof(creds)) {
            asterism_stream_close((uv_handle_t*)&conn->local_stream.socket);
            return;
        }
        char b64_creds[1024];
        int b64_len = 0;
        if ((size_t)(((creds_len + 2) / 3) * 4 + 1) > sizeof(b64_creds)) {
            asterism_stream_close((uv_handle_t*)&conn->local_stream.socket);
            return;
        }
        asterism_base64_encode((const unsigned char*)creds, (int)strlen(creds), b64_creds, &b64_len);
        b64_creds[b64_len] = '\0';
        
        req_len = snprintf(req_buf, sizeof(req_buf),
            "CONNECT %s:%u HTTP/1.1\r\n"
            "Host: %s:%u\r\n"
            "Proxy-Connection: Keep-Alive\r\n"
            "Proxy-Authorization: Basic %s\r\n"
            "\r\n",
            conn->portal->config->remote_host, conn->portal->config->remote_port,
            conn->portal->config->remote_host, conn->portal->config->remote_port,
            b64_creds);
    } else {
        req_len = snprintf(req_buf, sizeof(req_buf),
            "CONNECT %s:%u HTTP/1.1\r\n"
            "Host: %s:%u\r\n"
            "Proxy-Connection: Keep-Alive\r\n"
            "\r\n",
            conn->portal->config->remote_host, conn->portal->config->remote_port,
            conn->portal->config->remote_host, conn->portal->config->remote_port);
    }
    if (req_len < 0 || (size_t)req_len >= sizeof(req_buf)) {
        asterism_stream_close((uv_handle_t*)&conn->local_stream.socket);
        return;
    }

    struct asterism_write_req_s *write_req = AS_ZMALLOC(struct asterism_write_req_s);
    if (!write_req) {
        asterism_stream_close((uv_handle_t*)&conn->local_stream.socket);
        return;
    }
    write_req->write_buffer.base = __DUP_MEM(req_buf, (size_t)req_len);
    if (!write_req->write_buffer.base) {
        AS_FREE(write_req);
        asterism_stream_close((uv_handle_t*)&conn->local_stream.socket);
        return;
    }
    write_req->write_buffer.len = (unsigned int)req_len;
    write_req->write_req.data = conn;
    if (asterism_stream_write(&write_req->write_req, &conn->relay_stream, &write_req->write_buffer, on_handshake_write_complete) != 0) {
        AS_FREE(write_req->write_buffer.base);
        AS_FREE(write_req);
        asterism_stream_close((uv_handle_t*)&conn->local_stream.socket);
    }
}

static void on_local_connection(uv_stream_t *server_stream, int status)
{
    struct asterism_portal_s *portal = (struct asterism_portal_s *)server_stream->data;
    if (status < 0) {
        return;
    }

    struct asterism_portal_conn_s *conn = AS_ZMALLOC(struct asterism_portal_conn_s);
    if (!conn) return;

    conn->portal = portal;

    int ret = asterism_stream_accept(portal->as, server_stream, 0, 0,
                                     NULL, on_local_read, on_local_close, &conn->local_stream);
    if (ret != 0) {
        AS_FREE(conn);
        return;
    }

    ret = asterism_stream_connect(portal->as, portal->config->relay_host, portal->config->relay_port,
                                  0, 0, on_relay_connected, NULL, on_relay_read, on_relay_close, &conn->relay_stream);
    if (ret != 0) {
        asterism_stream_close((uv_handle_t*)&conn->local_stream.socket);
    }
}

static void portal_close_cb(uv_handle_t *handle)
{
    struct asterism_portal_s *portal = __CONTAINER_PTR(struct asterism_portal_s, listener, handle);
    AS_FREE(portal);
}

static void portal_close(uv_handle_t *handle)
{
    as_uv_close(handle, portal_close_cb);
}

int asterism_portal_init(struct asterism_s *as, struct asterism_portal_config_s *config)
{
    if (!as || !config || !config->local_host || !config->relay_host || !config->remote_host)
        return ASTERISM_E_INVALID_ARGS;

    int ret = 0;
    struct asterism_portal_s *portal = AS_ZMALLOC(struct asterism_portal_s);
    if (!portal) return ASTERISM_E_FAILED;

    portal->as = as;
    portal->config = config;
    ASTERISM_HANDLE_INIT(portal, listener, portal_close);

    ret = uv_tcp_init(as->loop, &portal->listener);
    if (ret != 0) {
        AS_FREE(portal);
        return ASTERISM_E_SOCKET_LISTEN_ERROR;
    }

    struct sockaddr_storage addr;
    memset(&addr, 0, sizeof(addr));
    
    // Check if IPv6
    if (strchr(config->local_host, ':') != NULL) {
        ret = uv_ip6_addr(config->local_host, config->local_port, (struct sockaddr_in6*)&addr);
    } else {
        ret = uv_ip4_addr(config->local_host, config->local_port, (struct sockaddr_in*)&addr);
    }

    if (ret != 0) {
        portal_close((uv_handle_t*)&portal->listener);
        return ASTERISM_E_ADDRESS_PARSE_ERROR;
    }

    ret = uv_tcp_bind(&portal->listener, (const struct sockaddr*)&addr, 0);
    if (ret != 0) {
        portal_close((uv_handle_t*)&portal->listener);
        return ASTERISM_E_SOCKET_LISTEN_ERROR;
    }

    portal->listener.data = portal;
    ret = uv_listen((uv_stream_t*)&portal->listener, ASTERISM_NET_BACKLOG, on_local_connection);
    if (ret != 0) {
        portal_close((uv_handle_t*)&portal->listener);
        return ASTERISM_E_SOCKET_LISTEN_ERROR;
    }

    struct asterism_portal_list_s *node = AS_ZMALLOC(struct asterism_portal_list_s);
    if (!node) {
        portal_close((uv_handle_t*)&portal->listener);
        return ASTERISM_E_FAILED;
    }
    node->portal = portal;
    node->next = as->portals;
    as->portals = node;

    asterism_log(ASTERISM_LOG_DEBUG, "Portal: Listening on %s:%u -> Forwarding to %s:%u via Relay %s:%u",
                 config->local_host, config->local_port,
                 config->remote_host, config->remote_port,
                 config->relay_host, config->relay_port);

    return 0;
}
