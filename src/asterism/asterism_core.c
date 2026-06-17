#include "asterism_core.h"
#include "asterism_portal.h"
#include "asterism_inner_http.h"
#include "asterism_inner_socks5.h"
#include "asterism_outer_tcp.h"
#include "asterism_connector_tcp.h"
#include "asterism_utils.h"
#include "asterism_log.h"
#include "asterism_datagram.h"
#include "queue.h"

void handles_close_cb(uv_handle_t *handle, void *arg);

struct asterism_trans_proto_s _global_proto_ping = {
    ASTERISM_TRANS_PROTO_VERSION,
    ASTERISM_TRANS_PROTO_PING,
    0};

struct asterism_trans_proto_s _global_proto_pong = {
    ASTERISM_TRANS_PROTO_VERSION,
    ASTERISM_TRANS_PROTO_PONG,
    0};

unsigned int asterism_tunnel_new_handshake_id()
{
    static unsigned int id = 0;
    id = (id + 1) | 1;
    return id;
}

int asterism_handshake_compare(struct asterism_handshake_s *a, struct asterism_handshake_s *b)
{
    return (a->id > b->id) - (a->id < b->id);
}

RB_GENERATE(asterism_handshake_tree_s, asterism_handshake_s, tree_entry, asterism_handshake_compare);

int asterism_session_compare(struct asterism_session_s *a, struct asterism_session_s *b)
{
    return strcmp(a->username, b->username);
}

RB_GENERATE(asterism_session_tree_s, asterism_session_s, tree_entry, asterism_session_compare);

int asterism_udp_session_compare(struct asterism_udp_session_s* a, struct asterism_udp_session_s* b)
{
    if (a->source_addr.sin_addr.s_addr != b->source_addr.sin_addr.s_addr)
        return a->source_addr.sin_addr.s_addr > b->source_addr.sin_addr.s_addr ? 1 : -1;
    return (a->source_addr.sin_port > b->source_addr.sin_port) -
           (a->source_addr.sin_port < b->source_addr.sin_port);
}

RB_GENERATE(asterism_udp_session_tree_s, asterism_udp_session_s, tree_entry, asterism_udp_session_compare);

int asterism_proto_frame_size(const void *data, size_t data_len, uint16_t *frame_len)
{
    if (!data || !frame_len)
        return -1;
    if (data_len < sizeof(struct asterism_trans_proto_s))
        return 0;

    const unsigned char *bytes = (const unsigned char *)data;
    if (bytes[0] != ASTERISM_TRANS_PROTO_VERSION)
        return -1;

    uint16_t len = asterism_read_be16(bytes + 2);
    if (len < sizeof(struct asterism_trans_proto_s) || len > ASTERISM_MAX_PROTO_SIZE)
        return -1;
    if (len > data_len)
        return 0;

    *frame_len = len;
    return 1;
}

int asterism_socks5_udp_header_size(
    const unsigned char *data,
    size_t data_len,
    size_t *header_len)
{
    if (!data || !header_len || data_len < 4)
        return -1;
    if (data[0] != 0 || data[1] != 0 || data[2] != 0)
        return -1;

    if (data[3] == 0x01)
    {
        if (data_len < 10)
            return -1;
        *header_len = 10;
        return 0;
    }
    if (data[3] == 0x03)
    {
        if (data_len < 5 || data[4] == 0)
            return -1;
        size_t len = 7u + data[4];
        if (len > data_len)
            return -1;
        *header_len = len;
        return 0;
    }
    return -1;
}

static void check_timer_close_cb(
    uv_handle_t *handle)
{
    struct check_timer_s *timer = __CONTAINER_PTR(struct check_timer_s, timer, handle);
    timer->as->check_timer = 0;
    AS_FREE(timer);
}

static void check_timer_close(
    uv_handle_t *handle)
{
    as_uv_close(handle, check_timer_close_cb);
}

static void check_timer_cb(
    uv_timer_t *handle)
{
    struct check_timer_s *timer = __CONTAINER_PTR(struct check_timer_s, timer, handle);
    struct asterism_s *as = timer->as;
    QUEUE *q;
    as->current_tick_count++;
    unsigned int current_tick_count = as->current_tick_count;
    unsigned int idle_timeout = as->idle_timeout;
    unsigned int udp_idle_timeout = as->udp_idle_timeout;

    // idle_timeout == 0 disables TCP idle reaping entirely (-T 0); dead peers
    // are still detected by TCP keepalive configured in stream_init.
    if (idle_timeout)
    {
        QUEUE_FOREACH(q, &as->conns_queue)
        {
            struct asterism_stream_s *stream = QUEUE_DATA(q, struct asterism_stream_s, queue);
            if (current_tick_count - stream->active_tick_count > idle_timeout)
            {
                asterism_log(ASTERISM_LOG_DEBUG, "tcp connection timeout!!!");
                asterism_stream_close((uv_handle_t *)&stream->socket);
            }
            else
            {
                //asterism_log(ASTERISM_LOG_DEBUG, "%d", stream->active_tick_count);
                break;
            }
        }
    }

    if (udp_idle_timeout) {
        QUEUE_FOREACH(q, &as->udp_conns_queue)
        {
            struct asterism_datagram_s* datagram = QUEUE_DATA(q, struct asterism_datagram_s, queue);
            if (current_tick_count - datagram->active_tick_count > udp_idle_timeout)
            {
                asterism_log(ASTERISM_LOG_DEBUG, "udp connection timeout!!!");
                asterism_datagram_close((uv_handle_t*)&datagram->socket);
            }
            else
            {
                //asterism_log(ASTERISM_LOG_DEBUG, "%d", datagram->active_tick_count);
                break;
            }
        }
    }
}

int asterism_core_prepare(struct asterism_s *as)
{
    if (!as)
        return ASTERISM_E_INVALID_ARGS;

    int ret = ASTERISM_E_OK;
    as->loop = uv_loop_new();
    if (!as->loop)
        return ASTERISM_E_FAILED;
    if (!as->idle_timeout_set) {
        as->idle_timeout = ASTERISM_CONNECTION_MAX_IDLE_COUNT;
    }
    if (as->reconnect_delay == 0) {
        as->reconnect_delay = ASTERISM_RECONNECT_DELAY;
    }
    if (as->heartbeat_interval == 0) {
        as->heartbeat_interval = ASTERISM_HEARTBEAT_INTERVAL;
    }
    _global_proto_ping.len = htons(sizeof(_global_proto_ping));
    _global_proto_pong.len = htons(sizeof(_global_proto_pong));

    QUEUE_INIT(&as->conns_queue);
    QUEUE_INIT(&as->udp_conns_queue);

    struct asterism_slist *next;
    struct asterism_slist *item;
    if (as->inner_bind_addrs) {
        item = as->inner_bind_addrs;
        do
        {
            next = item->next;
            char *inner_bind_addr = item->data;
            struct asterism_str scheme;
            struct asterism_str host;
            unsigned int port;
            asterism_host_type host_type;
            scheme.len = 0;
            host.len = 0;
            int ret_addr = asterism_parse_address(inner_bind_addr, &scheme, &host, &port, &host_type);
            if (ret_addr)
            {
                ret = ASTERISM_E_ADDRESS_PARSE_ERROR;
                goto cleanup;
            }
            if (asterism_str_empty(&scheme))
            {
                ret = ASTERISM_E_PROTOCOL_NOT_SUPPORT;
                goto cleanup;
            }
            if (asterism_vcasecmp(&scheme, "http") == 0)
            {
                struct asterism_str __host = asterism_strdup_nul(host);
                if (host.len && !__host.p)
                {
                    ret = ASTERISM_E_FAILED;
                    goto cleanup;
                }
                ret = asterism_inner_http_init(as, __host.p, &port);
                AS_FREE((char *)__host.p);
                if (ret)
                    goto cleanup;
            }
            else if (asterism_vcasecmp(&scheme, "socks5") == 0)
            {
                struct asterism_str __host = asterism_strdup_nul(host);
                if (host.len && !__host.p)
                {
                    ret = ASTERISM_E_FAILED;
                    goto cleanup;
                }
                ret = asterism_inner_socks5_init(as, __host.p, &port);
                AS_FREE((char *)__host.p);
                if (ret)
                    goto cleanup;
            }
            else
            {
                ret = ASTERISM_E_PROTOCOL_NOT_SUPPORT;
                goto cleanup;
            }
            item = next;
        } while (next);
    }

    if (as->outer_bind_addr)
    {
        struct asterism_str scheme;
        struct asterism_str host;
        unsigned int port;
        asterism_host_type host_type;
        scheme.len = 0;
        host.len = 0;
        int ret_addr = asterism_parse_address(as->outer_bind_addr, &scheme, &host, &port, &host_type);
        if (ret_addr)
        {
            ret = ASTERISM_E_ADDRESS_PARSE_ERROR;
            goto cleanup;
        }
        if (asterism_vcasecmp(&scheme, "tcp") && !asterism_str_empty(&scheme))
        {
            ret = ASTERISM_E_PROTOCOL_NOT_SUPPORT;
            goto cleanup;
        }
        struct asterism_str __host = asterism_strdup_nul(host);
        if (host.len && !__host.p)
        {
            ret = ASTERISM_E_FAILED;
            goto cleanup;
        }
        ret = asterism_outer_tcp_init(as, __host.p, &port);
        AS_FREE((char *)__host.p);
        if (ret)
            goto cleanup;
    }
    if (as->connect_addr)
    {
        struct asterism_str scheme;
        struct asterism_str host;
        unsigned int port;
        asterism_host_type host_type;
        scheme.len = 0;
        host.len = 0;
        if (!as->username || !as->password)
        {
            ret = ASTERISM_E_USERPASS_EMPTY;
            goto cleanup;
        }
        int ret_addr = asterism_parse_address(as->connect_addr, &scheme, &host, &port, &host_type);
        if (ret_addr)
        {
            ret = ASTERISM_E_ADDRESS_PARSE_ERROR;
            goto cleanup;
        }
        if (asterism_vcasecmp(&scheme, "tcp") && !asterism_str_empty(&scheme))
        {
            ret = ASTERISM_E_PROTOCOL_NOT_SUPPORT;
            goto cleanup;
        }
        struct asterism_str __host = asterism_strdup_nul(host);
        if (host.len && !__host.p)
        {
            ret = ASTERISM_E_FAILED;
            goto cleanup;
        }
        ret = asterism_connector_tcp_init(as, __host.p, port);
        AS_FREE((char *)__host.p);
        if (ret)
            goto cleanup;
    }
    
    struct asterism_portal_config_list_s *pc_node = as->portal_configs;
    while (pc_node) {
        ret = asterism_portal_init(as, &pc_node->config);
        if (ret != 0) {
            goto cleanup;
        }
        pc_node = pc_node->next;
    }

    as->check_timer = AS_ZMALLOC(struct check_timer_s);
    if (!as->check_timer)
    {
        ret = ASTERISM_E_FAILED;
        goto cleanup;
    }
    ASTERISM_HANDLE_INIT(as->check_timer, timer, check_timer_close);
    as->check_timer->as = as;
    ret = uv_timer_init(as->loop, &as->check_timer->timer);
    if (ret != 0)
    {
        ret = ASTERISM_E_FAILED;
        goto cleanup;
    }
    ret = uv_timer_start(&as->check_timer->timer, check_timer_cb, 1 * 1000, 1 * 1000);
    if (ret != 0)
    {
        ret = ASTERISM_E_FAILED;
        goto cleanup;
    }
cleanup:
    return ret;
}

int asterism_core_destroy(struct asterism_s *as)
{
    if (!as)
        return ASTERISM_E_INVALID_ARGS;

    int ret = ASTERISM_E_OK;
    if (as->loop)
        uv_loop_delete(as->loop);
    if (as->check_timer)
        AS_FREE(as->check_timer);
    if (as->username)
        AS_FREE(as->username);
    if (as->password)
        AS_FREE(as->password);
    if (as->session_auth_user)
        AS_FREE(as->session_auth_user);
    if (as->session_auth_pass)
        AS_FREE(as->session_auth_pass);
    if (as->connect_addr)
        AS_FREE(as->connect_addr);
    if (as->inner_bind_addrs)
        asterism_slist_free_all(as->inner_bind_addrs);
    if (as->outer_bind_addr)
        AS_FREE(as->outer_bind_addr);

    struct asterism_portal_config_list_s *pc = as->portal_configs;
    while (pc) {
        struct asterism_portal_config_list_s *next = pc->next;
        asterism_portal_free_config(&pc->config);
        AS_FREE(pc);
        pc = next;
    }
    as->portal_configs = NULL;

    struct asterism_portal_list_s *p = as->portals;
    while (p) {
        struct asterism_portal_list_s *next = p->next;
        AS_FREE(p);
        p = next;
    }
    as->portals = NULL;

    struct asterism_handshake_s *h = 0;
    struct asterism_handshake_s *_h = 0;
    RB_FOREACH_SAFE(h, asterism_handshake_tree_s, &as->handshake_set, _h)
    {
        RB_REMOVE(asterism_handshake_tree_s, &as->handshake_set, h);
        AS_FREE(h);
    }
    RB_INIT(&as->handshake_set);
    AS_FREE(as);
    return ret;
}

int asterism_core_run(struct asterism_s *as)
{
    int ret = ASTERISM_E_OK;

    ret = asterism_core_prepare(as);
    if (ret)
    {
        if (as->loop)
        {
            uv_walk(as->loop, handles_close_cb, as);
            uv_run(as->loop, UV_RUN_DEFAULT);
        }
        return ret;
    }

    ret = uv_run(as->loop, UV_RUN_DEFAULT);
    if (ret)
    {
        ret = ASTERISM_E_FAILED;
        goto cleanup;
    }
cleanup:
    return ret;
}

void handles_close_cb(
    uv_handle_t *handle,
    void *arg)
{
    struct asterism_handle_s *_handle = (struct asterism_handle_s *)handle->data;
    if (_handle && _handle->close)
        _handle->close(handle);
}

struct stop_async_s
{
    ASTERISM_HANDLE_FIELDS
    uv_async_t async;
    struct asterism_s *as;
};

static void stop_async_close_cb(uv_handle_t *handle)
{
    struct stop_async_s *async = __CONTAINER_PTR(struct stop_async_s, async, handle);
    AS_FREE(async);
}

static void stop_async_close(uv_handle_t *handle)
{
    as_uv_close(handle, stop_async_close_cb);
}

static void stop_async_cb(uv_async_t *handle)
{
    struct stop_async_s *async = __CONTAINER_PTR(struct stop_async_s, async, handle);
    uv_walk(async->as->loop, handles_close_cb, async->as);
}

int asterism_core_stop(struct asterism_s *as)
{
    if (!as || !as->loop)
        return ASTERISM_E_INVALID_ARGS;

    int ret = ASTERISM_E_OK;
    as->stoped = 1;
    struct stop_async_s *async = AS_ZMALLOC(struct stop_async_s);
    if (!async)
        return ASTERISM_E_FAILED;
    async->as = as;
    ASTERISM_HANDLE_INIT(async, async, stop_async_close);
    ret = uv_async_init(as->loop, &async->async, stop_async_cb);
    if (ret != 0)
    {
        AS_FREE(async);
        return ret;
    }
    ret = uv_async_send(&async->async);
    if (ret != 0)
        stop_async_close((uv_handle_t *)&async->async);
    return ret;
}
