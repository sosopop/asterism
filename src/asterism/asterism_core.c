#include "asterism_core.h"
#include "asterism_inner_http.h"
#include "asterism_outer_tcp.h"
#include "asterism_connector_tcp.h"
#include "asterism_utils.h"

unsigned int asterism_tunnel_new_handshake_id()
{
	static unsigned int id = 0;
	return id++;
}

int asterism_handshake_compare(struct asterism_handshake_s* a, struct asterism_handshake_s* b) {
	return a->id - b->id;
}

RB_GENERATE(asterism_handshake_tree_s, asterism_handshake_s, tree_entry, asterism_handshake_compare);

int asterism_session_compare(struct asterism_session_s* a, struct asterism_session_s* b) {
	return strcmp(a->username, b->username);
}

RB_GENERATE(asterism_session_tree_s, asterism_session_s, tree_entry, asterism_session_compare);


int asterism_core_prepare(struct asterism_s *as)
{
    int ret = ASTERISM_E_OK;
    as->loop = uv_loop_new();

    if (as->inner_bind_addr)
    {
        struct asterism_str scheme;
        struct asterism_str host;
        unsigned int port;
        asterism_host_type host_type;
        scheme.len = 0;
        host.len = 0;
        int ret_addr = asterism_parse_address(as->inner_bind_addr, &scheme, &host, &port, &host_type);
        if (ret_addr)
        {
            ret = ASTERISM_E_ADDRESS_PARSE_ERROR;
            goto cleanup;
        }
        if (asterism_vcasecmp(&scheme, "http") && !asterism_str_empty(&scheme))
        {
            ret = ASTERISM_E_PROTOCOL_NOT_SUPPORT;
            goto cleanup;
        }
        struct asterism_str __host = asterism_strdup_nul(host);
        ret = asterism_inner_http_init(as, __host.p, &port);
        AS_FREE((char *)__host.p);
        if (ret)
            goto cleanup;
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
        ret = asterism_connector_tcp_init(as, __host.p, port);
        AS_FREE((char *)__host.p);
        if (ret)
            goto cleanup;
    }
cleanup:
    return ret;
}

int asterism_core_destory(struct asterism_s *as)
{
    int ret = ASTERISM_E_OK;
    if (as->loop)
        uv_loop_delete(as->loop);
    if (as->username)
        AS_FREE(as->username);
    if (as->password)
        AS_FREE(as->password);
    if (as->connect_addr)
        AS_FREE(as->connect_addr);
    if (as->inner_bind_addr)
        AS_FREE(as->inner_bind_addr);
    if (as->outer_bind_addr)
        AS_FREE(as->outer_bind_addr);
    AS_FREE(as);

    return ret;
}

int asterism_core_run(struct asterism_s *as)
{
    int ret = ASTERISM_E_OK;
    ret = uv_run(as->loop, UV_RUN_DEFAULT);
    if (ret)
    {
        ret = ASTERISM_E_FAILED;
        goto cleanup;
    }
cleanup:
    return ret;
}
