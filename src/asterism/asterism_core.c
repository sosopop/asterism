#include "asterism_core.h"
#include "asterism_inner_http.h"
#include "asterism_outer_tcp.h"
#include "asterism_utils.h"

int asterism_core_prepare(struct asterism_s *as)
{
    int ret = ASTERISM_E_OK;
    as->loop = uv_loop_new();

    QUEUE_INIT(&as->inner_objs);
    QUEUE_INIT(&as->outer_objs);
    QUEUE_INIT(&as->connector_objs);

    if (as->inner_bind_addrs)
    {
        struct asterism_slist *inner_bind_addrs = as->inner_bind_addrs;
        while (inner_bind_addrs)
        {
            struct asterism_str scheme;
            struct asterism_str host;
            unsigned int port;
            asterism_host_type host_type;
            scheme.len = 0;
            host.len = 0;
            int ret_addr = asterism_parse_address(inner_bind_addrs->data, &scheme, &host, &port, &host_type);
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
            ret = asterism_inner_http_init(as, __host.p, &port, host_type == ASTERISM_HOST_TYPE_IPV6);
            free((char*)__host.p);
            if (ret)
                goto cleanup;

            inner_bind_addrs = inner_bind_addrs->next;
        }
    }
    if (as->outer_bind_addrs)
    {
        ret = asterism_outer_tcp_bind(as);
        if (ret != ASTERISM_E_OK)
            goto cleanup;
    }
    if (as->connect_addrs)
    {
        ret = asterism_outer_tcp_connect_addrs(as);
        if (ret != ASTERISM_E_OK)
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
    if (as->connect_addrs)
        asterism_slist_free_all(as->connect_addrs);
    if (as->inner_bind_addrs)
        asterism_slist_free_all(as->inner_bind_addrs);
    if (as->outer_bind_addrs)
        asterism_slist_free_all(as->outer_bind_addrs);
    free(as);

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