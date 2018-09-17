#include "asterism_core.h"
#include "asterism_inner_http.h"
#include "asterism_outer_tcp.h"

int asterism_core_prepare(struct asterism_s *as)
{
    int ret = ASTERISM_E_OK;
    as->loop = uv_loop_new();
    if (as->inner_bind_addr)
    {
        ret = asterism_inner_http_bind(as);
        if (ret != ASTERISM_E_OK)
            goto cleanup;
    }
    if (as->outer_bind_addr)
    {
        ret = asterism_outer_tcp_bind(as);
        if (ret != ASTERISM_E_OK)
            goto cleanup;
    }
    if (as->connect_addr)
    {
        ret = asterism_outer_tcp_connect_addr(as);
        if (ret != ASTERISM_E_OK)
            goto cleanup;
    }
cleanup:
    return ret;
}