#include "asterism_test02.h"
#include "../asterism_core.h"
#include "../asterism.h"
#include "../asterism_utils.h"
#include <uv.h>
#include <stdlib.h>
#include <assert.h>

int asterism_test02()
{
    int ret = ASTERISM_E_OK;

    printf("libuv: %s\n", uv_version_string());
    printf("asterism: %s\n", asterism_version());

    asterism_set_log_level(ASTERISM_LOG_DEBUG);
    asterism as = asterism_create();
    assert(as); 

    struct asterism_slist *inner_addrs = 0;
    //inner_addrs = asterism_slist_append(inner_addrs, "http://0.0.0.0:8080");
    inner_addrs = asterism_slist_append(inner_addrs, "http://[::]:8080");
    //inner_addrs = asterism_slist_append(inner_addrs, "socks5://0.0.0.0:1080");
    asterism_set_option(as, ASTERISM_OPT_INNER_BIND_ADDRS, inner_addrs);
    asterism_slist_free_all(inner_addrs);

    /*
    struct asterism_slist *outer_addrs = 0;
    outer_addrs = asterism_slist_append(outer_addrs, "tcp://0.0.0.0:8081");
    outer_addrs = asterism_slist_append(outer_addrs, "kcp://0.0.0.0:1081");
    asterism_set_option(as, ASTERISM_OPT_OUTER_BIND_ADDRS, outer_addrs);
    asterism_slist_free_all(outer_addrs);

    struct asterism_slist *connect_addrs = 0;
    connect_addrs = asterism_slist_append(connect_addrs, "tcp://127.0.0.1:8081");
    asterism_set_option(as, ASTERISM_OPT_CONNECT_ADDRS, connect_addrs);
    asterism_slist_free_all(connect_addrs);
    */

    assert(!asterism_prepare(as));
    assert(!asterism_run(as));

    asterism_destroy(as);
    return ret;
}