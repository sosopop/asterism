#include "asterism_test01.h"
#include "../asterism_core.h"
#include "../asterism.h"
#include "../asterism_utils.h"
#include <uv.h>
#include <stdlib.h>
#include <assert.h>

int asterism_test01()
{
    int ret = ASTERISM_E_OK;

    printf("libuv: %s\n", uv_version_string());
    printf("asterism: %s\n", asterism_version());

    asterism_set_log_level(ASTERISM_LOG_DEBUG);
    asterism as = asterism_create();

    //test asterism_slist
    struct asterism_slist *route_list = 0;
    route_list = asterism_slist_append(route_list, "test1");
    route_list = asterism_slist_append(route_list, "test2");
    route_list = asterism_slist_append(route_list, "test3");
    struct asterism_slist *temp_route_list = route_list;
    int i = 1;
    while (temp_route_list)
    {
        char *temp_buf = 0;
        asterism_snprintf(&temp_buf, 0, "test%d", i++);
        assert(strcmp(temp_buf, temp_route_list->data) == 0);
        free(temp_buf);
        printf("list data: %s\n", temp_route_list->data);
        temp_route_list = temp_route_list->next;
    }
    asterism_slist_free_all(route_list);

    assert(as);
    asterism_destroy(as);
    return ret;
}