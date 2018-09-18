#ifndef ASTERISM_CORE_H_
#define ASTERISM_CORE_H_
#include "asterism.h"
#include <uv.h>
#include "queue.h"

#define ASTERISM_VERSION "0.0.0.1"
#define ASTERISM_RECONNECT_DELAY 10000
#define ASTERISM_NET_BACKLOG 1024

struct asterism_route_data
{
    int dummy;
};

struct asterism_inner_interface
{
    void* queue[2];
};

struct asterism_outer_interface
{
    void* queue[2];
};

struct asterism_connector_interface
{
    void* queue[2];
};

struct asterism_s
{
    struct asterism_slist *inner_bind_addrs;
    struct asterism_slist *outer_bind_addrs;
    struct asterism_slist *connect_addrs;
    char *username;
    char *password;
    void *inner_stream;
    void *outer_stream;
    asterism_connnect_redirect_hook connect_redirect_hook_cb;
    //listener and connector list
    void* inner_objs[2];
    void* outer_objs[2];
    void* connector_objs[2];
    uv_loop_t *loop;
};

/***
 * over tcp virtual link protocol
 * conv_id 4bytes
 * sequence_number 4bytes
 * ack_sequence_number 4bytes
 * free_buffer_size 4bytes
 * package_size 2bytes
 * payload package_size - head_size
 * */

int asterism_core_prepare(struct asterism_s *as);

int asterism_core_destory(struct asterism_s *as);

int asterism_core_run(struct asterism_s *as);

#endif