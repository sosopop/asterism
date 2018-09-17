#ifndef ASTERISM_CORE_H_
#define ASTERISM_CORE_H_
#include "asterism.h"
#include <uv.h>

#define ASTERISM_VERSION "0.0.0.1"
#define ASTERISM_RECONNECT_DELAY 10000

struct asterism_route_data
{
    int dummy;
};

struct asterism_s
{
    char *inner_bind_addr;
    char *outer_bind_addr;
    char *connect_addr;
    char *username;
    char *password;
    void *inner_stream;
    void *outer_stream;
    asterism_connnect_redirect_hook connect_redirect_hook_cb;
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

#endif