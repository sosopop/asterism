#ifndef ASTERISM_OUTER_TCP_H_
#define ASTERISM_OUTER_TCP_H_
#include "asterism.h"
#include <uv.h>

struct asterism_tcp_outer
{
    uv_tcp_t tcp_obj;
};

int asterism_outer_tcp_bind(struct asterism_s *as);
int asterism_outer_tcp_connect_addr(struct asterism_s *as);

#endif