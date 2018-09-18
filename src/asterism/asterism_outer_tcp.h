#ifndef ASTERISM_OUTER_TCP_H_
#define ASTERISM_OUTER_TCP_H_
#include "asterism.h"
#include "asterism_core.h"
#include <uv.h>

struct asterism_tcp_outer
{
    uv_tcp_t *socket;
};

int asterism_outer_tcp_bind(struct asterism_s *as);
int asterism_outer_tcp_connect_addrs(struct asterism_s *as);

#endif