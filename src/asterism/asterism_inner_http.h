#ifndef ASTERISM_INNER_HTTP_H_
#define ASTERISM_INNER_HTTP_H_
#include <uv.h>
#include "asterism.h"
#include "asterism_core.h"

struct asterism_http_inner
{
    struct asterism_inner_interface face;
    uv_tcp_t *socket;
    struct asterism_s* asterism;
};

int asterism_inner_http_init(
    struct asterism_s *as,
    const char *ip, unsigned int* port, int ipv6);

#endif