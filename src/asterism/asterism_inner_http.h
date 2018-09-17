#ifndef ASTERISM_INNER_HTTP_H_
#define ASTERISM_INNER_HTTP_H_
#include "asterism.h"
#include <uv.h>

struct asterism_http_inner
{
    uv_tcp_t *socket;
};

int asterism_inner_http_bind(struct asterism_s *as);

#endif