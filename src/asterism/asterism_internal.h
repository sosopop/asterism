#ifndef ASTERISM_INTERNAL_H_
#define ASTERISM_INTERNAL_H_

#include "asterism.h"
#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>

#define ASTERISM_VERSION "0.0.0.1"
#define ASTERISM_RECONNECT_DELAY 10000
struct asterism_route_data
{
    int dummy;
};

struct asterism_s
{
    char *http_inner_listen_addr;
    char *tcp_outer_listen_add;
    char *connect_addr;
    char *my_username;
    char *my_password;
    struct asterism_route_data *route_data;
    int dummy;
};

#endif