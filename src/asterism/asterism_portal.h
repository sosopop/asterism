#ifndef ASTERISM_PORTAL_H_
#define ASTERISM_PORTAL_H_

#include <uv.h>
#include "asterism.h"
#include "asterism_core.h"
#include "asterism_stream.h"

struct asterism_portal_config_s
{
    char *local_host;
    unsigned int local_port;
    char *relay_host;
    unsigned int relay_port;
    char *relay_user;
    char *relay_pass;
    char *remote_host;
    unsigned int remote_port;
};

struct asterism_portal_s
{
    ASTERISM_HANDLE_FIELDS
    uv_tcp_t listener;
    struct asterism_s *as;
    struct asterism_portal_config_s *config;
};

struct asterism_portal_list_s
{
    struct asterism_portal_s *portal;
    struct asterism_portal_list_s *next;
};

struct asterism_portal_config_list_s
{
    struct asterism_portal_config_s config;
    struct asterism_portal_config_list_s *next;
};

int asterism_portal_parse_rule(const char *rule_str, struct asterism_portal_config_s *config);

int asterism_portal_init(struct asterism_s *as, struct asterism_portal_config_s *config);

void asterism_portal_free_config(struct asterism_portal_config_s *config);

#endif // ASTERISM_PORTAL_H_
