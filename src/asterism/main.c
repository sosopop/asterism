#ifdef _WIN32
#ifndef _CRTDBG_MAP_ALLOC
#define _CRTDBG_MAP_ALLOC
#endif
#include <stdlib.h>
#include <crtdbg.h>
#else
#include <stdlib.h>
#endif
#include <stdio.h>
#include <assert.h>
#include <signal.h>

#include "parg.h"
#include "asterism.h"

#ifndef UNIT_TEST

static void help()
{
    printf("asterism - A reverse proxy tunnel. Run as relay or agent mode.\n\n");
    printf("Usage:\n");
    printf("    asterism [options]\n\n");
    printf("Options:\n");
    printf("    -h, --help               Show this help message and exit.\n");
    printf("    -v, --verbose            Enable verbose output.\n");
    printf("    -V, --version            Display the version number of asterism.\n");
    printf("    -i, --in-addr <address>  Set the relay's proxy listen address.\n");
    printf("                             Example: -i http://0.0.0.0:8080\n");
    printf("                             Example: -i socks5://0.0.0.0:8082\n");
    printf("    -o, --out-addr <address> Set the relay's agent connection listen address.\n");
    printf("                             Example: -o tcp://0.0.0.0:1234\n");
    printf("    -r, --remote-addr <address> Set the agent's relay connection address.\n");
    printf("                             Example: -r tcp://1.1.1.1:1234\n");
    printf("    -u, --user <username>    Set the agent authentication username.\n");
    printf("    -p, --pass <password>    Set the agent authentication password.\n");
    printf("    -d, --udp                Enable SOCKS5 UDP support. Disabled by default.\n");
    printf("    -t, --udp-timeout <seconds> Set the UDP idle timeout in seconds. A value of 0 disables the timeout.\n");
    printf("                             Example: -t 60 sets a 60-second timeout.\n");
    printf("    -A, --auth-sessions      Require HTTP basic authentication for the session list (/sessions).\n");
    printf("        --public-sessions    Allow unauthenticated access to /sessions.\n");
    printf("    -U, --session-user <user> Set the username for the session list authentication.\n");
    printf("    -P, --session-pass <pass> Set the password for the session list authentication.\n");
    printf("    -L, --portal <rule>      Enable Portal mode (local port forwarding).\n");
    printf("                             Format: local_addr:local_port#relay_addr#remote_addr:remote_port\n");
    printf("                             Example: -L 127.0.0.1:3306#http://admin:admin123@1.2.3.4:8011#192.168.1.100:3306\n\n");
    printf("Examples:\n");
    printf("    Relay mode:\n");
    printf("      asterism -i http://0.0.0.0:8081 -o tcp://0.0.0.0:1234 -v\n");
    printf("      asterism -i http://0.0.0.0:8081 -o tcp://0.0.0.0:1234 -A -U admin -P admin123 -v\n");
    printf("    Agent mode:\n");
    printf("      asterism -r tcp://127.0.0.1:1234 -u test -p 12345678 -v\n");
    printf("    Portal mode:\n");
    printf("      asterism -L 127.0.0.1:3306#http://admin:admin123@1.2.3.4:8011#192.168.1.100:3306 -v\n");
}

static void show_version()
{
    printf("%s\n", asterism_version());
}

static asterism as = 0;

static void stop_prog(int signo)
{
    if (as)
    {
        asterism_stop(as);
    }
}

int main(int argc, char *argv[])
{
    signal(SIGINT, stop_prog);
#ifdef _WIN32
    //_CrtSetBreakAlloc(138);
    _CrtSetDbgFlag(_CrtSetDbgFlag(_CRTDBG_REPORT_FLAG) | _CRTDBG_LEAK_CHECK_DF);
#else
    signal(SIGPIPE, SIG_IGN);
#endif
    int ret = 0;
    struct parg_state ps;
    char verbose = 0;

    int next_option;
    const char *const short_options = "hvVi:o:r:u:p:dt:AU:P:L:";
    enum { OPT_PUBLIC_SESSIONS = 1000 };
    const struct parg_option long_options[] =
        {
            {"help", 0, NULL, 'h'},
            {"verbose", 0, NULL, 'v'},
            {"version", 0, NULL, 'V'},
            {"in-addr", 1, NULL, 'i'},
            {"out-addr", 1, NULL, 'o'},
            {"remote-addr", 1, NULL, 'r'},
            {"user", 1, NULL, 'u'},
            {"pass", 1, NULL, 'p'},
            {"udp", 0, NULL, 'd'},
            {"udp-timeout", 1, NULL, 't'},
            {"auth-sessions", 0, NULL, 'A'},
            {"public-sessions", 0, NULL, OPT_PUBLIC_SESSIONS},
            {"session-user", 1, NULL, 'U'},
            {"session-pass", 1, NULL, 'P'},
            {"portal", 1, NULL, 'L'},
            {NULL, 0, NULL, 0}};

    as = asterism_create();

    parg_init(&ps);

    if (argc == 1)
    {
        help();
        goto cleanup;
    }

    while (1)
    {
        next_option = parg_getopt_long(&ps, argc, argv, short_options, long_options, NULL);
        if (next_option == -1)
            break;
        switch (next_option)
        {
        case 'h':
            help();
            goto cleanup;
        case 'v':
            asterism_set_log_level(ASTERISM_LOG_DEBUG);
            break;
        case 'V':
            show_version();
            goto cleanup;
        case 'i':
            ret = asterism_set_option(as, ASTERISM_OPT_INNER_BIND_ADDR, ps.optarg);
            if (ret)
                goto cleanup;
            break;
        case 'o':
            ret = asterism_set_option(as, ASTERISM_OPT_OUTER_BIND_ADDR, ps.optarg);
            if (ret)
                goto cleanup;
            break;
        case 'r':
            ret = asterism_set_option(as, ASTERISM_OPT_CONNECT_ADDR, ps.optarg);
            if (ret)
                goto cleanup;
            break;
        case 'u':
            ret = asterism_set_option(as, ASTERISM_OPT_USERNAME, ps.optarg);
            if (ret)
                goto cleanup;
            break;
        case 'p':
            ret = asterism_set_option(as, ASTERISM_OPT_PASSWORD, ps.optarg);
            if (ret)
                goto cleanup;
            break;
        case 'd':
            ret = asterism_set_option(as, ASTERISM_OPT_SOCKS5_UDP, 1);
            if (ret)
                goto cleanup;
            break;
        case 't':
            ret = asterism_set_option(as, ASTERISM_OPT_UDP_IDLE_TIMEOUT, atoi(ps.optarg));
            if (ret)
                goto cleanup;
            break;
        case 'A':
            ret = asterism_set_option(as, ASTERISM_OPT_SESSION_AUTH, 1);
            if (ret)
                goto cleanup;
            break;
        case OPT_PUBLIC_SESSIONS:
            ret = asterism_set_option(as, ASTERISM_OPT_SESSION_POLICY, ASTERISM_SESSION_POLICY_PUBLIC);
            if (ret)
                goto cleanup;
            break;
        case 'U':
            ret = asterism_set_option(as, ASTERISM_OPT_SESSION_AUTH_USER, ps.optarg);
            if (ret)
                goto cleanup;
            break;
        case 'P':
            ret = asterism_set_option(as, ASTERISM_OPT_SESSION_AUTH_PASS, ps.optarg);
            if (ret)
                goto cleanup;
            break;
        case 'L':
            ret = asterism_set_option(as, ASTERISM_OPT_PORTAL, ps.optarg);
            if (ret)
                goto cleanup;
            break;
        case '?':
            help();
            goto cleanup;
        case -1:
            break;
        default:
            return (1);
        }
    }
    ret = asterism_run(as);
    if (ret)
    {
        fprintf(stderr, "Error: %s\n", asterism_errno_description(ret));
        goto cleanup;
    }
cleanup:
    if (as)
    {
        asterism_destroy(as);
    }
#if defined(_WIN32)
    assert(_CrtDumpMemoryLeaks() == 0);
#endif
    return ret;
}
#endif
