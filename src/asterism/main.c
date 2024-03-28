#ifdef WIN32
#ifndef _CRTDBG_MAP_ALLOC
#define _CRTDBG_MAP_ALLOC
#endif
#include <stdlib.h>
#include <crtdbg.h>
#endif
#include <stdio.h>
#include <assert.h>
#include <signal.h>

#include "parg.h"
#include "asterism.h"

#ifndef UNIT_TEST

static void help()
{
    printf("asterism - A tool that exposes the client's service interface to the server.\n\n");
    printf("Usage:\n");
    printf("    asterism [options]\n\n");
    printf("Options:\n");
    printf("    -h, --help               Show this help message and exit.\n");
    printf("    -v, --verbose            Enable verbose output.\n");
    printf("    -V, --version            Display the version number of asterism.\n");
    printf("    -i, --in-addr <address>  Set the server's local proxy listen address.\n");
    printf("                             Example: -i http://0.0.0.0:8080\n");
    printf("                             Example: -i socks5://0.0.0.0:8082\n");
    printf("    -o, --out-addr <address> Set the server's remote listen address.\n");
    printf("                             Example: -o tcp://0.0.0.0:1234\n");
    printf("    -r, --remote-addr <address> Set the client's connection address to the server.\n");
    printf("                             Example: -r tcp://1.1.1.1:1234\n");
    printf("    -u, --user <username>    Define the username for server authorization.\n");
    printf("    -p, --pass <password>    Define the password for server authorization.\n");
    printf("    -d, --udp                Enable SOCKS5 UDP support. Disabled by default.\n");
    printf("    -t, --udp-timeout <seconds> Set the UDP idle timeout in seconds. A value of 0 disables the timeout.\n");
    printf("                             Example: -t 60 sets a 60-second timeout.\n\n");
    printf("Examples:\n");
    printf("    asterism -i http://0.0.0.0:8081 -o tcp://0.0.0.0:1234 -v\n");
    printf("    asterism -r tcp://127.0.0.1:1234 -u test -p 12345678 -v\n");
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
#ifdef WIN32
    //_CrtSetBreakAlloc(138);
    _CrtSetDbgFlag(_CrtSetDbgFlag(_CRTDBG_REPORT_FLAG) | _CRTDBG_LEAK_CHECK_DF);
#else
    signal(SIGPIPE, SIG_IGN);
#endif
    int ret = 0;
    struct parg_state ps;
    char verbose = 0;

    int next_option;
    const char *const short_options = "hvVi:o:r:u:p:dt:";
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
        goto cleanup;
cleanup:
    if (as)
    {
        asterism_destroy(as);
    }
#if defined(WIN32)
    assert(_CrtDumpMemoryLeaks() == 0);
#endif
    return ret;
}
#endif