#include <stdio.h>
#include <assert.h>
#ifdef WIN32
#define _CRTDBG_MAP_ALLOC
#include <windows.h>
#include <stdlib.h>
#include <crtdbg.h>
#endif

#include <signal.h>

#include "parg.h"
#include "asterism.h"

static void help() {
	printf("asterism - A solution that exposes the client's service interface to the server\n\n");
	printf("Usage example:\n");
	printf("    asterism [(-h|--help)] [(-v|--verbose)] [(-V|--version)] [(-i|--in-addr) string] [(-o|--out-addr) string] [(-r|--remote-addr) string] [(-u|--user) string] [(-p|--pass) string]\n");
	printf("    asterism.exe -i http://0.0.0.0:8081 -o tcp://0.0.0.0:1234 -v\n");
	printf("    asterism.exe -r tcp://127.0.0.1:1234 -usosopop -p12345678 -v\n");
	printf("\n");
	printf("Options:\n");
	printf("    -h or --help: Displays this information.\n");
	printf("    -v or --verbose: Verbose mode on.\n");
	printf("    -V or --version: Displays the current version number.\n");
	printf("    -i or --in-addr string: Server local proxy listen address, example: -i http://0.0.0.0:8080\n");
	printf("    -o or --out-addr string: Server remote listen address, example: -i tcp://0.0.0.0:1234\n");
	printf("    -r or --remote-addr string: Client connect to address, example: -i tcp://1.1.1.1:1234\n");
	printf("    -u or --user string: Client username for Server authorization.\n");
	printf("    -p or --pass string: Client password for Server authorization.\n");
}

static void show_version() {
	printf("%s\n", asterism_version());
}

asterism as = 0;

static void stop_prog(int signo)
{
	if (as) {
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
	const char* const short_options = "hvVi:o:r:u:p:";
	const struct parg_option long_options[] =
	{
		{ "help", 0, NULL, 'h' },
		{ "verbose", 0, NULL, 'v' },
		{ "version", 0, NULL, 'V' },
		{ "in-addr", 1, NULL, 'i' },
		{ "out-addr", 1, NULL, 'o' },
		{ "remote-addr", 1, NULL, 'r' },
		{ "user", 1, NULL, 'u' },
		{ "pass", 1, NULL, 'p' },
		{ NULL, 0, NULL, 0 }
	};

	as = asterism_create();

	parg_init(&ps);

	if (argc == 1)
	{
		help();
		goto cleanup;
	}

	while (1) {
		next_option = parg_getopt_long(&ps, argc, argv, short_options, long_options, NULL);
		if (next_option == -1)
			break;
		switch (next_option) {
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
		case '?':
			help();
			goto cleanup;
		case -1:
			break;
		default:
			return(1);
		}
	}
	ret = asterism_run(as);
	if (ret)
		goto cleanup;
cleanup:
	if (as) {
		asterism_destroy(as);
	}
#if defined(WIN32)
    assert(_CrtDumpMemoryLeaks() == 0);
#endif
    return ret;
}
