#ifdef WIN32
#ifndef _CRTDBG_MAP_ALLOC
#define _CRTDBG_MAP_ALLOC
#endif
#include <crtdbg.h>
#include <winsock2.h>
#endif

#include "test_framework.h"
#include <stdio.h>

// Forward declarations of registration functions
void register_suite_utils(void);
void register_suite_proxy(void);
void register_suite_hooks(void);
void register_suite_timeouts(void);
void register_suite_portal(void);

int main(int argc, char *argv[]) {
#ifdef WIN32
    // Enable memory leak check on exit
    _CrtSetDbgFlag(_CrtSetDbgFlag(_CRTDBG_REPORT_FLAG) | _CRTDBG_LEAK_CHECK_DF);

    WSADATA wsa;
    int ws_ret = WSAStartup(MAKEWORD(2, 2), &wsa);
    if (ws_ret != 0) {
        fprintf(stderr, "WSAStartup failed: %d\n", ws_ret);
        return 1;
    }
#endif

    // Register all test suites
    register_suite_utils();
    register_suite_proxy();
    register_suite_hooks();
    register_suite_timeouts();
    register_suite_portal();

    // Run all tests
    int failures = run_all_tests();

#ifdef WIN32
    WSACleanup();
#endif

    return failures;
}
