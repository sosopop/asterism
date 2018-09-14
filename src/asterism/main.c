#include <stdio.h>
#include <assert.h>
#include <uv.h>
#ifdef WIN32
#define _CRTDBG_MAP_ALLOC
#include <windows.h>
#include <stdlib.h>
#include <crtdbg.h>
#endif

#include "asterism.h"

//target_link_libraries(uv advapi32 iphlpapi psapi userenv shell32 ws2_32)
int main(int argc, char const *argv[])
{
#ifdef WIN32
    _CrtSetDbgFlag(_CrtSetDbgFlag(_CRTDBG_REPORT_FLAG) | _CRTDBG_LEAK_CHECK_DF);
#endif

    printf("libuv: %s\n", uv_version_string());
    printf("asterism: %s\n", asterism_version());

    asterism as = asterism_create();

#if defined(WIN32)
    assert(_CrtDumpMemoryLeaks() == 0);
#endif
    return 0;
}
