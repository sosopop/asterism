#include "unit_test.h"
#include "asterism_test01.h"
#include "asterism_test02.h"

#ifdef UNIT_TEST

int main(int argc, char *argv[])
{
    int ret = 1;
#ifdef WIN32
    _CrtSetDbgFlag(_CrtSetDbgFlag(_CRTDBG_REPORT_FLAG) | _CRTDBG_LEAK_CHECK_DF);

    WSADATA wsa;
    ret = WSAStartup(MAKEWORD(2, 2), &wsa);
    assert(!ret);
#endif
    ret = asterism_test01();
    assert(!ret);
    ret = asterism_test02();
    assert(!ret);

#if defined(WIN32)
    ret = WSACleanup();
    assert(!ret);

    assert(_CrtDumpMemoryLeaks() == 0);
#endif
    return ret;
}

int ut_connect(const char* ip, unsigned short port)
{
    int sock = 0;
    struct sockaddr_in serv_addr;
    assert((sock = socket(AF_INET, SOCK_STREAM, 0)) > 0);
    memset(&serv_addr, 0, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(port);
    serv_addr.sin_addr.S_un.S_addr = inet_addr(ip);
    assert(serv_addr.sin_addr.S_un.S_addr > 0);
    assert(connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) >= 0);
    return sock;
}


void ut_sleep(int t)
{
#ifdef WIN32
    Sleep(t);
#else
    usleep(t * 1000);
#endif
}

#endif