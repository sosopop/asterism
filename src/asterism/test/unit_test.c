#include "unit_test.h"
#include "asterism_test01.h"
#include "asterism_test02.h"
#include "asterism_test03.h"

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
    assert(!asterism_test01());
    assert(!asterism_test03());
    assert(!asterism_test02());

#if defined(WIN32)
    ret = WSACleanup();
    assert(!ret);

    assert(_CrtDumpMemoryLeaks() == 0);
#endif
    return ret;
}

int ut_server(unsigned short port)
{
    int sock = 0;
    struct sockaddr_in serveraddr;
    memset(&serveraddr, 0, sizeof(serveraddr));
    assert((sock = (int)socket(AF_INET, SOCK_STREAM, 0)) > 0);

    serveraddr.sin_family = AF_INET;
    serveraddr.sin_addr.s_addr = htonl(INADDR_ANY);
    serveraddr.sin_port = htons((unsigned short)port);
    assert(bind(sock, (struct sockaddr *) &serveraddr, sizeof(serveraddr)) >= 0);
    assert(listen(sock, 5) >= 0);
    return sock;
}

int ut_accept(int sock)
{
    int clt = 0;
    struct sockaddr_in clientaddr;
    int clientlen = sizeof(clientaddr);
    memset(&clientaddr, 0, sizeof(clientaddr));

    clt = accept(sock, (struct sockaddr *) 0, 0);
    assert(clt >= 0);
    return clt;
}

int ut_connect(const char *ip, unsigned short port)
{
    int sock = 0;
    assert((sock = (int)socket(AF_INET, SOCK_STREAM, 0)) > 0);
    struct sockaddr_in serv_addr;
    memset(&serv_addr, 0, sizeof(serv_addr));
    assert(uv_ip4_addr(ip, port, &serv_addr) == 0);
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

void ut_close(int s)
{
#ifdef WIN32
    closesocket(s);
#else
    close(s);
#endif
}
#endif