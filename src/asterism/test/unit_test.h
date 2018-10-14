#ifndef UNIT_TEST_H_
#define UNIT_TEST_H_

#ifdef WIN32
#ifndef _CRTDBG_MAP_ALLOC
#define _CRTDBG_MAP_ALLOC
#endif
#include <crtdbg.h>
#endif

#include <stdlib.h>
#include <assert.h>
#include <uv.h>
#include <time.h>

#ifdef WIN32
#include <winsock2.h>
#include <WS2tcpip.h>
#else
#include <memory.h>
#include <unistd.h>
#include <netinet/in.h>
#include <sys/socket.h>
#endif

#include "../asterism.h"

int ut_server(unsigned short port);
int ut_accept(int sock);
int ut_connect(const char *ip, unsigned short port);
void ut_sleep(int t);
void ut_close(int s);

#endif