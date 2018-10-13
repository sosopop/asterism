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

#ifdef WIN32
#include <winsock2.h>
#else
#include <netinet/in.h>
#include <sys/socket.h>
#endif

#include "../asterism.h"

int ut_connect(const char* ip, unsigned short port);
void ut_sleep(int t);

#endif