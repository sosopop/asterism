#ifndef ASTERISM_DATAGRAM_H_
#define ASTERISM_DATAGRAM_H_

#include <uv.h>
#include "asterism_core.h"
#include <time.h>
#include "queue.h"


#define ASTERISM_DATAGRAM_FIELDS          \
    uv_udp_t socket;                      \
    struct asterism_s *as;                \
    char buffer[ASTERISM_UDP_BLOCK_SIZE]; \
    unsigned int buffer_len;              \
    uv_udp_send_t send_req;               \
    uv_close_cb _close_cb;                \
    uv_udp_recv_cb _recv_cb;              \
    uv_alloc_cb _alloc_cb;                \
    QUEUE queue;                          \
    unsigned int active_tick_count;


typedef struct asterism_datagram_s asterism_datagram_t;

struct asterism_datagram_s
{
    ASTERISM_HANDLE_FIELDS
    ASTERISM_DATAGRAM_FIELDS
};

int asterism_datagram_init(
    struct asterism_s* as,
    unsigned int crypt,
    uv_alloc_cb alloc_cb,
    uv_udp_recv_cb recv_cb,
    uv_close_cb close_cb,
    struct asterism_datagram_s* datagram);

int asterism_datagram_read(
    struct asterism_datagram_s* datagram);

int asterism_datagram_stop_read(
	struct asterism_datagram_s* datagram);

void asterism_datagram_close(
    uv_handle_t* handle);

int asterism_datagram_write(
    uv_udp_send_t* req,
    struct asterism_datagram_s* datagram,
    const uv_buf_t* bufs,
    uv_udp_send_cb cb);

#endif