#ifndef ASTERISM_DATAGRAM_H_
#define ASTERISM_DATAGRAM_H_

#include <uv.h>
#include "asterism_core.h"
#include <time.h>
#include "queue.h"

#define ASTERISM_UDP_BLOCK_SIZE 32 * 1024

#define ASTERISM_DATAGRAM_FIELDS          \
    uv_udp_t socket;                      \
    struct asterism_s *as;                \
    char buffer[ASTERISM_UDP_BLOCK_SIZE]; \
    unsigned int buffer_len;              \
    uv_write_t write_req;                 \
    uv_close_cb _close_cb;                \
    uv_read_cb _read_cb;                  \
    uv_alloc_cb _alloc_cb;                \
    unsigned int active_tick_count;		  \


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
    uv_read_cb read_cb,
    uv_close_cb close_cb,
    struct asterism_datagram_s* datagram);

int asterism_datagram_read(
    struct asterism_datagram_s* stream);

void asterism_datagram_close(
    struct asterism_datagram_s* stream);

int asterism_datagram_write(
    uv_write_t* req,
    struct asterism_datagram_s* stream,
    const uv_buf_t* bufs,
    uv_write_cb cb);

#endif