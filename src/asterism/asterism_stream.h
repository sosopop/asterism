#ifndef ASTERISM_STREAM_H_
#define ASTERISM_STREAM_H_

#include <uv.h>
#include "asterism_core.h"
#include <time.h>
#include "queue.h"


#define ASTERISM_STREAM_FIELDS            \
    uv_tcp_t socket;                      \
    struct asterism_s *as;                \
    struct asterism_stream_s *link;       \
    char buffer[ASTERISM_TCP_BLOCK_SIZE]; \
    unsigned int buffer_len;              \
    uv_write_t write_req;                 \
    uv_getaddrinfo_t *addr_req;           \
    uv_connect_cb _connect_cb;            \
    uv_close_cb _close_cb;                \
    uv_read_cb _read_cb;                  \
    uv_alloc_cb _alloc_cb;                \
    QUEUE queue;                          \
    unsigned int active_tick_count;       \
    unsigned int auto_trans : 1;\
    unsigned int crypt : 1;

typedef struct asterism_stream_s asterism_stream_t;

struct asterism_stream_s
{
    ASTERISM_HANDLE_FIELDS
    ASTERISM_STREAM_FIELDS
};

int asterism_stream_connect(
    struct asterism_s *as,
    const char *host,
    unsigned int port,
    unsigned int auto_trans,
    unsigned int crypt,
    uv_connect_cb connect_cb,
    uv_alloc_cb alloc_cb,
    uv_read_cb read_cb,
    uv_close_cb close_cb,
    asterism_stream_t *stream);

int asterism_stream_accept(
    struct asterism_s *as,
    uv_stream_t *server_stream,
    unsigned int auto_trans,
    unsigned int crypt,
    uv_alloc_cb alloc_cb,
    uv_read_cb read_cb,
    uv_close_cb close_cb,
    asterism_stream_t *stream);

int asterism_stream_read(
    struct asterism_stream_s *stream);

void asterism_stream_close(
    uv_handle_t *handle);

int asterism_stream_end(
    struct asterism_stream_s *stream);

int asterism_stream_trans(
    struct asterism_stream_s *stream);

void asterism_stream_set_autotrans(
    struct asterism_stream_s *stream, unsigned int enable);

void asterism_stream_eaten(
    struct asterism_stream_s *stream,
    unsigned int eaten);

int asterism_stream_write(
    uv_write_t *req,
    struct asterism_stream_s *stream,
    const uv_buf_t* bufs,
    uv_write_cb cb);

#endif // ASTERISM_STREAM_H_