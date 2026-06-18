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
    unsigned int active_tick_count;       \
    /* Number of in-flight writes on OTHER streams that hold a raw pointer  \
       back to this datagram (e.g. the SOCKS5-UDP relay path queues a write \
       on the TCP control channel and dereferences the datagram in the      \
       write callback). The struct is freed only once the uv handle is      \
       closed AND no such writes remain, to avoid use-after-free when the    \
       idle reaper closes the datagram mid-write. */                        \
    unsigned int pending_writes;          \
    unsigned char uv_closing : 1;


typedef struct asterism_datagram_s asterism_datagram_t;

struct asterism_datagram_s
{
    ASTERISM_HANDLE_FIELDS
    ASTERISM_DATAGRAM_FIELDS
};

int asterism_datagram_init(
    struct asterism_s* as,
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

/* Reference counting for in-flight writes that hold a back-pointer to the
   datagram while it is not actively reading. Call write_ref right before
   queuing such a write and write_unref from its completion callback. The
   datagram memory is freed by whichever of the uv close callback or the last
   write_unref happens last. is_closing reports whether the uv handle has
   already been closed (so the callback must not touch the socket). */
void asterism_datagram_write_ref(
    struct asterism_datagram_s* datagram);

void asterism_datagram_write_unref(
    struct asterism_datagram_s* datagram);

int asterism_datagram_is_closing(
    struct asterism_datagram_s* datagram);

int asterism_datagram_write(
    uv_udp_send_t* req,
    struct asterism_datagram_s* datagram,
    const uv_buf_t* bufs,
    uv_udp_send_cb cb);

#endif
