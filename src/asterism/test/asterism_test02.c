#include "asterism_test02.h"
#include "../asterism_core.h"
#include "../asterism.h"
#include "../asterism_utils.h"
#include <uv.h>
#include <stdlib.h>
#include <assert.h>

// int a = 0;
// char b[1024];

// static void client_shutdown(
//     uv_shutdown_t* req,
//     int status
// )
// {
//     AS_FREE(req);
// }
//
// static void client_write_callback(
//     uv_write_t* req,
//     int status
// )
// {
//     printf("send success %d %d\n", a++, status);
//     {
//         uv_stream_t* stream = (uv_stream_t*)req->data;
//         uv_write_t* wreq = __zero_malloc_st(uv_write_t);
//         uv_buf_t buf;
//         buf.base = b;
//         buf.len = sizeof(b);
//         wreq->data = stream;
//         //int ret = uv_try_write(stream, &buf, 1);
//         //printf("write ret = %d\n", ret);
//         int ret = uv_is_writable(stream);
// //         uv_shutdown_t req;
// //         ret = uv_shutdown(&req, stream, client_shutdown);
//         uv_write(wreq, stream, &buf, 1, client_write_callback);
//     }
//     AS_FREE(req);
// }
//
// static void client_connected(
//     uv_connect_t* req,
//     int status
// )
// {
//     int ret = 0;
//     uv_stream_t* stream = (uv_stream_t*)req->data;
//     uv_write_t* wreq = __zero_malloc_st(uv_write_t);
//     uv_buf_t buf;
//     buf.base = b;
//     buf.len = sizeof(b);
//     wreq->data = stream;
//     ret = uv_is_writable(stream);
//     uv_write(wreq, stream, &buf, 1, client_write_callback);
// }
//
// static void accept_cb(
//     uv_stream_t *stream,
//     int status)
// {
//     int ret = ASTERISM_E_OK;
//     uv_tcp_t* incoming = (uv_tcp_t*)AS_MALLOC(sizeof(uv_tcp_t));
//     ret = uv_tcp_init(stream->loop, incoming);
//     ret = uv_tcp_nodelay(incoming, 1);
//     ret = uv_accept((uv_stream_t*)stream, (uv_stream_t*)incoming);
//
//     //ret = uv_read_start((uv_stream_t*)&incoming, incoming_data_read_alloc_cb, net_data_read_cb);
// }

int asterism_test02()
{
    int ret = ASTERISM_E_OK;
    //     {
    //         int ret = 0;
    //         uv_loop_t *loop = uv_loop_new();
    //         uv_tcp_t client_socket;
    //         uv_connect_t client_conn;
    //         struct sockaddr_in client_addr;
    //
    //         uv_tcp_t client_socket1;
    //         uv_connect_t client_conn1;
    //         struct sockaddr_in client_addr1;
    //
    //         uv_tcp_t sever_socket;
    //         struct sockaddr_in server_addr;
    //         ret = uv_tcp_init(loop, &sever_socket);
    //         ret = uv_ip4_addr("127.0.0.1", (int)8080, &server_addr);
    //         ret = uv_tcp_bind(&sever_socket, (const struct sockaddr *)&server_addr, 0);
    //         ret = uv_listen((uv_stream_t *)&sever_socket, 1024, accept_cb);
    //
    //         ret = uv_tcp_init(loop, &client_socket);
    //         ret = uv_ip4_addr("127.0.0.1", (int)8080, &client_addr);
    //         client_conn.data = &client_socket;
    //         ret = uv_tcp_connect(&client_conn, &client_socket, (const struct sockaddr*)&client_addr, client_connected);
    //
    //         ret = uv_tcp_init(loop, &client_socket1);
    //         ret = uv_ip4_addr("127.0.0.1", (int)8080, &client_addr1);
    //         client_conn1.data = &client_socket1;
    //         ret = uv_tcp_connect(&client_conn1, &client_socket1, (const struct sockaddr*)&client_addr1, client_connected);
    //
    //         uv_run(loop, UV_RUN_DEFAULT);
    //     }

    printf("libuv: %s\n", uv_version_string());
    printf("asterism: %s\n", asterism_version());

    asterism_set_log_level(ASTERISM_LOG_DEBUG);
    asterism as = asterism_create();
    assert(as);

    //struct asterism_slist *inner_addrs = 0;
    //inner_addrs = asterism_slist_append(inner_addrs, "http://0.0.0.0:8080");
    //inner_addrs = asterism_slist_append(inner_addrs, "http://[::]:8080");
    //inner_addrs = asterism_slist_append(inner_addrs, "socks5://0.0.0.0:1080");
    //asterism_set_option(as, ASTERISM_OPT_INNER_BIND_ADDR, "http://[::]:8080");
    //asterism_set_option(as, ASTERISM_OPT_OUTER_BIND_ADDR, "tcp://0.0.0.0:8081");
    assert(!asterism_set_option(as, ASTERISM_OPT_USERNAME, "sosopop"));
    assert(!asterism_set_option(as, ASTERISM_OPT_PASSWORD, "12345678"));
    assert(!asterism_set_option(as, ASTERISM_OPT_CONNECT_ADDR, "tcp://127.0.0.1:1234"));
    //asterism_slist_free_all(inner_addrs);

    /*
    struct asterism_slist *outer_addrs = 0;
    outer_addrs = asterism_slist_append(outer_addrs, "tcp://0.0.0.0:8081");
    outer_addrs = asterism_slist_append(outer_addrs, "kcp://0.0.0.0:1081");
    asterism_set_option(as, ASTERISM_OPT_OUTER_BIND_ADDR, outer_addrs);
    asterism_slist_free_all(outer_addrs);

    struct asterism_slist *connect_addr = 0;
    connect_addr = asterism_slist_append(connect_addr, "tcp://127.0.0.1:8081");
    asterism_set_option(as, ASTERISM_OPT_CONNECT_ADDR, connect_addr);
    asterism_slist_free_all(connect_addr);
    */

    assert(!asterism_prepare(as));
    assert(!asterism_run(as));

    asterism_destroy(as);
    return ret;
}