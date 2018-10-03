#include "asterism_test02.h"
#include "../asterism_core.h"
#include "../asterism.h"
#include "../asterism_utils.h"
#include <uv.h>
#include <stdlib.h>
#include <assert.h>

//  int a = 0;
//  char b[1024];
// 
//  static void client_shutdown(
//      uv_shutdown_t* req,
//      int status
//  )
//  {
//      AS_FREE(req);
//  }
// 
//  static void client_write_callback(
//      uv_write_t* req,
//      int status
//  )
//  {
// 	 if(status == 0)
// 		printf("send success %d %d\n", a++, status);
// 	 else {
// 		 printf("send failed %d %d\n", a++, status);
// 		 return;
// 	 }
//      {
//          uv_stream_t* stream = (uv_stream_t*)req->data;
//          uv_write_t* wreq = __zero_malloc_st(uv_write_t);
//          uv_buf_t buf;
//          buf.base = b;
//          buf.len = sizeof(b);
//          wreq->data = stream;
//          //int ret = uv_try_write(stream, &buf, 1);
//          //printf("write ret = %d\n", ret);
//          int ret = uv_is_writable(stream);
//  //         uv_shutdown_t req;
//  //         ret = uv_shutdown(&req, stream, client_shutdown);
//          uv_write(wreq, stream, &buf, 1, client_write_callback);
//      }
//      AS_FREE(req);
//  }
// 
// 
//  static void incoming_read_cb(
// 	 uv_stream_t *stream,
// 	 ssize_t nread,
// 	 const uv_buf_t *buf)
//  {
// 	 if (nread > 0)
// 	 {
// 		 goto cleanup;
// 	 }
// 	 else if (nread == 0)
// 	 {
// 		 goto cleanup;
// 	 }
// 	 else if (nread == UV_EOF)
// 	 {
// 		 printf("shutdown\n");
// 		 goto cleanup;
// 	 }
// 	 else
// 	 {
// 		 printf("closed\n");
// 		 goto cleanup;
// 	 }
//  cleanup:
// 	 if (buf && buf->base)
// 		 AS_FREE(buf->base);
//  }
// 
//  static void incoming_data_read_alloc_cb(
// 	 uv_handle_t *handle,
// 	 size_t suggested_size,
// 	 uv_buf_t *buf)
//  {
// 	 buf->len = suggested_size;
// 	 buf->base = malloc(suggested_size);
//  }
// 
//  static void client_connected(
//      uv_connect_t* req,
//      int status
//  )
//  {
//      int ret = 0;
// 	 if (status == 0)
// 		 printf("connected\n");
// 	 else {
// 		 printf("connected failed\n");
// 		 return;
// 	 }
//      uv_stream_t* stream = (uv_stream_t*)req->data;
//      uv_write_t* wreq = __zero_malloc_st(uv_write_t);
//      uv_buf_t buf;
//      buf.base = b;
//      buf.len = sizeof(b);
//      wreq->data = stream;
// 
// 	 ret = uv_read_start(stream, incoming_data_read_alloc_cb, incoming_read_cb);
// 	 ret = uv_read_stop(stream);
//      ret = uv_is_writable(stream);
//      uv_write(wreq, stream, &buf, 1, client_write_callback);
//  }

int asterism_test02()
{
    int ret = ASTERISM_E_OK;
	//{
	//	int ret = 0;
	//	uv_loop_t *loop = uv_loop_new();
	//	uv_tcp_t client_socket;
	//	uv_connect_t client_conn;
	//	struct sockaddr_in client_addr;

	//	ret = uv_tcp_init(loop, &client_socket);
	//	ret = uv_ip4_addr("192.168.31.13", (int)8080, &client_addr);
	//	client_conn.data = &client_socket;
	//	ret = uv_tcp_connect(&client_conn, &client_socket, (const struct sockaddr*)&client_addr, client_connected);

	//	uv_run(loop, UV_RUN_DEFAULT);
	//}

    printf("libuv: %s\n", uv_version_string());
    printf("asterism: %s\n", asterism_version());

    asterism_set_log_level(ASTERISM_LOG_DEBUG);
    asterism as = asterism_create();
    assert(as);

    //struct asterism_slist *inner_addrs = 0;
    //inner_addrs = asterism_slist_append(inner_addrs, "http://0.0.0.0:8080");
    //inner_addrs = asterism_slist_append(inner_addrs, "http://[::]:8080");
    //inner_addrs = asterism_slist_append(inner_addrs, "socks5://0.0.0.0:1080");
    asterism_set_option(as, ASTERISM_OPT_INNER_BIND_ADDR, "http://[::]:8080");
	//asterism_set_option(as, ASTERISM_OPT_OUTER_BIND_ADDR, "tcp://0.0.0.0:8081");
	asterism_set_option(as, ASTERISM_OPT_OUTER_BIND_ADDR, "tcp://0.0.0.0:1234");
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