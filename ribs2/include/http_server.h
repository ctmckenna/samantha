/*
    This file is part of RIBS2.0 (Robust Infrastructure for Backend Systems).
    RIBS is an infrastructure for building great SaaS applications (but not
    limited to).

    Copyright (C) 2012,2013 Adap.tv, Inc.

    RIBS is free software: you can redistribute it and/or modify
    it under the terms of the GNU Lesser General Public License as published by
    the Free Software Foundation, version 2.1 of the License.

    RIBS is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Lesser General Public License for more details.

    You should have received a copy of the GNU Lesser General Public License
    along with RIBS.  If not, see <http://www.gnu.org/licenses/>.
*/
#ifndef _HTTP_SERVER__H_
#define _HTTP_SERVER__H_

#include "ribs_defs.h"
#include "ctx_pool.h"
#include "vmbuf.h"
#include "sstr.h"
#include "timeout_handler.h"
#include "hashtable.h"
#include "uri_decode.h"
#include "http_headers.h"
#include "tcp_server.h"

struct http_server_context {
    struct tcp_server_context *tcp_ctx;
    struct http_server *server;
    struct vmbuf request;
    struct vmbuf header;
    struct vmbuf payload;
    char *uri;
    char *headers;
    char *query;
    char *content;
    uint32_t content_len;
    int persistent;
    char user_data[];
};

struct http_server {
    struct tcp_server tcp;
    void (*user_func)(void);
    /* misc ctx */
    size_t init_request_size;
    size_t init_header_size;
    size_t init_payload_size;
    size_t max_req_size;
    size_t context_size;
    struct websocket_server *websocket;
};

#define HTTP_SERVER_INIT_DEFAULTS .tcp = TCP_SERVER_INITIALIZER, .init_request_size = 8*1024, .init_header_size = 8*1024, .init_payload_size = 8*1024, .max_req_size = 1024*1024*1024, .context_size = 0, .websocket = NULL
#define HTTP_SERVER_INITIALIZER { HTTP_SERVER_INIT_DEFAULTS }

#define HTTP_SERVER_NOT_FOUND (-2)

int http_server_init(struct http_server *server);
int http_server_init_acceptor(struct http_server *server);
void http_server_header_start(const char *status, const char *content_type);
void http_server_header_start_no_body(const char *status);
void http_server_header_close(void);
void http_server_set_cookie(const char *name, const char *value, uint32_t max_age, const char *path, const char *domain);
void http_server_set_session_cookie(const char *name, const char *value, const char *path);
struct vmbuf *http_server_begin_cookie(const char *name);
struct vmbuf *http_server_end_cookie(time_t expires, const char *domain, const char *path);
void http_server_response(const char *status, const char *content_type);
void http_server_response_sprintf(const char *status, const char *content_type, const char *format, ...);
void http_server_header_content_length(void);
void http_server_fiber_main(void);
int http_server_sendfile(const char *filename);
int http_server_sendfile2(const char *filename, const char *additional_headers, const char *ext);
int http_server_sendfile_payload(int ffd, off_t size);
int http_server_generate_dir_list(const char *filename);
void http_server_close(struct http_server *server);
void http_server_handle_websocket();

/*
 * inline
 */
static inline struct http_server_context *http_server_get_context(void) {
    return (struct http_server_context *)(tcp_server_get_context()->user_data);
}

static inline void *http_server_get_app_context(struct http_server_context *http_server_ctx) {
    return http_server_ctx->user_data;
}

static inline void http_server_decode_uri(char *decoded) {
    struct http_server_context *ctx = http_server_get_context();
    http_uri_decode(ctx->uri, decoded);
}

static inline void http_server_parse_query_params(struct hashtable *query_params) {
    struct http_server_context *ctx = http_server_get_context();
    http_uri_decode_query_params(ctx->query, query_params);
}

#endif // _HTTP_SERVER__H_
