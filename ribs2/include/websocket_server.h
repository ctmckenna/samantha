
#ifndef _WEBSOCKET__H_
#define _WEBSOCKET__H_

#include "vmbuf.h"
#include "tcp_server.h"
#include "http_server.h"

enum websocket_server_opcode {
    WEBSOCKET_TEXT = 1,
    WEBSOCKET_BINARY = 2,
    WEBSOCKET_END = 8,
    WEBSOCKET_PING = 9,
    WEBSOCKET_PONG = 10
};

struct websocket_server_context {
    struct tcp_server_context *tcp_ctx;
    struct websocket_server *server;
    struct vmbuf request;
    enum websocket_server_opcode opcode;
    int fin;
    void *content;
    size_t content_len;
    char user_data[];
};

// websocket currently only runs as part of http_server.
struct websocket_server {
    void (*user_func)(void);
    void (*on_handshake)(struct vmbuf *payload);
    void (*on_close)(int fd);
    size_t init_request_size;
    size_t init_header_size;
    size_t init_payload_size;
    size_t max_req_size;
    size_t context_size;
    const char *log;
};

struct frame_buffer {
    struct vmbuf header;
    struct vmbuf payload;
    struct list list;
};

struct websocket_server_connection_data {
    struct list frame_buffers;
};

#define WEBSOCKET_SERVER_INIT_DEFAULTS .on_handshake = NULL, .on_close = NULL, .init_request_size = 8*1024, .init_header_size = 8*1024, .init_payload_size = 8*1024, .max_req_size = 1024*1024*1024, .context_size = 0, .log = "-"
#define WEBSOCKET_SERVER_INITIALIZER { WEBSOCKET_SERVER_INIT_DEFAULTS }

void websocket_server_send(enum websocket_server_opcode opcode, int fd, const char *payload, size_t payload_len);
void websocket_server_send_sprintf(enum websocket_server_opcode opcode, int fd, const char *format, ...);
const char *websocket_server_opcode_to_string(enum websocket_server_opcode opcode);

struct frame_buffer *websocket_server_frame_buffer_get();
void websocket_server_frame_buffer_return(struct frame_buffer *frame_buffer);

/* called by http_server_init */
int websocket_server_init(struct websocket_server *server);
/* http connection to websocket */
int websocket_server_handshake(char *method, char *version);
static inline void websocket_init_conn_data(struct tcp_server_connection_data *conn_data) {
    struct list *frame_list = (struct list *)conn_data->user_data;
    list_init(frame_list);
}

static inline struct websocket_server_connection_data *websocket_server_get_connection_data(int fd) {
    return (struct websocket_server_connection_data *)tcp_server_get_connection_data(fd)->user_data;
}

static inline struct websocket_server_context *websocket_server_get_context(void) {
    struct http_server_context *http_ctx = http_server_get_context();
    return (struct websocket_server_context *)(http_ctx->user_data + http_ctx->server->context_size);
}

static inline struct websocket_server_context *websocket_server_get_fd_context(int fd) {
    return (struct websocket_server_context *)(tcp_server_get_fd_context(fd)->user_data);
}

static inline int websocket_server_get_request_fd() {
    return websocket_server_get_context()->tcp_ctx->fd;
}

#endif //_WEBSOCKET__H_
