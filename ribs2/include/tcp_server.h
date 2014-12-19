#ifndef _SERVER__H_
#define _SERVER__H_

#include "ribs_defs.h"
#include <stdint.h>
#include "ctx_pool.h"
#include "timeout_handler.h"
#include "object_pool.h"

struct tcp_server_context {
    int fd;
    struct tcp_server *server;
    char user_data[];
};

struct tcp_server_connection_data {
    void (*user_func)(void);              // useful for stateful servers
    char user_data[];
};

#define TCP_SERVER_MAX_WRITE_BUFS 10
struct tcp_server_write_state {
    int fd;
    void *user_arg;
    int iovec_idx;
    size_t out_bufs;
    struct iovec iovec[TCP_SERVER_MAX_WRITE_BUFS + 1];
};

struct tcp_server {
    int fd;
    uint16_t port;
    struct ctx_pool ctx_pool;
    struct object_pool conn_data_pool;
    void (*user_func)(void);
    /* misc ctx */
    struct ribs_context *idle_ctx;
    struct ribs_context *accept_ctx;
    struct timeout_handler timeout_handler;
    size_t stack_size; /* set to zero for auto */
    size_t num_stacks; /* set to zero for auto */
    size_t context_size;
    size_t conn_data_size;
    void (*conn_data_init)(struct tcp_server_connection_data *conn_data);
    void *parent_server;
};

#define TCP_SERVER_INIT_DEFAULTS .port = 8080, .stack_size = 0, .num_stacks = 0, .context_size = 0, .conn_data_size = 0, .conn_data_init = NULL, .parent_server = NULL, .timeout_handler.timeout = 60000
#define TCP_SERVER_INITIALIZER { TCP_SERVER_INIT_DEFAULTS }

void tcp_server_close_connection();
void tcp_server_close_connection1(int fd);
void tcp_server_idle_connection();
void tcp_server_idle_connection1(void (*user_func)(void));
int tcp_server_init(struct tcp_server *server);
int tcp_server_init_acceptor(struct tcp_server *server);
int tcp_server_write(struct vmbuf **buf_arr, size_t in_bufs);
int tcp_server_write_fd(int fd, struct vmbuf **buf_arr, size_t in_bufs);
int tcp_server_write_yield(int fd, struct vmbuf **buf_arr, size_t in_bufs, int (*on_yield)(struct tcp_server_write_state *write_state));
int tcp_server_write_state(struct tcp_server_write_state *write_state, int (*on_yield)(struct tcp_server_write_state *write_state));
int tcp_server_get_ip(int sfd, char *ip_buf, size_t ip_buf_len);
/*
 * inline
 */
static inline struct tcp_server_context *tcp_server_get_context(void) {
    return (struct tcp_server_context *)(current_ctx->reserved);
}

static inline struct tcp_server_connection_data *tcp_server_get_connection_data(int fd) {
    return (struct tcp_server_connection_data *)((epoll_worker_fd_map + fd)->conn_data);
}

static inline struct tcp_server_context *tcp_server_get_fd_context(int fd) {
    return (struct tcp_server_context *)epoll_worker_get_ctx(fd);
}

static inline void tcp_server_yield() {
    struct tcp_server_context *ctx = tcp_server_get_context();
    struct epoll_worker_fd_data *fd_data = epoll_worker_fd_map + ctx->fd;
    timeout_handler_add_fd_data(&ctx->server->timeout_handler, fd_data);
    yield();
    TIMEOUT_HANDLER_REMOVE_FD_DATA(fd_data);
}

static inline int tcp_server_yield1(struct tcp_server_write_state *write_state) {
    (void)write_state;
    tcp_server_yield();
    return 0;
}

static inline int tcp_server_read(struct vmbuf *req) {
    if (0 >= vmbuf_read(req, tcp_server_get_context()->fd)) {
        tcp_server_close_connection();
        return -1;
    }
    return 0;
}

#endif //_SERVER__H_
