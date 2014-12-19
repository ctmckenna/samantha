#include "tcp_server.h"
#include "logger.h"
#include <netinet/in.h>
#include <netinet/tcp.h>
#include "epoll_worker.h"
#include <unistd.h>
#include <sys/uio.h>
#include <arpa/inet.h>
#include <sys/time.h>
#include <sys/resource.h>

#define ACCEPTOR_STACK_SIZE 8192
#define DEFAULT_NUM_STACKS 64

static void tcp_server_idle_handler(void);
static void tcp_server_accept_connections(void);

static struct object_pool write_state_pool = OBJECT_POOL_INITIALIZER;

int tcp_server_init(struct tcp_server *server) {
    /*
     * idle connection handler
     */
    server->idle_ctx = ribs_context_create(SMALL_STACK_SIZE, sizeof(struct tcp_server *), tcp_server_idle_handler);
    *(struct tcp_server **)server->idle_ctx->reserved = server;

    /*
     * context pool
     */
    if (0 == server->num_stacks)
        server->num_stacks = DEFAULT_NUM_STACKS;
    if (0 == server->stack_size) {
        struct rlimit rlim;
        if (0 > getrlimit(RLIMIT_STACK, &rlim))
            return LOGGER_PERROR("getrlimit(RLIMIT_STACK)"), -1;
        server->stack_size = rlim.rlim_cur;
    }
    LOGGER_INFO("server pool: initial=%zu, grow=%zu, stack_size=%zu", server->num_stacks, server->num_stacks, server->stack_size);
    ctx_pool_init(&server->ctx_pool, server->num_stacks, server->num_stacks, server->stack_size, sizeof(struct tcp_server_context) + server->context_size);

    /*
     * connection data pool
     */
    OBJECT_POOL_INIT(server->conn_data_pool);
    server->conn_data_pool.object_size = sizeof(struct tcp_server_connection_data) + server->conn_data_size;
    if (0 > object_pool_init(&server->conn_data_pool))
        return LOGGER_PERROR("object_pool_init"), -1;

    /*
     * write_state pool
     */
    write_state_pool.object_size = sizeof(struct tcp_server_write_state);
    write_state_pool.initial_size = 10;
    write_state_pool.grow = 20;
    if (0 > object_pool_init(&write_state_pool))
        return LOGGER_PERROR("object_pool_init"), -1;

    /*
     * listen socket
     */
    const int LISTEN_BACKLOG = 32768;
    LOGGER_INFO("listening on port: %d, backlog: %d", server->port, LISTEN_BACKLOG);
    int lfd = socket(PF_INET, SOCK_STREAM | SOCK_NONBLOCK, IPPROTO_TCP);
    if (0 > lfd)
        return -1;

    int rc;
    const int option = 1;
    rc = setsockopt(lfd, SOL_SOCKET, SO_REUSEADDR, &option, sizeof(option));
    if (0 > rc)
        return LOGGER_PERROR("setsockopt, SO_REUSEADDR"), rc;

    rc = setsockopt(lfd, IPPROTO_TCP, TCP_NODELAY, &option, sizeof(option));
    if (0 > rc)
        return LOGGER_PERROR("setsockopt, TCP_NODELAY"), rc;

    struct linger ls;
    ls.l_onoff = 0;
    ls.l_linger = 0;
    rc = setsockopt(lfd, SOL_SOCKET, SO_LINGER, (void *)&ls, sizeof(ls));
    if (0 > rc)
        return LOGGER_PERROR("setsockopt, SO_LINGER"), rc;

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(struct sockaddr_in));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(server->port);
    addr.sin_addr.s_addr = INADDR_ANY;
    if (0 > bind(lfd, (struct sockaddr *)&addr, sizeof(addr)))
        return LOGGER_PERROR("bind"), -1;

    if (0 > listen(lfd, LISTEN_BACKLOG))
        return LOGGER_PERROR("listen"), -1;

    server->accept_ctx = ribs_context_create(ACCEPTOR_STACK_SIZE, sizeof(struct tcp_server *), tcp_server_accept_connections);
    server->fd = lfd;
    *(struct tcp_server **)server->accept_ctx->reserved = server;
    return 0;
}

int tcp_server_write(struct vmbuf **buf_arr, size_t in_bufs) {
    return tcp_server_write_yield(tcp_server_get_context()->fd, buf_arr, in_bufs, tcp_server_yield1);
}

int tcp_server_write_fd(int fd, struct vmbuf **buf_arr, size_t in_bufs) {
    return tcp_server_write_yield(fd, buf_arr, in_bufs, tcp_server_yield1);
}

/* will free write_state unless on_yield does not return 0 */
int tcp_server_write_state(struct tcp_server_write_state *write_state, int (*on_yield)(struct tcp_server_write_state *write_state)) {
    for (;;) {
        ssize_t num_write = writev(write_state->fd, write_state->iovec + write_state->iovec_idx, write_state->out_bufs - write_state->iovec_idx);
        if (0 > num_write) {
            if (EAGAIN == errno) {
                continue;
            } else {
                object_pool_put(&write_state_pool, write_state);
                return -1;
            }
        } else {
            while (num_write && num_write >= (ssize_t)write_state->iovec[write_state->iovec_idx].iov_len) {
                num_write -= write_state->iovec[write_state->iovec_idx].iov_len;
                ++write_state->iovec_idx;
            }
            write_state->iovec[write_state->iovec_idx].iov_len -= num_write;
            write_state->iovec[write_state->iovec_idx].iov_base += num_write;
            if (write_state->iovec[write_state->iovec_idx].iov_len == 0)
                break;
        }
        if (0 != on_yield(write_state))
            return 1;
    }
    object_pool_put(&write_state_pool, write_state);
    return 0;
}

int tcp_server_write_yield(int fd, struct vmbuf **buf_arr, size_t in_bufs, int (*on_yield)(struct tcp_server_write_state *write_state)) {
    if (in_bufs > TCP_SERVER_MAX_WRITE_BUFS)
        return LOGGER_PERROR("tcp_server doesn't currently support writes with more than %d vmbufs - attempted to write with %d", TCP_SERVER_MAX_WRITE_BUFS, in_bufs), -1;
    struct tcp_server_write_state *write_state = object_pool_get(&write_state_pool);
    write_state->fd = fd;
    write_state->out_bufs = 0;
    size_t i = 0;
    for (; i < in_bufs; ++i) {
        if (vmbuf_wlocpos(buf_arr[i]) == 0)
            continue;
        write_state->iovec[write_state->out_bufs] = (struct iovec){ vmbuf_data(buf_arr[i]), vmbuf_wlocpos(buf_arr[i]) };
        ++write_state->out_bufs;
    }
    if (write_state->out_bufs == 0)
        return 0;
    write_state->iovec[write_state->out_bufs] = (struct iovec){NULL, 0};
    write_state->iovec_idx = 0;
    return tcp_server_write_state(write_state, on_yield);
}

void tcp_server_close_connection1(int fd) {
    object_pool_put(&tcp_server_get_context()->server->conn_data_pool, tcp_server_get_connection_data(fd));
    (epoll_worker_fd_map + fd)->conn_data = NULL;
    close(fd);
}

void tcp_server_close_connection() {
    tcp_server_close_connection1(tcp_server_get_context()->fd);
}

void tcp_server_idle_connection1(void (*user_func)(void)) {
    struct tcp_server_context *ctx = tcp_server_get_context();
    struct epoll_worker_fd_data *fd_data = epoll_worker_fd_map + ctx->fd;
    if (NULL == user_func)
        user_func = ctx->server->user_func;
    fd_data->ctx = ctx->server->idle_ctx;
    ((struct tcp_server_connection_data *)fd_data->conn_data)->user_func = user_func;
    timeout_handler_add_fd_data(&ctx->server->timeout_handler, fd_data);
}

void tcp_server_idle_connection() {
    tcp_server_idle_connection1(NULL);
}

static void tcp_server_user_func_wrapper(void) {
    struct tcp_server_context *tcp_ctx = tcp_server_get_context();
    tcp_server_get_connection_data(tcp_ctx->fd)->user_func();
    ctx_pool_put(&tcp_ctx->server->ctx_pool, current_ctx);
}

static void tcp_server_idle_handler(void) {
    struct tcp_server *server = *(struct tcp_server **)current_ctx->reserved;
    for (;;) {
        if (last_epollev.events == EPOLLOUT)
            yield();
        else {
            struct ribs_context *new_ctx = ctx_pool_get(&server->ctx_pool);
            ribs_makecontext(new_ctx, event_loop_ctx, tcp_server_user_func_wrapper);
            int fd = last_epollev.data.fd;
            struct epoll_worker_fd_data *fd_data = epoll_worker_fd_map + fd;
            fd_data->ctx = new_ctx;
            struct tcp_server_context *tcp_ctx = (struct tcp_server_context *)new_ctx->reserved;
            tcp_ctx->fd = fd;
            tcp_ctx->server = server;
            TIMEOUT_HANDLER_REMOVE_FD_DATA(fd_data);
            ribs_swapcurcontext(new_ctx);
        }
    }
}

static struct tcp_server_connection_data *create_connection_data(struct tcp_server *server) {
    struct tcp_server_connection_data *conn_data = (struct tcp_server_connection_data *)object_pool_get(&server->conn_data_pool);
    conn_data->user_func = server->user_func;
    if (server->conn_data_init)
        server->conn_data_init(conn_data);
    return conn_data;
}

static void tcp_server_accept_connections(void) {
    struct tcp_server *server = *(struct tcp_server **)current_ctx->reserved;
    for (;; yield()) {
        struct sockaddr_in new_addr;
        socklen_t new_addr_size = sizeof(struct sockaddr_in);
        int fd = accept4(server->fd, (struct sockaddr *)&new_addr, &new_addr_size, SOCK_CLOEXEC | SOCK_NONBLOCK);
        if (0 > fd)
            continue;

        if (0 > ribs_epoll_add_fd(fd, EPOLLIN | EPOLLOUT | EPOLLET | EPOLLRDHUP, server->idle_ctx)) {
            close(fd);
            continue;
        }
        (epoll_worker_fd_map + fd)->conn_data = create_connection_data(server);

        timeout_handler_add_fd_data(&server->timeout_handler, epoll_worker_fd_map + fd);
    }
}

int tcp_server_init_acceptor(struct tcp_server *server) {
    if (0 > ribs_epoll_add_fd(server->fd, EPOLLIN, server->accept_ctx))
        return -1;
    return timeout_handler_init(&server->timeout_handler);
}

int tcp_server_get_ip(int sfd, char *ip_buf, size_t ip_buf_size) {
    if (ip_buf_size < INET_ADDRSTRLEN)
        return -1;
    struct sockaddr_in sockaddr;
    socklen_t socklen = sizeof(sockaddr);
    if (0 > getpeername(sfd, (struct sockaddr *)&sockaddr, &socklen))
        return -1;
    if (NULL == inet_ntop(AF_INET, &sockaddr.sin_addr, ip_buf, INET_ADDRSTRLEN))
        return -1;
    return 0;
}
