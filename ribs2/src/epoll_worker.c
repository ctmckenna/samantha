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
#include "epoll_worker.h"
#include <stdio.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <stdlib.h>
#include <signal.h>
#include "logger.h"
#include <fcntl.h>
#include <errno.h>

#ifdef __APPLE__
#include "apple.h"
#else
#include <sys/epoll.h>
#include <sys/signalfd.h>
#endif

static int ribs_epoll_fd = -1;
struct epoll_event last_epollev;

struct epoll_worker_fd_data *epoll_worker_fd_map;

static struct ribs_context main_ctx = { .memalloc = MEMALLOC_INITIALIZER };
struct ribs_context *current_ctx = &main_ctx;
struct ribs_context *event_loop_ctx;

static int queue_ctx_fd = -1;

#ifdef UGLY_GETADDRINFO_WORKAROUND
static void sigrtmin_to_context(void) {
    struct signalfd_siginfo siginfo;
    while (1) {
       int res = read(last_epollev.data.fd, &siginfo, sizeof(struct signalfd_siginfo));
       if (sizeof(struct signalfd_siginfo) != res || NULL == (void *)siginfo.ssi_ptr) {
           LOGGER_PERROR("sigrtmin_to_ctx got NULL or < 128 bytes: %d", res);
           yield();
       } else
           ribs_swapcurcontext((void *)siginfo.ssi_ptr);
    }
}
#endif

static void pipe_to_context(void) {
    void *ctx;
    while (1) {
        if (sizeof(&ctx) != read(last_epollev.data.fd, &ctx, sizeof(&ctx))) {
            LOGGER_PERROR("read in pipe_to_context");
            yield();
        } else
            ribs_swapcurcontext(ctx);
    }
}

int ribs_epoll_add_fd(int fd, uint32_t events, struct ribs_context* ctx) {
    struct epoll_event ev = { .events = events, .data.fd = fd };
    if (0 > epoll_ctl(ribs_epoll_fd, EPOLL_CTL_ADD, fd, &ev))
        return LOGGER_PERROR("epoll_ctl"), -1;
    epoll_worker_set_fd_ctx(fd, ctx);
    return 0;
}

/*int ribs_epoll_mod(int fd, uint32_t events) {

  }*/

int ribs_epoll_add_signal(int sfd, uint32_t events, struct ribs_context *ctx) {
    #ifdef __APPLE__
    events = (events & ~EPOLLIN) | SIGNALFD;
    #endif
    return ribs_epoll_add_fd(sfd, events, ctx);
}

int ribs_epoll_add_timer(int tfd, uint32_t events, struct ribs_context *ctx) {
    #ifdef __APPLE__
    /* timer added to event queue when armed */
    (void)tfd; (void)events; //assuming events is EPOLLIN since we can't write to a timer
    epoll_worker_set_fd_ctx(tfd, ctx);
    return 0;
    #else
    return ribs_epoll_add_fd(tfd, events, ctx);
    #endif
}

struct ribs_context* small_ctx_for_fd(int fd, size_t reserved_size, void (*func)(void)) {
    void *ctx=ribs_context_create(SMALL_STACK_SIZE, reserved_size, func);
    if (NULL == ctx)
        return LOGGER_PERROR("ribs_context_create"), NULL;
    if (0 > ribs_epoll_add_fd(fd, EPOLLIN, ctx))
        return NULL;
    return ctx;
}

static void event_loop(void) {
    for (;;yield());
}

/* kqueue needs to know if fd is a signal */
struct ribs_context* small_ctx_for_signal(int sfd, size_t reserved_size, void (*func)(void)) {
    void *ctx=ribs_context_create(SMALL_STACK_SIZE, reserved_size, func);
    if (NULL == ctx)
        return LOGGER_PERROR("ribs_context_create"), NULL;
    if (0 > ribs_epoll_add_signal(sfd, EPOLLIN, ctx))
        return NULL;
    return ctx;
}

struct ribs_context* small_ctx_for_timer(int tfd, size_t reserved_size, void (*func)(void)) {
    void *ctx = ribs_context_create(SMALL_STACK_SIZE, reserved_size, func);
    if (NULL == ctx)
        return LOGGER_PERROR("ribs_context_create"), NULL;
    if (0 > ribs_epoll_add_timer(tfd, EPOLLIN, ctx))
        return NULL;
    return ctx;
}

int epoll_worker_init(void) {
    struct rlimit rlim;
    if (0 > getrlimit(RLIMIT_NOFILE, &rlim))
        return LOGGER_PERROR("getrlimit(RLIMIT_NOFILE)"), -1;
    epoll_worker_fd_map = calloc(rlim.rlim_cur, sizeof(struct epoll_worker_fd_data));

    ribs_epoll_fd = epoll_create1(EPOLL_CLOEXEC);
    if (ribs_epoll_fd < 0)
        return LOGGER_PERROR("epoll_create1"), -1;

    /* block some signals */
    sigset_t set;
    sigemptyset(&set);
    sigaddset(&set, SIGPIPE);
    if (-1 == sigprocmask(SIG_BLOCK, &set, NULL))
        return LOGGER_PERROR("sigprocmask"), -1;

#ifdef UGLY_GETADDRINFO_WORKAROUND
    sigemptyset(&set);
    sigaddset(&set, SIGRTMIN);
    if (-1 == sigprocmask(SIG_BLOCK, &set, NULL))
        return LOGGER_PERROR("sigprocmask"), -1;

    /* sigrtmin to context */
    int sfd = signalfd(-1, &set, SFD_NONBLOCK);
    if (0 > sfd)
        return LOGGER_PERROR("signalfd"), -1;
    if (NULL == small_ctx_for_signal(sfd, sigrtmin_to_context))
        return -1;
#endif

    event_loop_ctx = ribs_context_create(SMALL_STACK_SIZE, 0, event_loop);
    /* pipe to context */
    int pipefd[2];
    if (0 > pipe2(pipefd, O_NONBLOCK))
        return LOGGER_PERROR("pipe"), -1;
    if (NULL == small_ctx_for_fd(pipefd[0], 0, pipe_to_context))
        return -1;
    queue_ctx_fd = pipefd[1];
    return ribs_epoll_add_fd(queue_ctx_fd, EPOLLOUT | EPOLLET | EPOLLRDHUP, event_loop_ctx);
}

void epoll_worker_loop(void) {
    ribs_swapcurcontext(event_loop_ctx);
}

void epoll_worker_exit(void) {
    ribs_swapcurcontext(&main_ctx);
}

int ribs_epoll_mod_fd(int fd, uint32_t events) {
    struct epoll_event ev = { .events = events, .data.fd = fd };
    if (0 > epoll_ctl(ribs_epoll_fd, EPOLL_CTL_MOD, fd, &ev))
        return LOGGER_PERROR("epoll_ctl"), -1;
    return 0;
}

void yield() {
  while(0 >= epoll_wait(ribs_epoll_fd, &last_epollev, 1, -1));
  ribs_swapcurcontext(epoll_worker_get_last_context());
}

int queue_current_ctx(void) {
    while (0 > write(queue_ctx_fd, &current_ctx, sizeof(void *))) {
        if (EAGAIN != errno)
            return LOGGER_PERROR("unable to queue context: write"), -1;
        /* pipe is full!!! wait for it to clear
           This is switching to LIFO mode, which can cause IO starvation
           if too many contexes are trying to use this facility, very unlikely
        */
        LOGGER_INFO("Warning: context queue is full");
        struct ribs_context *previous_context = epoll_worker_fd_map[queue_ctx_fd].ctx;
        epoll_worker_fd_map[queue_ctx_fd].ctx = current_ctx;
        yield(); // come back to me when can write
        epoll_worker_fd_map[queue_ctx_fd].ctx = previous_context;
    }
    return 0;
}

void courtesy_yield(void) {
    if (0 == epoll_wait(ribs_epoll_fd, &last_epollev, 1, 0))
        return;
    // save since queue_current_ctx() will override if queue if full;
    struct ribs_context *save_ctx = epoll_worker_get_last_context();
    queue_current_ctx();
    ribs_swapcurcontext(save_ctx);
}
