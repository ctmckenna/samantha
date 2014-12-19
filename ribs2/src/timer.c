/*
    This file is part of RIBS2.0 (Robust Infrastructure for Backend Systems).
    RIBS is an infrastructure for building great SaaS applications (but not
    limited to).

    Copyright (C) 2012 Adap.tv, Inc.

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
#include "timer.h"
#include "context.h"
#include "epoll_worker.h"
#include "logger.h"
#include "heap.h"
#include <limits.h>

#ifdef __APPLE__
#include "apple.h"
#else
#include <sys/time.h>
#include <sys/timerfd.h>
#endif

struct ribs_timer {
    int tfd;
    struct heap timeout_heap;
};

struct heap_entry {
    struct timer *timer;
    struct timeval ts;
    void (*handler)(struct timer *timer);
};

static struct ribs_timer ribs_timer = { .tfd = -1, .timeout_heap = HEAP_INITIALIZER };

static int timer_cmp(void *_a, void *_b) {
    struct heap_entry *a = (struct heap_entry*)_a;
    struct heap_entry *b = (struct heap_entry *)_b;
    return timercmp(&b->ts, &a->ts, <) ? -1 : 1;
}

static void expiration_handler(void) {
    for (;;yield()) {
        #ifndef __APPLE__
        uint64_t num_exp;
        if (sizeof(num_exp) != read(ribs_timer.tfd, &num_exp, sizeof(num_exp)))
            continue;
        #endif
        struct timeval now;
        gettimeofday(&now, NULL);
        while (!heap_empty(&ribs_timer.timeout_heap)) {
            struct heap_entry *top = heap_top(&ribs_timer.timeout_heap);
            if (timercmp(&top->ts, &now, >)) {
                struct timeval when;
                timersub(&now, &top->ts, &when);
                struct itimerspec timerspec = { {0,0}, { when.tv_sec, when.tv_usec } };
                if (0 > timerfd_settime(ribs_timer.tfd, 0, &timerspec, NULL))
                    LOGGER_PERROR("timerfd_settime");
                break;
            }
            uint32_t entry_ofs = top->timer->entry_ofs;
            top->timer->entry_ofs = UINT_MAX;
            top->handler(top->timer);
            // remove after handler to avoid double settimes if handler adds another timer
            heap_remove(&ribs_timer.timeout_heap, entry_ofs);
        }
    }
}

static int ribs_timer_init(struct ribs_timer *ribs_timer) {
    ribs_timer->tfd = timerfd_create(CLOCK_MONOTONIC, TFD_CLOEXEC | TFD_NONBLOCK);
    if (0 > ribs_timer->tfd)
        return LOGGER_PERROR("timerfd_create"), -1;
    struct ribs_context *ctx = ribs_context_create(1024 * 1024, sizeof(struct ribs_timer *), expiration_handler);
    *(struct ribs_timer **)ctx->reserved = ribs_timer;
    if (0 > ribs_epoll_add_timer(ribs_timer->tfd, EPOLLIN, ctx))
        return LOGGER_PERROR("epoll_add"), close(ribs_timer->tfd), -1;
    if (0 > heap_init(&ribs_timer->timeout_heap, 0, sizeof(struct heap_entry), timer_cmp))
        return LOGGER_PERROR("heap_init"), -1;
    return 0;
}

int ribs_timer_once(time_t msec, struct timer *timer, void (*handler)(struct timer *timer)) {
    if (unlikely(ribs_timer.tfd == -1)) {
        if (0 > ribs_timer_init(&ribs_timer))
            return -1;
    }
    if (timer->entry_ofs < UINT_MAX)
        return LOGGER_ERROR("timer added twice or uninitialized"), -1;
    struct timeval now;
    if (0 > gettimeofday(&now, NULL))
        return -1;
    struct timeval when = { msec / 1000, (msec % 1000) * 1000 };
    struct timeval ts;
    timeradd(&now, &when, &ts);
    struct heap_entry entry = { timer, ts, handler };
    if (heap_empty(&ribs_timer.timeout_heap)) {
        struct itimerspec timerspec = { {0,0}, { when.tv_sec, when.tv_usec } };
        if (0 > timerfd_settime(ribs_timer.tfd, 0, &timerspec, NULL))
            return LOGGER_PERROR("timerfd_settime: %d", ribs_timer.tfd), close(ribs_timer.tfd), -1;
    } else {
        ts = ((struct heap_entry *)heap_top(&ribs_timer.timeout_heap))->ts;
        if (timercmp(&entry.ts, &ts, <)) {
            timersub(&entry.ts, &now, &when);
            struct itimerspec timerspec = {{0,0},{when.tv_sec,when.tv_usec}};
            if (0 > timerfd_settime(ribs_timer.tfd, 0, &timerspec, NULL))
                return LOGGER_PERROR("timerfd_settime: %d", ribs_timer.tfd), close(ribs_timer.tfd), -1;
        }
    }
    timer->entry_ofs = heap_insert(&ribs_timer.timeout_heap, &entry);
    return 0;
}

int ribs_timer_remove(struct timer *timer) {
    if (UINT_MAX == timer->entry_ofs)
        return 0; //nothing to remove
    int is_top = heap_is_top(&ribs_timer.timeout_heap, timer->entry_ofs);
    heap_remove(&ribs_timer.timeout_heap, timer->entry_ofs);
    timer->entry_ofs = UINT_MAX;
    if (!is_top)
        return 0;
    struct timeval now;
    if (0 > gettimeofday(&now, NULL))
        return LOGGER_PERROR("gettimeofday"), -1;
    struct timeval *top_ts = &((struct heap_entry *)heap_top(&ribs_timer.timeout_heap))->ts;
    struct timeval when;
    timersub(top_ts, &now, &when);
    struct itimerspec timerspec = {{0,0},{when.tv_sec,when.tv_usec}};
    if (0 > timerfd_settime(ribs_timer.tfd, 0, &timerspec, NULL))
        return LOGGER_PERROR("timerfd_settime: %d", ribs_timer.tfd), close(ribs_timer.tfd), -1;
    return 0;
}
