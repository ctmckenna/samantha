#ifdef __APPLE__

#include "apple.h"
#include "logger.h"
#include <errno.h>
#include <CommonCrypto/CommonDigest.h>
#include "hashtable.h"
#include "ilog2.h"
#include <signal.h>

#undef munmap
#undef mmap
#undef sendfile
#undef sysconf
#undef socket
#undef strerror_r
#undef SHA1
#undef waitid

static struct hashtable mmap_table = HASHTABLE_INITIALIZER;
static int calling_mmap_table = 0;  //if mmap, or mremap called from mmap_table, use mmap_table_map_data instead of hashtable
struct mmap_data mmap_table_map_data;

static struct hashtable sfd_table = HASHTABLE_INITIALIZER;

struct mmap_data {
    int prot;
    int flags;
    int fd;
    off_t offset;
};

struct signalfd_data {
    int write_pipe;
    sigset_t sig_mask;
};

int munmap_apple(void *addr, size_t len) {
    if (!hashtable_is_initialized(&mmap_table))
        abort();
    hashtable_remove(&mmap_table, &addr, sizeof(addr));
    return munmap(addr, len);
}

void *mremap(void *old_address, size_t old_size, size_t new_size, int flags) {
    (void)flags;
    struct mmap_data data;
    if (!calling_mmap_table) {
        calling_mmap_table = 1;
        uint32_t entry_ofs = hashtable_lookup(&mmap_table, &old_address, sizeof(old_address));
        if (entry_ofs == 0)
            abort();
        data = *(struct mmap_data *)hashtable_get_val(&mmap_table, entry_ofs);
        hashtable_remove(&mmap_table, &old_address, sizeof(old_address));
        calling_mmap_table = 0;
    } else
        data = mmap_table_map_data;
    void *new_addr = mmap(NULL, new_size, data.prot, data.flags, data.fd, data.offset);
    int read_and_write = (PROT_READ | PROT_WRITE);
    if ((data.prot & read_and_write) == read_and_write)
        //if PROT_READ not given, assume we're mapping to file, if not PROT_WRITE, then there's nothing to copy
        memcpy(new_addr, old_address, old_size);
    munmap(old_address, old_size);
    if (!calling_mmap_table) {
        calling_mmap_table = 1;
        hashtable_insert(&mmap_table, &new_addr, sizeof(new_addr), &data, sizeof(data));
        calling_mmap_table = 0;
    }
    return new_addr;
}

void *mmap_apple(void *addr, size_t length, int prot, int flags, int fd, off_t offset) {
    if (!calling_mmap_table && !hashtable_is_initialized(&mmap_table)) {
        calling_mmap_table = 1;
        hashtable_init(&mmap_table, 128);
        calling_mmap_table = 0;
    }
    void *new_addr = mmap(addr, length, prot, flags, fd, offset);
    struct mmap_data data = { prot, flags, fd, offset };
    if (calling_mmap_table)
        mmap_table_map_data = data;
    else {
        calling_mmap_table = 1;
        hashtable_insert(&mmap_table, &new_addr, sizeof(new_addr), &data, sizeof(data));
        calling_mmap_table = 0;
    }
    return new_addr;
}

/* only available flag is EPOLL_CLOEXEC */
int epoll_create1(int flags) {
    kqfd = kqueue();
    if (flags & EPOLL_CLOEXEC)
        fcntl(kqfd, F_SETFD, fcntl(kqfd, F_GETFD) | FD_CLOEXEC);
    return kqfd;
}

static int sigset_to_signo(sigset_t *sigset) {
    static int masks_initialized = 0;
    static int signals[32];
    static sigset_t cur_sigset;
    static uint8_t cur_state = 0;
    if (!masks_initialized) {
        masks_initialized = 1;
        int signo;
        sigset_t init_sigset;
        for (signo = 1; signo < (int)sizeof(signals); ++signo) {
            sigemptyset(&init_sigset);
            sigaddset(&init_sigset, signo);
            signals[ilog2(init_sigset)] = signo;
        }
        sigemptyset(&cur_sigset);
    }
    if (sigset != NULL) {
        cur_sigset = *sigset;
        cur_state = 0;
    }
    while (cur_state < (uint8_t)sizeof(signals)) {
        uint32_t mask = 1 << cur_state;
        ++cur_state;
        if (cur_sigset & mask)
            return signals[ilog2(mask)];
    }
    return -1;
}

/* event can be null if op is epoll_ctl_del */
int epoll_ctl(int kqfd, int op, int fd, struct epoll_event *event) {
    static const int e_filters[2] = {EPOLLIN, EPOLLOUT};
    static const int k_filters[2] = {EVFILT_READ, EVFILT_WRITE};
    struct kevent k_event;
    int i;
    memset(&k_event, 0, sizeof(k_event));
    k_event.ident = fd;
    k_event.flags = (op&(EPOLL_CTL_ADD|EPOLL_CTL_MOD)?EV_ADD:0);
    if (!(op & EPOLL_CTL_DEL)) {
        k_event.flags |= (event->events&EPOLLONESHOT?EV_ONESHOT:0) | (event->events&EPOLLET?EV_CLEAR:0);
        k_event.udata = (void *)(uint64_t)event->data.fd;//double cast to avoid compiler warning
        for (i = 0; i < 2; ++i) {
            if (event->events & e_filters[i]) {
                k_event.filter = k_filters[i];
                if (0 > kevent(kqfd, &k_event, 1, NULL, 0, 0))
                    return -1;
            }
        }

        if (event->events & SIGNALFD) {
            //EVFILT_SIGNAL
            if (!hashtable_is_initialized(&sfd_table)) abort();
            if (event->data.fd != fd) abort(); //we assume epoll->data.fd is the signalfd
            uint32_t entry_ofs = hashtable_lookup(&sfd_table, &fd, sizeof(fd));
            if (0 == entry_ofs) abort();
            struct signalfd_data *data = (struct signalfd_data *)hashtable_get_val(&sfd_table, entry_ofs);
            k_event.filter = EVFILT_SIGNAL;
            int signo = -1;
            for (signo = sigset_to_signo(&data->sig_mask); signo != -1; signo = sigset_to_signo(NULL)) {
                k_event.ident = signo;
                if (0 > kevent(kqfd, &k_event, 1, NULL, 0, 0))
                    return -1;
            }
        }
        return 0;
    } else
        return LOGGER_PERROR("EPOLL_CTL_DEL not currently handled for OSX"), -1;
}

static void write_signal(int signalfd, int signo) {
    uint32_t entry_ofs = hashtable_lookup(&sfd_table, &signalfd, signalfd);
    if (0 == entry_ofs) abort();
    struct signalfd_data *data = (struct signalfd_data *)hashtable_get_val(&sfd_table, entry_ofs);
    struct signalfd_siginfo siginfo = { signo };
    write(data->write_pipe, &siginfo, sizeof(siginfo));
}

/* epoll_wait with BSD's kqueue */
int epoll_wait(int kqfd, struct epoll_event *events, int maxevents, int timeout) {
    struct kevent k_events[maxevents];
    int i;
    int ret;
    struct timespec ts;
    int16_t filter = 0;
    /* kevent uses timeout if non-null, otherwise ignores */
    const struct timespec *ts_ptr = NULL;
    memset(k_events, 0, sizeof(k_events));
    if (timeout >= 0) {
        ts.tv_sec = timeout / 1000;
        ts.tv_nsec = (timeout % 1000) * 1000000;
        ts_ptr = &ts;
    }
    ret = kevent(kqfd, NULL, 0, k_events, maxevents, ts_ptr);
    if (0 >= ret)
        return ret;
    for (i = 0; i < ret; ++i) {
        filter = k_events[i].filter;
        events[i].events = ((filter == EVFILT_READ || filter == EVFILT_SIGNAL || filter == EVFILT_TIMER) ? EPOLLIN : 0) | ((filter == EVFILT_WRITE) ? EPOLLOUT : 0);
        events[i].data.fd = (int)(uint64_t)k_events[i].udata;
        if (filter == EVFILT_SIGNAL)
            write_signal(events[i].data.fd, k_events[i].ident);
    }
    return ret;
}

/* Creates file descriptor using kqueue() - fd not used, just needed for offset into epoll_fd_map
   Doesn't matter if CLOCK_MONOTONIC or CLOCK_REALTIME is used since only relative timeouts are supported by
   timerfd_settime */
int timerfd_create(int clockid, int flags) {
    (void)clockid;
    (void)flags;
    return kqueue();
}

/* add timer to kqueue here because we can't add a timer to kqueue without also setting its expiration. */
int timerfd_settime(int fd, int flags, const struct itimerspec *new_value, struct itimerspec *old_value) {
    struct kevent k_event;
    int ret;

    if (old_value != NULL)
        return LOGGER_PERROR("timerfd_settime's old_value must be NULL for OSX"), -1;
    if (flags != 0)
        return LOGGER_PERROR("timerfd_settime only handles relative timeouts for OSX"), -1;
    if ((new_value->it_interval.tv_sec != 0 && new_value->it_interval.tv_sec != new_value->it_value.tv_sec) || (new_value->it_interval.tv_nsec != 0 && new_value->it_interval.tv_nsec != new_value->it_value.tv_nsec))
        return LOGGER_PERROR("timerfd_settime only supports intervals on OSX if interval equals initial timeout"), -1;
    memset(&k_event, 0, sizeof(k_event));
    k_event.ident = fd;
    k_event.udata = (void *)(uint64_t)fd;
    k_event.filter = EVFILT_TIMER;
    k_event.data = new_value->it_value.tv_sec * 1000000 + new_value->it_value.tv_nsec/1000;
    k_event.fflags = NOTE_USECONDS;
    /* nonzero it_value arms timer, zero value disarms */
    if (new_value->it_value.tv_sec != 0 || new_value->it_value.tv_nsec != 0)
        k_event.flags |= EV_ADD;
    else
        k_event.flags |= EV_DELETE;
    /* if interval is zero, timer only expires once */
    if (new_value->it_interval.tv_sec == 0 && new_value->it_interval.tv_nsec == 0)
        k_event.flags |= EV_ONESHOT;
    ret = kevent(kqfd, &k_event, 1, NULL, 0, 0);
    return ret - ret;
}

int fstatat(int dirfd, const char *pathname, struct stat *buf, int flags) {
    int cwd = open(".", O_RDONLY);
    int ret_val;
    int fd;

    if (0 > fchdir(dirfd))
        return -1;
    if (flags & AT_SYMLINK_NOFOLLOW) {
        fd = open(pathname, O_NOFOLLOW);
    /* if open failed, likely a symlink */
        if (0 > fd)
            ret_val = lstat(pathname, buf);
        else
            ret_val = fstat(fd, buf);
    } else {
        ret_val = stat(pathname, buf);
    }
    if (0 > fchdir(cwd))
        return -1;
    close(cwd);
    return ret_val;
}

static long phys_pages() {
    int names[2];
    size_t memsize = 0;
    size_t pagesize = 0;
    size_t mem_ret_len = sizeof(memsize);
    size_t page_ret_len = sizeof(pagesize);

    names[0] = CTL_HW;
    names[1] = HW_USERMEM; /* physical memory not used by kernel */
    sysctl(names, 2, &memsize, &mem_ret_len, NULL, 0);

    names[1] = HW_PAGESIZE;
    sysctl(names, 2, &pagesize, &page_ret_len, NULL, 0);

    return (long)(memsize / pagesize);
}

/* changed name of sysconf to catch _SC_PHYS_PAGES */
long sysconf_apple(int name) {
    if (name == _SC_PHYS_PAGES)
        return phys_pages();
    else
        return sysconf(name);
}

/* send_file_apple implements linux's sendfile using bsd's sendfile */
ssize_t send_file_apple(int out_fd, int in_fd, off_t *offset, size_t count) {
    size_t start_file_ofs;
    off_t filesize;
    off_t bytes_read = count;
    off_t start_offs = (offset == NULL) ? lseek(in_fd, 0, SEEK_CUR) : *offset;
    int ret =  sendfile(in_fd, out_fd, start_offs, &bytes_read, (struct sf_hdtr *)NULL, 0);
    int err = errno;
  /* if 0, we finished file */
    if (bytes_read == 0) {
        start_file_ofs = lseek(in_fd, 0, SEEK_CUR);
        filesize = lseek(in_fd, 0, SEEK_END);
        bytes_read = filesize - start_offs;
        if (offset != NULL) {
            *offset = filesize;
            lseek(in_fd, start_file_ofs, SEEK_SET);
        }
    } else
        (offset != NULL) ? *offset += bytes_read : lseek(in_fd, bytes_read, SEEK_CUR);

    errno = err;
    if (0 > ret)
        return ret;
    else
        return bytes_read;
}

char *strerror_r_apple(int errnum, char *buf, size_t buflen) {
    strerror_r(errnum, buf, buflen);
    return buf;
}

unsigned char *SHA1_apple(const unsigned char *d, size_t n, unsigned char *md) {
    return CC_SHA1(d, n, md);
}

 /* call pipe and set flags on file descriptors.
 */
int pipe2(int fildes[2], int flags) {
    int i;
    if (0 > pipe(fildes))
        return -1;
    for (i = 0; i < 2 && fcntl(fildes[i], F_SETFL, (fcntl(fildes[i],F_GETFL)) | flags) >= 0; ++i);
    if (i < 2)
        return -1;
    return 0;
}

char *strchrnul(const char *s, int c) {
    for (; *s != c && *s; ++s);
    return (char *)s;
}

uint64_t be64toh(uint64_t big_endian_64bits) {
    #ifdef __LITTLE_ENDIAN__
    return ((uint64_t)ntohl((uint32_t)big_endian_64bits)) << 32 | ((uint64_t)ntohl((uint32_t)(big_endian_64bits >> 32)));
    #elif __BIG_ENDIAN__
    return big_endian_64bits;
    #else
    abort();
    return 0;
    #endif
}

uint64_t htobe64(uint64_t host_64bits) {
    #ifdef __LITTLE_ENDIAN__
    return ((uint64_t)htonl((uint32_t)host_64bits)) << 32 | (uint64_t)htonl((uint32_t)(host_64bits >> 32));
    #elif __BIG_ENDIAN__
    return host_64bits;
    #else
    abort();
    return 0;
    #endif
}

int accept4(int socket, struct sockaddr *addr_buf, socklen_t *addr_len, int flags) {
    int sfd = accept(socket, addr_buf, addr_len);
    if (flags & SOCK_CLOEXEC)
        fcntl(sfd, F_SETFD, fcntl(sfd, F_GETFD) | FD_CLOEXEC);
    if (flags & SOCK_NONBLOCK)
        fcntl(sfd, F_SETFL, fcntl(sfd, F_GETFL) | O_NONBLOCK);
    return sfd;
}

int socket_apple(int socket_family, int socket_type, int protocol) {
    int sfd = socket(socket_family, socket_type & ~SOCK_NONBLOCK, protocol);
    if (socket_type & SOCK_NONBLOCK)
        fcntl(sfd, F_SETFL, fcntl(sfd, F_GETFL) | O_NONBLOCK);
    return sfd;
}

//only works if signalfd added to epoll
int signalfd(int fd, const sigset_t *mask, int flags) {
    if (fd != -1) {
        LOGGER_PERROR("Mac OSX ribs2 does not currently support changes to signalfd");
        abort();
    }
    if (!hashtable_is_initialized(&sfd_table))
        hashtable_init(&sfd_table, 64);
    int signal_pipe[2];
    if (0 > pipe2(signal_pipe, flags))
        return -1;
    struct signalfd_data data = { signal_pipe[1], *mask };
    hashtable_insert(&sfd_table, &signal_pipe[0], sizeof(signal_pipe[0]), &data, sizeof(data));
    return signal_pipe[0];
}

int waitid_apple(idtype_t idtype, id_t id, siginfo_t *infop, int options) {
    if (options & (WNOWAIT | WCONTINUED)) {
        LOGGER_PERROR("Mac OSX waitid doesn't support WNOWAIT or WCONTINUED options");
        abort();
    }
    if (options & WSTOPPED) {
        options &= ~WSTOPPED;
        options |= WUNTRACED;
    }
    int stat_loc = 0;
    pid_t pid = 0;
    switch(idtype) {
    case P_PID:
        pid = wait4(id, &stat_loc, options, NULL);
        break;
    case P_PGID:
        pid = wait4(id * -1, &stat_loc, options, NULL);
        break;
    case P_ALL:
        pid = wait4(-1, &stat_loc, options, NULL);
        break;
    }
    infop->si_signo = SIGCHLD;
    if (pid != -1)
        infop->si_pid = pid;
    if (WIFEXITED(stat_loc)) {
        infop->si_code = CLD_EXITED;
        infop->si_status = WEXITSTATUS(stat_loc);
    } else if (WIFSIGNALED(stat_loc))
        infop->si_code = CLD_KILLED;
    if (pid == -1)
        return -1;
    return 0;
}

#define munmap munmap_apple
#define mmap mmap_apple
#define sendfile send_file_apple
#define sysconf sysconf_apple
#define socket socket_apple
#define strerror_r strerror_r_apple
#define SHA1 SHA1_apple
#define waitid waitid_apple

#endif //__APPLE__
