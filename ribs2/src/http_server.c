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
#include "http_server.h"
#include <sys/types.h>
#include <dirent.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <fcntl.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <stdlib.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <sys/uio.h>
#include "mime_types.h"
#include "logger.h"
#include "websocket_server.h"
#include "websocket_log.h"

#ifdef __APPLE__
#include "apple.h"
#else
#include <sys/epoll.h>
#include <sys/sendfile.h>
#endif

#define HTTP_DEF_STR(var,str)                   \
    const char var[]=str
#include "http_defs.h"

#define ACCEPTOR_STACK_SIZE 8192
#define MIN_HTTP_REQ_SIZE 5 // method(3) + space(1) + URI(1) + optional VER...
#define DEFAULT_MAX_REQ_SIZE 1024*1024*1024
#define DEFAULT_NUM_STACKS 64

/* methods */
SSTRL(HEAD, "HEAD " );
SSTRL(GET,  "GET "  );
SSTRL(POST, "POST " );
SSTRL(PUT,  "PUT "  );
/* misc */
SSTRL(HTTP_SERVER_VER, "HTTP/1.1");
SSTRL(HTTP_SERVER_NAME, "ribs2.0");
SSTRL(CRLFCRLF, "\r\n\r\n");
SSTRL(CRLF, "\r\n");
SSTRL(CONNECTION, "\r\nConnection: ");
SSTRL(UPGRADE, "\r\nUpgrade: ");
SSTRL(UPGRADE_WEBSOCKET, "websocket");
SSTRL(CONNECTION_CLOSE, "close");
SSTRL(CONNECTION_KEEPALIVE, "Keep-Alive");
SSTRL(CONTENT_LENGTH, "\r\nContent-Length: ");
SSTRL(SET_COOKIE, "\r\nSet-Cookie: ");
SSTRL(COOKIE_VERSION, "Version=\"1\"");
/* 1xx */
SSTRL(HTTP_STATUS_100, "100 Continue");
SSTRL(EXPECT_100, "\r\nExpect: 100");

static int http_server_process_request(char *method, char *version, char *uri, char *headers);

int http_server_init(struct http_server *server) {
    /*
     * one time global initializers
     */
    if (0 > mime_types_init())
        return LOGGER_ERROR("failed to initialize mime types"), -1;
    if (0 > http_headers_init())
        return LOGGER_ERROR("failed to initialize http headers"), -1;

    if (server->max_req_size == 0)
        server->max_req_size = DEFAULT_MAX_REQ_SIZE;

    server->tcp.user_func = http_server_fiber_main;
    server->tcp.parent_server = server;

    size_t context_size = server->context_size;
    if (server->websocket != NULL) {
        context_size += server->websocket->context_size;
        context_size += sizeof(struct http_server_context) + sizeof(struct websocket_server_context);
        server->tcp.conn_data_size = sizeof(struct websocket_server_connection_data);
        server->tcp.conn_data_init = websocket_init_conn_data;
        websocket_server_init(server->websocket);
    } else
        context_size += sizeof(struct http_server_context);
    server->tcp.context_size = context_size;

    if (0 > tcp_server_init(&server->tcp))
        return -1;
    return 0;
}

int http_server_init_acceptor(struct http_server *server) {
    return tcp_server_init_acceptor(&server->tcp);
}

static int check_persistent(char *p) {
    char *conn = strstr(p, CONNECTION);
    char *h1_1 = strstr(p, " HTTP/1.1");
    // HTTP/1.1
    if ((NULL != h1_1 &&
         (NULL == conn ||
          0 != SSTRNCMPI(CONNECTION_CLOSE, conn + SSTRLEN(CONNECTION)))) ||
        // HTTP/1.0
        (NULL == h1_1 &&
         NULL != conn &&
         0 == SSTRNCMPI(CONNECTION_KEEPALIVE, conn + SSTRLEN(CONNECTION))))
        return 1;
    else
        return 0;
}

void http_server_header_start(const char *status, const char *content_type) {
    struct http_server_context *ctx = http_server_get_context();
    vmbuf_sprintf(&ctx->header, "%s %s\r\nServer: %s\r\nContent-Type: %s%s%s", HTTP_SERVER_VER, status, HTTP_SERVER_NAME, content_type, CONNECTION, ctx->persistent ? CONNECTION_KEEPALIVE : CONNECTION_CLOSE);
}

void http_server_header_start_no_body(const char *status) {
    struct http_server_context *ctx = http_server_get_context();
    vmbuf_sprintf(&ctx->header, "%s %s\r\nServer: %s%s%s", HTTP_SERVER_VER, status, HTTP_SERVER_NAME, CONNECTION, ctx->persistent ? CONNECTION_KEEPALIVE : CONNECTION_CLOSE);
}

void http_server_header_close(void) {
    struct http_server_context *ctx = http_server_get_context();
    vmbuf_strcpy(&ctx->header, CRLFCRLF);
}

void http_server_set_cookie(const char *name, const char *value, uint32_t max_age, const char *path, const char *domain) {
    struct http_server_context *ctx = http_server_get_context();
    vmbuf_sprintf(&ctx->header, "%s%s=\"%s\"", SET_COOKIE, name, value);
    if (path) vmbuf_sprintf(&ctx->header, ";Path=%s", path);
    if (max_age) vmbuf_sprintf(&ctx->header, ";Max-Age=%u", max_age);
    if (domain) vmbuf_sprintf(&ctx->header, ";Domain=%s", domain);
    vmbuf_sprintf(&ctx->header, ";%s", COOKIE_VERSION);
}

void http_server_set_session_cookie(const char *name, const char *value, const char *path) {
    http_server_set_cookie(name, value, 0, path, NULL);
}

struct vmbuf *http_server_begin_cookie(const char *name) {
    struct vmbuf *buf = &http_server_get_context()->header;
    vmbuf_sprintf(buf, "\r\nSet-Cookie: %s=\"", name);
    return buf;
}

struct vmbuf *http_server_end_cookie(time_t expires, const char *domain, const char *path) {
    struct vmbuf *buf = &http_server_get_context()->header;
    struct tm tm;
    gmtime_r(&expires, &tm);
    vmbuf_sprintf(buf, "\";Path=%s;Domain=%s;Expires=", path, domain);
    vmbuf_strftime(buf, "%a, %d-%b-%Y %H:%M:%S %Z", &tm);
    return buf;
}

void http_server_response(const char *status, const char *content_type) {
    struct http_server_context *ctx = http_server_get_context();
    vmbuf_reset(&ctx->header);
    http_server_header_start(status, content_type);
    http_server_header_content_length();
    http_server_header_close();
}

void http_server_response_sprintf(const char *status, const char *content_type, const char *format, ...) {
    struct http_server_context *ctx = http_server_get_context();
    vmbuf_reset(&ctx->header);
    vmbuf_reset(&ctx->payload);
    http_server_header_start(status, content_type);
    va_list ap;
    va_start(ap, format);
    vmbuf_vsprintf(&ctx->payload, format, ap);
    va_end(ap);
    http_server_header_content_length();
    http_server_header_close();
}

void http_server_header_content_length(void) {
    struct http_server_context *ctx = http_server_get_context();
    vmbuf_sprintf(&ctx->header, "%s%zu", CONTENT_LENGTH, vmbuf_wlocpos(&ctx->payload));
}

static inline void http_server_write(void) {
    struct http_server_context *ctx = http_server_get_context();
    struct vmbuf *tosend[2];
    tosend[0] = &ctx->header;
    tosend[1] = &ctx->payload;
    if (0 > tcp_server_write(tosend, 2))
        ctx->persistent = 0;
}

static inline int http_server_handle_req_limit(size_t max_req_size) {
    struct http_server_context *ctx = http_server_get_context();
    if (vmbuf_wlocpos(&ctx->request) > max_req_size) {
        http_server_response(HTTP_STATUS_413, HTTP_CONTENT_TYPE_TEXT_PLAIN);
        http_server_write();
        tcp_server_close_connection();
        return 1;
    }
    return 0;
}

void http_server_fiber_main(void) {
    struct http_server_context *ctx = http_server_get_context();
    ctx->tcp_ctx = tcp_server_get_context();
    ctx->server = ctx->tcp_ctx->server->parent_server;

    struct http_server *server = ctx->server;

    char *URI;
    char *version;
    char *headers;
    char *content;
    size_t content_length;
    ctx->persistent = 0;

    vmbuf_init(&ctx->request, server->init_request_size);
    vmbuf_init(&ctx->header, server->init_header_size);
    vmbuf_init(&ctx->payload, server->init_payload_size);
    size_t max_req_size = server->max_req_size;

    for (;; tcp_server_yield()) {
        if (0 > tcp_server_read(&ctx->request))
            return;
        if (http_server_handle_req_limit(max_req_size))
            return;
        if (vmbuf_wlocpos(&ctx->request) > MIN_HTTP_REQ_SIZE)
            break;
    }
    do {
        if (0 == SSTRNCMP(GET, vmbuf_data(&ctx->request)) || 0 == SSTRNCMP(HEAD, vmbuf_data(&ctx->request))) {
            /* GET or HEAD */
            while (0 != SSTRNCMP(CRLFCRLF,  vmbuf_wloc(&ctx->request) - SSTRLEN(CRLFCRLF))) {
                tcp_server_yield();
                if (0 > tcp_server_read(&ctx->request))
                    return;
                if (http_server_handle_req_limit(max_req_size))
                    return;
            }
            /* make sure the string is \0 terminated */
            /* this will overwrite the first CR */
            *(vmbuf_wloc(&ctx->request) - SSTRLEN(CRLFCRLF)) = 0;
            char *p = vmbuf_data(&ctx->request);
            ctx->persistent = check_persistent(p);
            URI = strchrnul(p, ' '); /* can't be NULL GET and HEAD constants have space at the end */
            *URI = 0;
            ++URI; // skip the space
            p = strchrnul(URI, '\r'); /* HTTP/1.0 */
            headers = p;
            if (0 != *headers) /* are headers present? */
                headers += SSTRLEN(CRLF); /* skip the new line */
            *p = 0;
            p = strchrnul(URI, ' '); /* truncate the version part */
            version = p;
            if (0 != *version)
                ++version;
            *p = 0; /* \0 at the end of URI */
            ctx->content = NULL;
            ctx->content_len = 0;

            /* minimal parsing and call user function - return if switching context to new server */
            if (1 == http_server_process_request(vmbuf_data(&ctx->request), version, URI, headers))
                return;
        } else if (0 == SSTRNCMP(POST, vmbuf_data(&ctx->request)) || 0 == SSTRNCMP(PUT, vmbuf_data(&ctx->request))) {
            /* POST or PUT */
            for (;;) {
                *vmbuf_wloc(&ctx->request) = 0;
                /* wait until we have the header */
                if (NULL != (content = strstr(vmbuf_data(&ctx->request), CRLFCRLF)))
                    break;
                tcp_server_yield();
                if (0 > tcp_server_read(&ctx->request))
                    return;
                if (http_server_handle_req_limit(max_req_size))
                    return;
            }
            *content = 0; /* terminate at the first CR like in GET */
            content += SSTRLEN(CRLFCRLF);
            size_t content_ofs = content - vmbuf_data(&ctx->request);

            if (strstr(vmbuf_data(&ctx->request), EXPECT_100)) {
                vmbuf_sprintf(&ctx->header, "%s %s\r\n\r\n", HTTP_SERVER_VER, HTTP_STATUS_100);
                if (0 > vmbuf_write(&ctx->header, ctx->tcp_ctx->fd)) {
                    tcp_server_close_connection();
                    return;
                }
                vmbuf_reset(&ctx->header);
            }
            ctx->persistent = check_persistent(vmbuf_data(&ctx->request));

            /* parse the content length */
            char *p = strcasestr(vmbuf_data(&ctx->request), CONTENT_LENGTH);
            if (NULL == p) {
                http_server_response(HTTP_STATUS_411, HTTP_CONTENT_TYPE_TEXT_PLAIN);
                break;
            }

            p += SSTRLEN(CONTENT_LENGTH);
            content_length = atoi(p);
            for (;;) {
                if (content_ofs + content_length <= vmbuf_wlocpos(&ctx->request))
                    break;
                tcp_server_yield();
                if (0 > tcp_server_read(&ctx->request))
                    return;
                if (http_server_handle_req_limit(max_req_size))
                    return;
            }
            p = vmbuf_data(&ctx->request);
            URI = strchrnul(p, ' '); /* can't be NULL PUT and POST constants have space at the end */
            *URI = 0;
            ++URI; /* skip the space */
            p = strchrnul(URI, '\r'); /* HTTP/1.0 */
            headers = p;
            if (0 != *headers) /* are headers present? */
                headers += SSTRLEN(CRLF); /* skip the new line */
            *p = 0;
            p = strchrnul(URI, ' '); /* truncate http version */
            version = p;
            if (0 != *version)
                ++version;
            *p = 0; /* \0 at the end of URI */
            ctx->content = vmbuf_data_ofs(&ctx->request, content_ofs);
            *(ctx->content + content_length) = 0;
            ctx->content_len = content_length;

            /* minimal parsing and call user function */
            if (1 == http_server_process_request(vmbuf_data(&ctx->request), version, URI, headers))
                return;
        } else {
            http_server_response(HTTP_STATUS_501, HTTP_CONTENT_TYPE_TEXT_PLAIN);
            break;
        }
    } while(0);

    if (vmbuf_wlocpos(&ctx->header) > 0) {
        epoll_worker_resume_events(ctx->tcp_ctx->fd);
        http_server_write();
    }

    if (ctx->persistent)
        tcp_server_idle_connection();
    else
        tcp_server_close_connection();
}

static int http_server_process_request(char *method, char *version, char *uri, char *headers) {
    struct http_server_context *ctx = http_server_get_context();
    ctx->headers = headers;
    char *query = strchrnul(uri, '?');
    if (*query)
        *query++ = 0;
    ctx->query = query;
    static const char HTTP[] = "http://";
    if (0 == SSTRNCMP(HTTP, uri)) {
        uri += SSTRLEN(HTTP);
        uri = strchrnul(uri, '/');
    }
    ctx->uri = uri;
    if (ctx->server->websocket != NULL) {
        const char *upgrade = strstr(headers, UPGRADE + 2); //headers may not include \r\n
        if (upgrade != NULL && 0 == SSTRNCMPI(UPGRADE_WEBSOCKET, upgrade + SSTRLEN(UPGRADE) - 2)) {
            return websocket_server_handshake(method, version);
        }
    }
    epoll_worker_ignore_events(ctx->tcp_ctx->fd);
    ctx->server->user_func();
    return 0;
}

int http_server_sendfile(const char *filename) {
    return http_server_sendfile2(filename, NULL, NULL);
}

int http_server_sendfile2(const char *filename, const char *additional_headers, const char *ext) {
    if (0 == *filename)
        filename = ".";
    struct http_server_context *ctx = http_server_get_context();
    int ffd = open(filename, O_RDONLY);
    if (ffd < 0)
        return HTTP_SERVER_NOT_FOUND;
    struct stat st;
    if (0 > fstat(ffd, &st)) {
        LOGGER_PERROR(filename);
        close(ffd);
        return HTTP_SERVER_NOT_FOUND;
    }
    if (S_ISDIR(st.st_mode)) {
        close(ffd);
        return 1;
    }

    vmbuf_reset(&ctx->header);

    if (NULL != ext)
        http_server_header_start(HTTP_STATUS_200, mime_types_by_ext(ext));
    else
        http_server_header_start(HTTP_STATUS_200, mime_types_by_filename(filename));
    vmbuf_sprintf(&ctx->header, "%s%lu", CONTENT_LENGTH, (uint64_t)st.st_size);
    if (additional_headers)
        vmbuf_strcpy(&ctx->header, additional_headers);

    http_server_header_close();
    int res = http_server_sendfile_payload(ffd, st.st_size);
    close(ffd);
    if (0 > res)
        LOGGER_PERROR(filename);
    return res;
}

int http_server_sendfile_payload(int ffd, off_t size) {
    struct http_server_context *ctx = http_server_get_context();
    int fd = ctx->tcp_ctx->fd;
    int option = 1;
    if (0 > setsockopt(fd, IPPROTO_TCP, TCP_CORK, &option, sizeof(option)))
        LOGGER_PERROR("TCP_CORK set");
    epoll_worker_resume_events(ctx->tcp_ctx->fd);
    http_server_write();
    vmbuf_reset(&ctx->header);
    off_t ofs = 0;
    for (;;tcp_server_yield()) {
        if (0 > sendfile(fd, ffd, &ofs, size - ofs) && EAGAIN != errno)
            return ctx->persistent = 0, -1;
        if (ofs >= size) break;
    }
    option = 0;
    if (0 > setsockopt(fd, IPPROTO_TCP, TCP_CORK, &option, sizeof(option)))
        LOGGER_PERROR("TCP_CORK release");
    return 0;
}

int http_server_generate_dir_list(const char *URI) {
    struct http_server_context *ctx = http_server_get_context();
    struct vmbuf *payload = &ctx->payload;
    const char *dir = URI;
    if (*dir == '/') ++dir;
    if (0 == *dir)
        dir = ".";
    vmbuf_sprintf(payload, "<html><head><title>Index of %s</title></head>", dir);
    vmbuf_strcpy(payload, "<body>");
    vmbuf_sprintf(payload, "<h1>Index of %s</h1><hr>", dir);

    vmbuf_sprintf(payload, "<a href=\"..\">../</a><br><br>");
    vmbuf_sprintf(payload, "<table width=\"100%%\" border=\"0\">");
    DIR *d = opendir(dir);
    int error = 0;
    if (d) {
        struct dirent de, *dep;
        while (0 == readdir_r(d, &de, &dep) && dep) {
            if (de.d_name[0] == '.')
                continue;
            struct stat st;
            if (0 > fstatat(dirfd(d), de.d_name, &st, 0)) {
                vmbuf_sprintf(payload, "<tr><td>ERROR: %s</td><td>N/A</td></tr>", de.d_name);
                continue;
            }
            const char *slash = (S_ISDIR(st.st_mode) ? "/" : "");
            struct tm t_res, *t;
            t = localtime_r(&st.st_mtime, &t_res);

            vmbuf_strcpy(payload, "<tr>");
            vmbuf_sprintf(payload, "<td><a href=\"%s%s\">%s%s</a></td>", de.d_name, slash, de.d_name, slash);
            vmbuf_strcpy(payload, "<td>");
            if (t)
                vmbuf_strftime(payload, "%F %T", t);
            vmbuf_strcpy(payload, "</td>");
            vmbuf_sprintf(payload, "<td>%lu</td>", (uint64_t)st.st_size);
            vmbuf_strcpy(payload, "</tr>");
        }
        closedir(d);
    }
    vmbuf_strcpy(payload, "<tr><td colspan=3><hr></td></tr></table>");
    vmbuf_sprintf(payload, "<address>RIBS 2.0 Port %hu</address></body>", ctx->server->tcp.port);
    vmbuf_strcpy(payload, "</html>");
    return error;
}

void http_server_close(struct http_server *server) {
    close(server->tcp.fd);
}
