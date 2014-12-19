#include "websocket_server.h"

#include "sstr.h"
#include "http_server.h"
#include "http_defs.h"
#include "malloc.h"
#include "base64.h"
#include "websocket_log.h"
#include <limits.h>
#ifdef __APPLE__
#include "apple.h"
#else
#include <openssl/sha.h>
#endif

SSTRL(GET, "GET");
SSTRL(HTTP_1_1, "HTTP/1.1");

SSTRL(SEC_WEBSOCKET_ACCEPT, "\r\nSec-WebSocket-Accept: ");
SSTRL(SEC_WEBSOCKET_VERSION, "\r\nSec-WebSocket-Version: ");
SSTRL(UPGRADE, "\r\nUpgrade: ");
SSTRL(CONNECTION, "\r\nConnection: ");

SSTRL(WEBSOCKET_TOKEN, "websocket");
SSTRL(UPGRADE_TOKEN, "upgrade");
SSTRL(ACCEPT_CODE, "258EAFA5-E914-47DA-95CA-C5AB0DC85B11");

#define PAYLOAD_LEN(req) (*((uint8_t *)req + 1) & 127)
#define PAYLOAD_LEN_16EXT(req) (ntohs(*(uint16_t *)((char *)req + 2)))
#define PAYLOAD_LEN_64EXT(req) (be64toh(*(uint64_t *)((char *)req + 2)))
#define MASK_KEY_OFS(req) (PAYLOAD_LEN(req) < 126 ? 2 : ((PAYLOAD_LEN(req) == 126) ? 4 : 10))

static struct ctx_pool write_ctx_pool;
static struct object_pool frame_buffer_pool = OBJECT_POOL_INITIALIZER;
static int frame_buffer_pool_initialized = 0;
static const uint16_t DEFAULT_CLOSE_CODE = 1000;
static const int WRITE_CONTEXTS = 8;

struct write_context {
    struct tcp_server_write_state *write_state;
    struct ribs_context *orig_ctx;
};

int websocket_server_init(struct websocket_server *server) {
    websocket_log_init(server->log);
    ctx_pool_init(&write_ctx_pool, WRITE_CONTEXTS, WRITE_CONTEXTS, SMALL_STACK_SIZE, sizeof(struct write_context));
    return 0;
}

static void websocket_server_write_ctx_fiber_main(void) {
    struct ribs_context *orig_ctx = ((struct write_context *)current_ctx->reserved)->orig_ctx;
    struct tcp_server_write_state *write_state = ((struct write_context *)current_ctx->reserved)->write_state;
    tcp_server_write_state(write_state, tcp_server_yield1);
    struct list *frame_buffers = &websocket_server_get_connection_data(write_state->fd)->frame_buffers;
    list_pop_head(frame_buffers);
    struct vmbuf *tosend[2];
    while (!list_empty(frame_buffers)) {
        struct frame_buffer *frame_buffer = LIST_ENT(list_head(frame_buffers), struct frame_buffer, list);
        tosend[0] = &frame_buffer->header;
        tosend[1] = &frame_buffer->payload;
        tcp_server_write_fd(write_state->fd, tosend, 2);
        list_remove(&frame_buffer->list);
    }
    ribs_epoll_mod_fd(write_state->fd, EPOLLIN | EPOLLOUT);
    epoll_worker_set_fd_ctx(write_state->fd, orig_ctx);
}

static inline int websocket_server_broadcast_yield(struct tcp_server_write_state *write_state) {
    struct ribs_context *new_ctx = ctx_pool_get(&write_ctx_pool);
    ribs_makecontext(new_ctx, event_loop_ctx, websocket_server_write_ctx_fiber_main);
    struct write_context *ctx = (struct write_context *)new_ctx->reserved;
    ctx->write_state = write_state;
    ribs_epoll_mod_fd(write_state->fd, EPOLLIN);
    ctx->orig_ctx = epoll_worker_get_ctx(write_state->fd);
    epoll_worker_set_fd_ctx(write_state->fd, new_ctx);
    return 1;
}

static inline int websocket_server_yield(struct tcp_server_write_state *write_state) {
    ribs_epoll_mod_fd(write_state->fd, EPOLLIN);
    tcp_server_yield();
    ribs_epoll_mod_fd(write_state->fd, EPOLLIN | EPOLLOUT);
    return 0;
}

/* broadcast should only be true if we're called from another context */
static inline void websocket_server_write1(int fd, int broadcasting) {
    int (*websocket_write_yield)(struct tcp_server_write_state *write_state);
    if (broadcasting)
        websocket_write_yield = websocket_server_broadcast_yield;
    else
        websocket_write_yield = websocket_server_yield;

    struct vmbuf *tosend[2];
    struct list *frame_list = &websocket_server_get_connection_data(fd)->frame_buffers;
    while (!list_empty(frame_list)) {
        struct frame_buffer *frame_buffer = LIST_ENT(list_head(frame_list), struct frame_buffer, list);
        tosend[0] = &frame_buffer->header;
        tosend[1] = &frame_buffer->payload;
        if (1 == tcp_server_write_yield(fd, tosend, 2, websocket_write_yield))
            //write happens on another ctx
            return;
        list_remove(&frame_buffer->list);
        websocket_server_frame_buffer_return(frame_buffer);
    }
}

static inline void websocket_server_write() {
    websocket_server_write1(websocket_server_get_request_fd(), 0);
}

static inline void websocket_server_write_broadcast(int fd) {
    websocket_server_write1(fd, 1);
}

void websocket_server_frame_buffer_return(struct frame_buffer *frame_buffer) {
    object_pool_put(&frame_buffer_pool, frame_buffer);
}

struct frame_buffer *websocket_server_frame_buffer_get() {
    if (unlikely(!frame_buffer_pool_initialized)) {
        frame_buffer_pool.object_size = sizeof(struct frame_buffer);
        if (0 > object_pool_init(&frame_buffer_pool))
            LOGGER_PERROR("object_pool_init");
        frame_buffer_pool_initialized = 1;
    }
    struct frame_buffer *frame_buffer = object_pool_get(&frame_buffer_pool);
    list_init(&frame_buffer->list);
    vmbuf_init(&frame_buffer->header, 4096);
    vmbuf_init(&frame_buffer->payload, 4096);
    return frame_buffer;
}

static inline int websocket_server_handshake_fail(const char *msg) {
    struct http_server_context *http_ctx = http_server_get_context();
    vmbuf_strcpy(&http_ctx->payload, msg);
    http_server_header_start(HTTP_STATUS_400, HTTP_CONTENT_TYPE_TEXT_PLAIN);

    vmbuf_strcpy(&http_ctx->header, SEC_WEBSOCKET_VERSION);
    vmbuf_strcpy(&http_ctx->header, "13");

    http_server_header_content_length();
    http_server_header_close();
    websocket_log_log(http_ctx->tcp_ctx->fd, REJECT_HANDSHAKE, WEBSOCKET_TEXT, msg, strlen(msg));
    return 0;
}

static inline void websocket_server_add_accept_token(const char *sec_websocket_key, size_t websocket_key_len, struct vmbuf *buf) {
    size_t key_out_len = websocket_key_len + SSTRLEN(ACCEPT_CODE);
    unsigned char *key_out = ribs_malloc(key_out_len);
    memcpy(key_out, sec_websocket_key, websocket_key_len);
    memcpy(key_out + websocket_key_len, ACCEPT_CODE, SSTRLEN(ACCEPT_CODE));
    unsigned char hash[20];
    SHA1(key_out, key_out_len, hash);
    size_t token_ofs = vmbuf_wlocpos(buf);
    size_t token_len = BASE64_ENCODED_LEN(sizeof(hash));
    vmbuf_alloc(buf, token_len);
    ribs_base64_encode_std(vmbuf_data_ofs(buf, token_ofs), &token_len, hash, sizeof(hash), '=');
}

static inline void websocket_server_create_ctx() {
    struct http_server_context *http_ctx = http_server_get_context();
    struct websocket_server *server = http_ctx->server->websocket;
    struct tcp_server_context *tcp_ctx = http_ctx->tcp_ctx;

    // overwrite http_ctx
    struct websocket_server_context *websocket_ctx = websocket_server_get_context();
    websocket_ctx->server = server;
    websocket_ctx->tcp_ctx = tcp_ctx;
}

static void websocket_server_build_header(struct vmbuf *payload, enum websocket_server_opcode opcode, struct vmbuf *header) {
    vmbuf_reset(header);
    uint8_t opcode_byte = (uint8_t)opcode;
    vmbuf_memcpy(header, &opcode_byte, 1);
    size_t payload_len = vmbuf_wlocpos(payload);
    if (payload_len < 126) {
        uint8_t len = (uint8_t)payload_len;
        vmbuf_memcpy(header, &len, sizeof(uint8_t));
    } else if (payload_len <= USHRT_MAX) {
        vmbuf_chrcpy(header, 126);
        uint16_t len = htons((uint16_t)payload_len);
        vmbuf_memcpy(header, &len, sizeof(uint16_t));
    } else {
        vmbuf_chrcpy(header, 127);
        uint64_t len = htobe64((uint64_t)payload_len);
        vmbuf_memcpy(header, &len, sizeof(uint64_t));
    }
    // set fin bit to 1
    *(uint8_t *)vmbuf_data(header) |= 128;
}

static int websocket_server_handle_req_limit(size_t max_req_size) {
    struct websocket_server_context *ctx = websocket_server_get_context();
    if (vmbuf_wlocpos(&ctx->request) > max_req_size) {
        websocket_server_send(WEBSOCKET_END, websocket_server_get_request_fd(), "", 0);
        return 1;
    }
    return 0;
}

static inline int process_frame(int *fin, enum websocket_server_opcode *opcode, size_t *payload_ofs, size_t *payload_len) {
    struct websocket_server_context *ctx = websocket_server_get_context();
    size_t max_req_size = ctx->server->max_req_size;
    size_t min_req_size = 2;
    for (;; tcp_server_yield()) {
        if (0 > tcp_server_read(&ctx->request))
            return -1;
        if (websocket_server_handle_req_limit(max_req_size))
            return -2;
        if (vmbuf_wlocpos(&ctx->request) >= min_req_size)
            break;
    }
    *fin = (*(uint8_t *)vmbuf_data(&ctx->request)) & 128;
    *opcode = (*(uint8_t *)vmbuf_data(&ctx->request)) & 15;
    *payload_len = PAYLOAD_LEN(vmbuf_data(&ctx->request));
    if (*payload_len > 125) {
        if (*payload_len == 126)
            min_req_size = 4;//length stored in 16 bits
        else
            min_req_size = 10;//length stored in 64 bits
        for (;vmbuf_wlocpos(&ctx->request) < min_req_size; tcp_server_yield()) {
            if (0 > tcp_server_read(&ctx->request))
                return -1;
            if (websocket_server_handle_req_limit(max_req_size))
                return -2;
        }
        char *frame_start = vmbuf_data(&ctx->request);
        *payload_len = (*payload_len == 126) ? PAYLOAD_LEN_16EXT(frame_start) : PAYLOAD_LEN_64EXT(frame_start);
    }
    uint32_t mask_key_ofs = MASK_KEY_OFS(vmbuf_data(&ctx->request));
    min_req_size = mask_key_ofs + sizeof(uint32_t);
    for (;;) {
        if (vmbuf_wlocpos(&ctx->request) >= min_req_size)
            break;
        tcp_server_yield();
        if (0 > tcp_server_read(&ctx->request))
            return -1;
        if (websocket_server_handle_req_limit(max_req_size))
            return -2;
    }
    *payload_ofs = mask_key_ofs + sizeof(uint32_t);
    min_req_size = *payload_ofs + *payload_len;
    for (;;) {
        if (vmbuf_wlocpos(&ctx->request) >= min_req_size)
            break;
        tcp_server_yield();
        if (0 > tcp_server_read(&ctx->request))
            return -1;
        if (websocket_server_handle_req_limit(max_req_size))
            return -2;
    }
    uint8_t *key = (uint8_t *)vmbuf_data_ofs(&ctx->request, mask_key_ofs);
    uint32_t i = 0;
    unsigned char *payload = (unsigned char *)vmbuf_data_ofs(&ctx->request, *payload_ofs);
    for (; i < *payload_len; ++i)
        payload[i] = payload[i] ^ key[i % 4];
    payload[*payload_len] = '\0'; //if it's text, make it null terminated
    return 0;
}

static inline void websocket_server_init_ctx(void) {
    struct websocket_server_context *ctx = websocket_server_get_context();
    ctx->tcp_ctx = tcp_server_get_context();
    ctx->server = ((struct http_server *)tcp_server_get_context()->server->parent_server)->websocket;
    vmbuf_init(&ctx->request, ctx->server->init_request_size);
}

static void websocket_server_fiber_main(void) {
    websocket_server_init_ctx();
    struct websocket_server_context *ctx = websocket_server_get_context();
    size_t payload_ofs = 0;
    int first_frame = 1;
    enum websocket_server_opcode opcode;
    enum websocket_server_opcode cur_frame_opcode;
    for (;;) {
        int ret = process_frame(&ctx->fin, &cur_frame_opcode, &payload_ofs, &ctx->content_len);
        if (0 > ret) {
            if (-1 == ret)
                ctx->server->on_close(ctx->tcp_ctx->fd);
            return;
        }
        if (first_frame)
            opcode = cur_frame_opcode;
        if (WEBSOCKET_END == opcode) {
            websocket_server_send(WEBSOCKET_END, websocket_server_get_request_fd(), "", 0);
            tcp_server_idle_connection1(&websocket_server_fiber_main);
            return;
        }
        ctx->opcode = opcode;
        ctx->content = vmbuf_data_ofs(&ctx->request, payload_ofs);
        first_frame = ctx->fin ? 1 : 0;
        char repl_null = ((char *)ctx->content)[ctx->content_len];
        ((char *)ctx->content)[ctx->content_len] = '\0'; //null terminate for TEXT opcode
        websocket_log_log(websocket_server_get_request_fd(), REQUEST, opcode, ctx->content, ctx->content_len);

        ctx->server->user_func();

        ((char *)ctx->content)[ctx->content_len] = repl_null;
        size_t pending_frame_len = vmbuf_wlocpos(&ctx->request) - (payload_ofs + ctx->content_len);
        if (0 == pending_frame_len && first_frame)
            break;
        memcpy(vmbuf_data(&ctx->request), vmbuf_data_ofs(&ctx->request, payload_ofs + ctx->content_len), pending_frame_len);
        vmbuf_wlocset(&ctx->request, pending_frame_len);
    }
    tcp_server_idle_connection1(&websocket_server_fiber_main);
}

static void websocket_server_send_frame(enum websocket_server_opcode opcode, int fd, struct frame_buffer *frame_buffer) {
    websocket_server_build_header(&frame_buffer->payload, opcode, &frame_buffer->header);
    struct websocket_server_connection_data *conn_data = websocket_server_get_connection_data(fd);
    int is_broadcast = current_ctx != epoll_worker_get_ctx(fd);
    if (list_empty(&conn_data->frame_buffers)) {
        list_insert_tail(&conn_data->frame_buffers, &frame_buffer->list);
        if (is_broadcast)
            websocket_server_write_broadcast(fd);
        else
            websocket_server_write();
    } else
        list_insert_tail(&conn_data->frame_buffers, &frame_buffer->list);
    websocket_log_log(fd, is_broadcast ? BROADCAST : RESPONSE, opcode, vmbuf_data(&frame_buffer->payload), vmbuf_wlocpos(&frame_buffer->payload));
}

void websocket_server_send(enum websocket_server_opcode opcode, int fd, const char *payload, size_t payload_len) {
    struct frame_buffer *frame_buffer = websocket_server_frame_buffer_get();
    if (WEBSOCKET_END == opcode) {
        uint16_t close_code = htons(DEFAULT_CLOSE_CODE);
        vmbuf_memcpy(&frame_buffer->payload, &close_code, sizeof(close_code));
    }
    vmbuf_memcpy(&frame_buffer->payload, payload, payload_len);
    websocket_server_send_frame(opcode, fd, frame_buffer);
    if (WEBSOCKET_END == opcode)
        shutdown(fd, SHUT_RDWR);
}

void websocket_server_send_sprintf(enum websocket_server_opcode opcode, int fd, const char *format, ...) {
    struct frame_buffer *frame_buffer = websocket_server_frame_buffer_get();
    if (WEBSOCKET_END == opcode) {
        uint16_t close_code = htons(DEFAULT_CLOSE_CODE);
        vmbuf_memcpy(&frame_buffer->payload, &close_code, sizeof(close_code));
    }
    va_list ap;
    va_start(ap, format);
    vmbuf_sprintf(&frame_buffer->payload, format, ap);
    va_end(ap);
    websocket_server_send_frame(opcode, fd, frame_buffer);
    if (WEBSOCKET_END == opcode)
        shutdown(fd, SHUT_RDWR);
}

/* called from http_server.  If handshake is successful, websocket_server
   takes over management of the tcp connection */
int websocket_server_handshake(char *method, char *version) {
    if (0 != SSTRNCMP(GET, method))
        return websocket_server_handshake_fail("websocket handshake requires GET request");
    if (0 != SSTRNCMP(HTTP_1_1, version))
        return websocket_server_handshake_fail("websocket handshake requires HTTP/1.1");

    struct http_server_context *http_ctx = http_server_get_context();
    struct http_headers h;
    http_headers_init();
    http_headers_parse(http_ctx->headers, &h);
    if (0 != SSTRNCMPI(UPGRADE_TOKEN, h.connection))
        return websocket_server_handshake_fail("websocket handshake requires Connection header with 'upgrade'");
    if (0 != strcmp("13", h.sec_websocket_version))
        return websocket_server_handshake_fail("websocket version must be 13");
    size_t key_len = strlen(h.sec_websocket_key);
    if (key_len > BASE64_ENCODED_LEN(16))
        return websocket_server_handshake_fail("decoded websocket key must be 16 bytes");

    //size_t decoded_len = BASE64_DECODED_LEN(key_len);
    //if (decoded_len != 16)
    //    return websocket_server_handshake_fail("websocket key must be 16 bytes");

    http_server_header_start(HTTP_STATUS_101, HTTP_CONTENT_TYPE_TEXT_PLAIN);

    vmbuf_strcpy(&http_ctx->header, UPGRADE);
    vmbuf_strcpy(&http_ctx->header, WEBSOCKET_TOKEN);

    vmbuf_strcpy(&http_ctx->header, CONNECTION);
    vmbuf_strcpy(&http_ctx->header, UPGRADE_TOKEN);

    vmbuf_strcpy(&http_ctx->header, SEC_WEBSOCKET_ACCEPT);
    websocket_server_add_accept_token(h.sec_websocket_key, key_len, &http_ctx->header);

    vmbuf_reset(&http_ctx->payload);
    http_server_header_content_length();
    http_server_header_close();

    websocket_server_create_ctx();
    if (http_ctx->server->websocket->on_handshake != NULL)
        http_ctx->server->websocket->on_handshake(&http_ctx->payload);
    struct frame_buffer *frame_buffer = websocket_server_frame_buffer_get();
    vmbuf_memcpy(&frame_buffer->header, vmbuf_data(&http_ctx->header), vmbuf_wlocpos(&http_ctx->header));
    vmbuf_memcpy(&frame_buffer->payload, vmbuf_data(&http_ctx->payload), vmbuf_wlocpos(&http_ctx->payload));
    list_insert_tail(&websocket_server_get_connection_data(websocket_server_get_request_fd())->frame_buffers, &frame_buffer->list);
    websocket_server_write();
    tcp_server_idle_connection1(&websocket_server_fiber_main);
    websocket_log_log(http_ctx->tcp_ctx->fd, ACCEPT_HANDSHAKE, WEBSOCKET_TEXT, "", 0);
    return 1;
}

const char *websocket_server_opcode_to_string(enum websocket_server_opcode opcode) {
#define ENUM_CASE(E) case E: return #E
    switch(opcode) {
        ENUM_CASE(WEBSOCKET_TEXT);
        ENUM_CASE(WEBSOCKET_BINARY);
        ENUM_CASE(WEBSOCKET_END);
        ENUM_CASE(WEBSOCKET_PING);
        ENUM_CASE(WEBSOCKET_PONG);
    }
    return NULL;
}
