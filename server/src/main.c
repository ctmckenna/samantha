#include "ribs.h"
#include "sammy_context.h"

static struct hashtable listeners = HASHTABLE_INITIALIZER;


static int broadcast_thing_to_say(struct hashtable *ht, uint32_t rec, void *_say_what) {
    const char *say_what = (const char *)_say_what;
    int fd = *(int *)hashtable_get_key(ht, rec);
    websocket_server_send(WEBSOCKET_TEXT, fd, say_what, strlen(say_what));
    return 0;
}


static void handle_http_request() {
    sammy_context_init();

    const char *say_what = sammy_context_get_query_param("say");
    if (NULL == say_what) {
        http_server_response_sprintf(HTTP_STATUS_200, HTTP_CONTENT_TYPE_TEXT_PLAIN, "give me something to say\n");
        return;
    }

    hashtable_foreach(&listeners, broadcast_thing_to_say, (void *)say_what);
    http_server_response_sprintf(HTTP_STATUS_200, HTTP_CONTENT_TYPE_TEXT_PLAIN, "broadcasted %s\n", say_what);
}

static void handle_websocket_request() {}

static void on_websocket_handshake(struct vmbuf *payload) {
    (void)payload;
    struct websocket_server_context *wctx = websocket_server_get_context();
    int fd = wctx->tcp_ctx->fd;
    hashtable_lookup_insert(&listeners, &fd, sizeof(fd), "", 0);
}

static void handle_websocket_close() {
    struct websocket_server_context *wctx = websocket_server_get_context();
    int fd = wctx->tcp_ctx->fd;
    hashtable_remove(&listeners, &fd, sizeof(fd));
}

int main(void) {
    struct websocket_server websocket = WEBSOCKET_SERVER_INITIALIZER;
    websocket.user_func = handle_websocket_request;
    websocket.on_close = handle_websocket_close;
    websocket.on_handshake = on_websocket_handshake;
    websocket.log = "-";

    struct http_server server = HTTP_SERVER_INITIALIZER;
    server.tcp.port = 8080;
    server.user_func = handle_http_request;
    server.websocket = &websocket;
    server.context_size = sizeof(struct sammy_context);

    hashtable_init(&listeners, 64);

    if (0 > http_server_init(&server)) {
        printf("http_server_init failed\n");
        exit(EXIT_FAILURE);
    }
    if (0 > ribs_server_init(0, NULL, NULL, 1)) {
        printf("ribs_server_init failed\n");
        exit(EXIT_FAILURE);
    }
    if (0 > epoll_worker_init()) {
        printf("epoll_worker_init failed\n");
        exit(EXIT_FAILURE);
    }
    if (0 > http_server_init_acceptor(&server)) {
        printf("http_server_init_acceptor failed\n");
        exit(EXIT_FAILURE);
    }
    ribs_server_start();
    return 0;
}
