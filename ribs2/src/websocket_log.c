#include "websocket_log.h"
#include <string.h>
#include "vmbuf.h"
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

static int fd = -1;
static struct vmbuf log_buf;

void websocket_log_init(const char *filename) {
    if (NULL == filename)
        return;
    if (0 == strcmp("-", filename))
        fd = STDOUT_FILENO;
    else
        fd = open(filename, O_WRONLY | O_APPEND | O_CREAT, 0644);
    vmbuf_init(&log_buf, 4096);
}

static const char *websocket_log_action_to_string(enum websocket_log_action action) {
#define ENUM_CASE(E) case E: return #E
    switch(action) {
        ENUM_CASE(REQUEST);
        ENUM_CASE(BROADCAST);
        ENUM_CASE(RESPONSE);
        ENUM_CASE(ACCEPT_HANDSHAKE);
        ENUM_CASE(REJECT_HANDSHAKE);
    }
    return NULL;
}

void websocket_log_log(int sockfd, enum websocket_log_action action, enum websocket_server_opcode opcode, const char *msg, size_t msg_len) {
    if (0 > fd)
        return;
    vmbuf_reset(&log_buf);
    char ip[16];
    memset(ip, 0, sizeof(ip));
    if (0 > tcp_server_get_ip(sockfd, ip, sizeof(ip)))
        strcpy(ip, "unknown");
    const char *action_str = websocket_log_action_to_string(action);
    const char *opcode_str = websocket_server_opcode_to_string(opcode);
    static const int MAX_ACTION_STR = 16;
    static const int MAX_OPCODE_STR = 16;
    vmbuf_sprintf(&log_buf, "%s %-*s %-*s %.*s\n", ip, MAX_ACTION_STR, action_str, MAX_OPCODE_STR, opcode_str, (int)msg_len, msg);
    vmbuf_write(&log_buf, fd);
}
