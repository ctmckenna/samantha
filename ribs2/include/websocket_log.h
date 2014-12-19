#ifndef _ACCESS_LOG__H_
#define _ACCESS_LOG__H_

#include "websocket_server.h"

enum websocket_log_action {
    REQUEST,
    BROADCAST,
    RESPONSE,
    ACCEPT_HANDSHAKE,
    REJECT_HANDSHAKE
};

void websocket_log_init(const char *filename);
void websocket_log_log(int sockfd, enum websocket_log_action action, enum websocket_server_opcode opcode, const char *msg, size_t msg_len);

#endif//_ACCESS_LOG__H_
