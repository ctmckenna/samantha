#include "sammy_context.h"

static struct sammy_context *sammy_context_get() {
    return http_server_get_app_context(http_server_get_context());
}

void sammy_context_init() {
    struct http_server_context *hctx = http_server_get_context();
    struct sammy_context *ctx = sammy_context_get();

    hashtable_init(&ctx->query_params, 64);
    http_uri_decode_query_params(hctx->query, &ctx->query_params);
}

const char *sammy_context_get_query_param(const char *param) {
    return hashtable_lookup_str(&sammy_context_get()->query_params, param, NULL);
}
