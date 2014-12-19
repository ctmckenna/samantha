#ifndef _WEB_SERVER__H_
#define _WEB_SERVER__H_

#include "http_server.h"

struct web_server {
    struct http_server http;
    const char *root;
    const char *root_file;
    const char *page404;
    size_t context_size;
};

struct web_server_context {
    struct vmbuf misc_buf;                 /* miscellaneous buffer */
    struct hashtable misc_table;           /* miscellaneous table */
    size_t pending_requests;               /* pending asynchronous requests */
    struct hashtable query_params;
    struct hashtable cookies;
    struct http_headers headers;
    char *uri;                       /* sanitized uri */
    size_t uri_len;
    int uri_argc;                    /* number trailing uri path components */
    char **uri_argv;                /* pointers to uri path components */
    char user_data[];
};

typedef void (*controller_func)(void);
typedef void (*html_func)();  /* replace html_func tag with contents from render_sprintf() or render_partial() */

#define WEB_HTTP_SERVER_INITIALIZER { .user_func = &web_server_main, HTTP_SERVER_INIT_DEFAULTS }
#define WEB_SERVER_INIT_DEFAULTS .http = WEB_HTTP_SERVER_INITIALIZER, .root = "public/", .root_file = "index.html", .page404 = NULL, .context_size = 0
#define WEB_SERVER_INITIALIZER { WEB_SERVER_INIT_DEFAULTS }

/* functions for starting web_server */
int web_server_init(struct web_server *server);
int web_server_init_acceptor(struct web_server *server);
int web_server_run(struct web_server *server);

/* configuration functions */
void web_server_add_controller(const char *uri, controller_func func);//connects uri to controller
void web_server_add_html_func(const char *ident, html_func func);//connects template ident to function

struct web_server_context *web_server_get_context();

/* rendering functions:  All rendering paths are relative to root directory
  'render_page' and 'render_page_as_mimetype' should be called from controllers.
  'render_partial' and 'render_sprintf' should be called from html_func. */
void web_server_render_404();                     /* uses 404 file given in web_server struct */
void web_server_render_partial(const char *path); /* renders file with .rp (ribs partial) extension */
void web_server_render_sprintf(const char *format, ...); /* renders format string (rendering from html_func) */
void web_server_render_page(const char *path);    /* renders file with valid mimetype extension */
void web_server_render_page_as_mimetype(const char *path, const char *mime_type); /* renders file as mime_type */
void web_server_get_filename(const char *uri_path, struct vmbuf *buf, size_t *ofs);

/* initializes web server context and calls controller.
   Tries to render page if controller fails to do */
void web_server_main();

#endif //_WEB_SERVER__H_
