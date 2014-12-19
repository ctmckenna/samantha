#include "web_server.h"
#include "logger.h"
#include "file_mapper.h"
#include "http_defs.h"
#include "mime_types.h"
#include "http_cookies.h"
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <limits.h>

#ifdef __APPLE__
#include "apple.h"
#endif

static struct hashtable controller_map = HASHTABLE_INITIALIZER;
static struct hashtable html_func_map = HASHTABLE_INITIALIZER;
static struct hashtable page_map = HASHTABLE_INITIALIZER;
static char *root = NULL;
static size_t root_len;
static char *root_file = NULL;
static char *page404 = NULL;

struct page_header {
    long last_mod_millis;      /* last modification time of file in millis */
    size_t templ_offs;        /* offset to struct templates array */
};

//template is mapping between <%ident> html tag and html_func
struct template {
    size_t offs;
    size_t len;
    html_func f;
};

/* context for web_server's use */
struct private_context {
    int render_called;
    struct vmbuf mb;               /* miscellaneous buffer - readonly after call to controller */
    struct vmbuf uri_arg_ptrs;     /* holds pointers to uri path components - readonly after call to controller */
    size_t uri_ofs;
};

/* removes '..'s, '.'s,  and consecutive '/'s.
 *  uri is assumed to already be decoded.  A sanitized uri always starts
 *  with a '/', has no '..' and '.' path components or trailing '/'s
*/
static size_t sanitize_uri(const char *uri, char *sanitized_uri) {
    char *sanitized_start = sanitized_uri;
    const char *p;
    char *skip_str;
    while(*uri == '/') ++uri; //remove leading '/'s
    p = uri;
    do {
        uri = strchrnul(uri, '/');
        int mid_len = uri - p;
        if (mid_len == 2)
            skip_str = "..";
        else if (mid_len == 1)
            skip_str = ".";
        else if (mid_len != 0)
            skip_str = NULL;
        else {
            ++p;
            continue;
        }
        if (skip_str != NULL && 0 == strncmp(p, skip_str, mid_len)) {
            p += mid_len + 1;
        } else {
            for (*sanitized_uri++ = '/'; p < uri; *sanitized_uri++ = *p++);
            ++p;
        }
    } while (*uri++ != '\0');
    if (sanitized_uri == sanitized_start)
        *sanitized_uri++ = '/';
    *sanitized_uri = '\0';
    return sanitized_uri - sanitized_start;
}

static int get_modified_time(const char *filename, long *mtime_millis) {
    struct stat st;
    int fd = open(filename, O_RDONLY | O_CLOEXEC);
    if (0 > fd)
        return LOGGER_ERROR("Failed to open file: [%s]", filename), -1;
    if (0 > fstat(fd, &st))
        return LOGGER_ERROR("fstat failed on file: [%s]"), -1;
    *mtime_millis = st.st_mtime;
    close(fd);
    return 0;
}

static int parse_templates(struct vmbuf *page_buf) {
    SSTRL(PREF, "<%");
    static const char suf = '>';
    const char *buf_start = vmbuf_data(page_buf);
    const char *page = buf_start + sizeof(struct page_header);
    const char *start = strstr(page, PREF);
    const char *end = (start != NULL) ? strchr(start + SSTRLEN(PREF), suf) : NULL;
    uint32_t entry_ofs = 0;
    const char *next_start;
    struct template templ;
    while (start != NULL) {
        if (end == NULL)
            return LOGGER_ERROR("Unterminated template starting at [%s]", start), -1;
        next_start = strstr(start + SSTRLEN(PREF), PREF);
        if (next_start != NULL && next_start < end)
            return LOGGER_ERROR("Cannot start template within template [%s]", next_start), -1;

        templ.offs = start - buf_start;
        templ.len = end+1 - start;

        start += SSTRLEN(PREF);
        for (;*start == ' '; ++start);
        for (;*(end-1) == ' '; --end);
        entry_ofs = hashtable_lookup(&html_func_map, start, end-start);
        if (entry_ofs)
            templ.f = *(html_func *)hashtable_get_val(&html_func_map, entry_ofs);
        else //allowing templates to have no function - will replace with empty string
            templ.f = NULL;
        vmbuf_memcpy(page_buf, &templ, sizeof(struct template));
        start = next_start;
        if (start != NULL)
            end = strchr(start + SSTRLEN(PREF), suf);
    }
    return 0;
}

static int create_page_buf(const char *uri, size_t uri_len, struct vmbuf *page_buf) {
    struct file_mapper fm = FILE_MAPPER_INITIALIZER;
    static struct vmbuf vmb = VMBUF_INITIALIZER;
    struct page_header *pg_header;
    uint32_t entry_ofs = 0;
    if (0 > file_mapper_init(&fm, uri))
        return -1;
    if (0 > vmbuf_init(&vmb, fm.size + sizeof(struct page_header)))
        return -1;
    vmbuf_alloc(&vmb, sizeof(struct page_header));
    vmbuf_memcpy(&vmb, fm.mem, fm.size);
    vmbuf_memcpy(&vmb, "\0", 1); //for parsing templates
    file_mapper_free(&fm);
    pg_header = (struct page_header *)vmbuf_data(&vmb);
    pg_header->templ_offs = vmbuf_wlocpos(&vmb);
    if (0 > get_modified_time(uri, &pg_header->last_mod_millis))
        return -1;
    if (0 == strcmp(mime_types_by_filename(uri), DEFAULT_MIME_TYPE)) {
        if (0 > parse_templates(&vmb))
            return LOGGER_PERROR("Couldn't parse templ from file [%s]", uri), -1;
    }
    hashtable_insert(&page_map, uri, uri_len, &vmb, sizeof(struct vmbuf));
    entry_ofs = hashtable_lookup(&page_map, uri, uri_len);
    if (!entry_ofs)
        return -1;
    *page_buf = *(struct vmbuf *)hashtable_get_val(&page_map, entry_ofs);
    return 0;
}

static int get_page_buf(const char *uri, size_t uri_len, struct vmbuf *page_buf) {
    uint32_t entry_ofs = 0;
    static int page_map_initialized = 0;
    if (unlikely(!page_map_initialized))
        hashtable_init(&page_map, 512);
    entry_ofs = hashtable_lookup(&page_map, uri, uri_len);
    if (entry_ofs) {
        *page_buf = *(struct vmbuf *)hashtable_get_val(&page_map, entry_ofs);
        return 0;
    } else {
        return create_page_buf(uri, uri_len, page_buf);
    }
}

static int page_to_payload(struct vmbuf *page_buf) {
    struct http_server_context *ctx = http_server_get_context();
    struct page_header *pg_header = (struct page_header *)vmbuf_data(page_buf);
    struct template *template_arr = (struct template *)vmbuf_data_ofs(page_buf, pg_header->templ_offs);
    size_t arr_len = (vmbuf_wlocpos(page_buf) - pg_header->templ_offs) / sizeof(struct template);
    size_t cur_ofs = sizeof(struct page_header);
    size_t i;
    for (i = 0; i < arr_len; ++i) {
        vmbuf_memcpy(&ctx->payload, vmbuf_data_ofs(page_buf, cur_ofs), template_arr[i].offs - cur_ofs);
        if (template_arr[i].f != NULL)
            template_arr[i].f();

        cur_ofs = template_arr[i].offs + template_arr[i].len;
    }
    vmbuf_memcpy(&ctx->payload, vmbuf_data_ofs(page_buf, cur_ofs), (pg_header->templ_offs-1) - cur_ofs);
    return 0;
}

static struct private_context *get_private_context() {
    return (struct private_context *)http_server_get_context()->user_data;
}

struct web_server_context *web_server_get_context() {
    return (struct web_server_context *)((char *)http_server_get_context()->user_data + sizeof(struct private_context));
}

/* offsets written from last arg to first, so pop off vmbuf from back to front when writing
   pointers to the uri path components */
static inline void arg_offsets_to_argv(size_t num_args, size_t *argv_ofs) {
    struct private_context *private_ctx = get_private_context();
    *argv_ofs = vmbuf_wlocpos(&private_ctx->uri_arg_ptrs);
    int i = num_args - 1;
    for (; i >= 0; --i) {
        size_t arg_ofs = *(size_t *)vmbuf_data_ofs(&private_ctx->uri_arg_ptrs, i * sizeof(size_t));
        char *arg = vmbuf_data_ofs(&private_ctx->mb, arg_ofs);
        vmbuf_memcpy(&private_ctx->uri_arg_ptrs, &arg, sizeof(char *));
    }
}

static inline void init_controller_map() {
    static int initialized = 0;
    if (unlikely(!initialized)) {
        hashtable_init(&controller_map, 128);
        initialized = 1;
    }
}

static void call_controller() {
    controller_func controller;
    uint32_t entry_ofs;
    struct web_server_context *web_ctx = web_server_get_context();
    struct private_context *private_ctx = get_private_context();
    size_t argv_ofs = 0;
    size_t num_args = 0;
    size_t uri_args_ofs = vmbuf_wlocpos(&private_ctx->mb);
    init_controller_map();
    vmbuf_alloc(&private_ctx->mb, web_ctx->uri_len+1);
    memcpy(vmbuf_data_ofs(&private_ctx->mb, uri_args_ofs), vmbuf_data_ofs(&private_ctx->mb, private_ctx->uri_ofs), web_ctx->uri_len+1);

    char *start = vmbuf_data_ofs(&private_ctx->mb, uri_args_ofs);
    char *end = start + web_ctx->uri_len;
    while (end > start) {
        entry_ofs = hashtable_lookup(&controller_map, start, end - start);
        if (entry_ofs)
            goto found;
        for (--end; *end != '/'; --end);
        *end = '\0';
        size_t ofs = (size_t)(end+1 - start);
        vmbuf_memcpy(&private_ctx->uri_arg_ptrs, &ofs, sizeof(size_t));
    }
    entry_ofs = hashtable_lookup(&controller_map, "/", 1);
    if (!entry_ofs) {
        //private_context's mb is now readonly
        web_ctx->uri = vmbuf_data_ofs(&private_ctx->mb, private_ctx->uri_ofs);
        return;
    }
 found:
    num_args = vmbuf_wlocpos(&private_ctx->uri_arg_ptrs) / sizeof(size_t);
    //uri_argc already 0, and uri_argv already NULL. no need to set if num_args == 0
    if (num_args) {
        arg_offsets_to_argv(num_args, &argv_ofs);//offsets and argv stored in uri_arg_ptrs vmbuf

        //after writing pointers into web_ctx, private_context's mb and uri_arg_ptrs becomes readonly
        web_ctx->uri_argc = num_args;
        web_ctx->uri_argv = (char **)vmbuf_data_ofs(&private_ctx->uri_arg_ptrs, argv_ofs);
    }
    web_ctx->uri = vmbuf_data_ofs(&private_ctx->mb, private_ctx->uri_ofs);

    controller = *(controller_func *)hashtable_get_val(&controller_map, entry_ofs);
    controller();
    return;
}

void web_server_get_filename(const char *uri_path, struct vmbuf *buf, size_t *ofs) {
    *ofs = vmbuf_wlocpos(buf);
    vmbuf_memcpy(buf, root, root_len);
    if (*uri_path == '/') ++uri_path;
    vmbuf_strcpy(buf, uri_path);
    vmbuf_chrcpy(buf, '\0');
}

/* finds page in root directory, calls template functions, and outputs result to payload */
static inline int render(const char *file) {
    // NOTE: full_path is static even though render may be called recursively.
    // This works because render is called after full_path is no longer needed in previous stack frame
    static struct vmbuf full_path = VMBUF_INITIALIZER;
    static int initialized = 0;
    struct vmbuf page_buf;
    if (unlikely(!initialized)) {
        vmbuf_init(&full_path, 1024);
        vmbuf_memcpy(&full_path, root, root_len);
    }
    if (*file == '/') ++file; //root already has trailing '/'
    vmbuf_wlocset(&full_path, root_len);
    vmbuf_strcpy(&full_path, file); //not adding null since we're not appending anything else
    if (0 > get_page_buf(vmbuf_data(&full_path), vmbuf_wlocpos(&full_path), &page_buf)) {
        return -1;
    }
    if (0 > page_to_payload(&page_buf))
        return -1;
    return 0;
}

void web_server_add_controller(const char *file, controller_func func) {
    init_controller_map();
    hashtable_insert(&controller_map, file, strlen(file), &func, sizeof(func));
}

void web_server_add_html_func(const char *ident, html_func func) {
    static int initialized = 0;
    if (unlikely(!initialized)) {
        hashtable_init(&html_func_map, 64);
        initialized = 1;
    }
    hashtable_insert(&html_func_map, ident, strlen(ident), &func, sizeof(func));
}

void web_server_render_404() {
    if (NULL != page404 && 0 == render(page404)) {
        http_server_response(HTTP_STATUS_404, mime_types_by_filename(page404));
        return;
    }
    http_server_response_sprintf(HTTP_STATUS_404, HTTP_CONTENT_TYPE_TEXT_PLAIN, "page not found");
}

void web_server_render_page(const char *file_path) {
    const char *mime = mime_types_by_filename(file_path);
    web_server_render_page_as_mimetype(file_path, mime);
}

/* renders page as mimetype.  File extension doesn't matter. */
void web_server_render_page_as_mimetype(const char *file_path, const char *mime_type) {
    if (0 > render(file_path))
        web_server_render_404();
    else
        http_server_response(HTTP_STATUS_200, mime_type);
}

/* Must be a .rp (ribs partial) file - should be called from template html_functions. */
void web_server_render_partial(const char *file_path) {
    SSTRL(RP_EXT, "rp");
    const char *ext = strrchr(file_path, '.');
    if (!ext)
        return;
    if (0 != strcmp(RP_EXT, ++ext)) {
        LOGGER_ERROR("Cannot render [%s] as partial.\nPartials must have '.rp' extension");
        return;
    }
    render(file_path);
}

void web_server_render_sprintf(const char *format, ...) {
    struct http_server_context *ctx = http_server_get_context();
    va_list ap;
    va_start(ap, format);
    vmbuf_vsprintf(&ctx->payload, format, ap);
}

static int private_ctx_init() {
    struct private_context *private_ctx = get_private_context();
    private_ctx->render_called = 0;
    private_ctx->uri_ofs = ULLONG_MAX;
    if (0 > vmbuf_init(&private_ctx->mb, 512) ||
        0 > vmbuf_init(&private_ctx->uri_arg_ptrs, 512))
        return -1;
    return 0;
}

static int web_server_ctx_init() {
    struct web_server_context *web_ctx = web_server_get_context();

    if (0 > hashtable_init(&web_ctx->query_params, 1024) ||
        0 > hashtable_init(&web_ctx->cookies, 1024) ||
        0 > vmbuf_init(&web_ctx->misc_buf, 4096) ||
        0 > hashtable_init(&web_ctx->misc_table, 1024))
        return -1;
    web_ctx->pending_requests = 0;
    if (0 > private_ctx_init())
        return -1;

    http_headers_parse(http_server_get_context()->headers, &web_ctx->headers);
    http_cookies_parse(web_ctx->headers.cookie, &web_ctx->cookies);
    http_server_parse_query_params(&web_ctx->query_params);

    web_ctx->uri_len = 0;
    /* these values are set just before calling controller */
    web_ctx->uri = NULL;
    web_ctx->uri_argc = 0;
    web_ctx->uri_argv = NULL;
    return 0;
}

void web_server_main() {
    size_t decoded_uri_len;
    struct http_server_context *http_ctx = http_server_get_context();
    struct private_context *private_ctx = get_private_context();
    if (0 > web_server_ctx_init()) {
        http_server_response_sprintf(HTTP_STATUS_500, HTTP_CONTENT_TYPE_TEXT_PLAIN, "Internal Error");
        return;
    }
    decoded_uri_len = http_uri_decode(http_ctx->uri, http_ctx->uri) - 1;
    private_ctx->uri_ofs = vmbuf_wlocpos(&private_ctx->mb);
    vmbuf_alloc(&private_ctx->mb, decoded_uri_len + 1);
    web_server_get_context()->uri_len = sanitize_uri(http_ctx->uri, vmbuf_data_ofs(&private_ctx->mb, private_ctx->uri_ofs));
    call_controller();
    if (vmbuf_wlocpos(&http_ctx->header) == 0) {
        if (0 == strcmp(web_server_get_context()->uri, "/"))
            web_server_render_page(root_file);
        else
            web_server_render_page(web_server_get_context()->uri);
    }
}

int web_server_init(struct web_server *server) {
    if (server->root == NULL)
        return LOGGER_ERROR("No root directory"), -1;
    if (server->root_file == NULL)
        return LOGGER_ERROR("No root file"), -1;
    root_len = strlen(server->root);
    root = malloc(root_len+2); //1 null byte, 1 '/'
    strcpy(root, server->root);
    if (server->root[root_len-1] != '/') {
        strcpy(root+root_len, "/");
        ++root_len;
    }
    root_file = malloc(strlen(server->root_file) + 1);
    sanitize_uri(server->root_file, root_file);

    if (server->page404 != NULL) {
        page404 = malloc(strlen(server->page404+1));
        strcpy(page404, server->page404);
    }
    server->http.context_size = sizeof(struct private_context) + sizeof(struct web_server_context) + server->context_size;
    if (0 > http_server_init(&server->http))
        return -1;
    return 0;
}

int web_server_init_acceptor(struct web_server *server) {
    return http_server_init_acceptor(&server->http);
}

int web_server_run(struct web_server *server) {
    if (0 > web_server_init(server))
        return LOGGER_ERROR("web_server_init failed"), -1;
    if (0 > epoll_worker_init())
        return LOGGER_ERROR("epoll_worker_init failed"), -1;
    if (0 > web_server_init_acceptor(server))
        return LOGGER_ERROR("web_server_init_acceptor failed"), -1;
    epoll_worker_loop();
    return 0;
}
