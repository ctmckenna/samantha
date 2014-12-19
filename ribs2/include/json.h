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
#ifndef _JSON__H_
#define _JSON__H_
#include "ribs.h"
#include "vmbuf.h"

#include <stdint.h>

struct json_stack_item
{
    char *begin;
    char *end;
};

struct json
{
    int level;
    char *cur;
    const char *err;
    struct json_stack_item last_string;
    struct json_stack_item last_key;
    struct vmbuf stack;
    struct vmbuf cb_stack;

    void (*callback_string)     (struct json *json, char *kb, char *ke, char *vb, char *ve);
    void (*callback_primitive)  (struct json *json, char *kb, char *ke, char *vb, char *ve);
    void (*callback_block_begin)(struct json *json, char *kb, char *ke);
    void (*callback_block_end)  (struct json *json, char *kb, char *ke);
};

#define JSON_INIT_DEFAULTS .err = NULL, .stack = VMBUF_INITIALIZER, .cb_stack = VMBUF_INITIALIZER
#define JSON_INITIALIZER { JSON_INIT_DEFAULTS }

void json_stack_item_set(struct json_stack_item *si, char *b, char *e);
void json_stack_item_reset(struct json_stack_item *si);
int  json_stack_item_isset(struct json_stack_item *si);
void json_push_callbacks(struct json *js);
void json_pop_callbacks(struct json *js);
void json_null_obj_parse(struct json *js);

void json_reset_callbacks(struct json *js);
int  json_init(struct json *js);
int  json_parse(struct json *js, char *str);

int  json_parse_string(struct json *js);
int  json_parse_primitive(struct json *js);
void json_unescape_str(char *buf);
size_t json_escape_str(char *d, const char *s);
size_t json_escape_str_vmb(struct vmbuf *buf, const char *s);

#endif // _JSON__H_
