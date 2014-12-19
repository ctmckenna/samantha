/*
    This file is part of RIBS2.0 (Robust Infrastructure for Backend Systems).
    RIBS is an infrastructure for building great SaaS applications (but not
    limited to).

    Copyright (C) 2012 Adap.tv, Inc.

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
#ifndef _TIMER__H_
#define _TIMER__H_

#include "ribs_defs.h"

struct timer {
    uint32_t entry_ofs;
};

#define TIMER_INIT_DEFAULTS .entry_ofs = UINT_MAX
#define TIMER_INITIALIZER { TIMER_INIT_DEFAULTS }

#define TIMER_ENT(ptr, type, member) \
    ((type *)((char *)(ptr)-offsetof(type, member)))

int ribs_timer_once(time_t msec, struct timer *timer, void (*handler)(struct timer *timer));
int ribs_timer_remove(struct timer *timer);

#endif // _TIMER__H_
