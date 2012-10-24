#ifndef _LTT_TRACER_CORE_H
#define _LTT_TRACER_CORE_H

/*
 * Copyright (C) 2005-2011 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 *
 * This contains the core definitions for the Linux Trace Toolkit.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; version 2.1 of
 * the License.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301 USA
 */

#include <stdint.h>
#include <stddef.h>
#include <urcu/arch.h>
#include <urcu/list.h>
#include <lttng/ust-tracer.h>
#include <lttng/bug.h>
#include <lttng/ringbuffer-config.h>
#include <usterr-signal-safe.h>

struct ltt_session;
struct ltt_channel;
struct ltt_event;

void ust_lock(void);
void ust_unlock(void);

void lttng_fixup_event_tls(void);
void lttng_fixup_vtid_tls(void);
void lttng_fixup_procname_tls(void);

#endif /* _LTT_TRACER_CORE_H */
