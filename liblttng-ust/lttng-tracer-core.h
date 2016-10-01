#ifndef _LTTNG_TRACER_CORE_H
#define _LTTNG_TRACER_CORE_H

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

struct lttng_session;
struct lttng_channel;
struct lttng_event;
struct lttng_ctx_field;
struct lttng_ust_lib_ring_buffer_ctx;
struct lttng_ctx_value;

int ust_lock(void) __attribute__ ((warn_unused_result));
void ust_lock_nocheck(void);
void ust_unlock(void);

void lttng_fixup_event_tls(void);
void lttng_fixup_vtid_tls(void);
void lttng_fixup_procname_tls(void);

const char *lttng_ust_obj_get_name(int id);

int lttng_get_notify_socket(void *owner);

void lttng_ust_sockinfo_session_enabled(void *owner);

void lttng_ust_malloc_wrapper_init(void);

ssize_t lttng_ust_read(int fd, void *buf, size_t len);

size_t lttng_ust_dummy_get_size(struct lttng_ctx_field *field, size_t offset);
void lttng_ust_dummy_record(struct lttng_ctx_field *field,
		 struct lttng_ust_lib_ring_buffer_ctx *ctx,
		 struct lttng_channel *chan);
void lttng_ust_dummy_get_value(struct lttng_ctx_field *field,
		struct lttng_ctx_value *value);
int lttng_context_is_app(const char *name);
void lttng_ust_fixup_tls(void);

#endif /* _LTTNG_TRACER_CORE_H */
