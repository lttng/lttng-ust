/*
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 * Copyright (C) 2005-2011 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 *
 * This contains the core definitions for the Linux Trace Toolkit.
 */

#ifndef _LTTNG_TRACER_CORE_H
#define _LTTNG_TRACER_CORE_H

#include <stddef.h>
#include <urcu/arch.h>
#include <urcu/list.h>
#include <lttng/ust-tracer.h>
#include <lttng/bug.h>
#include <lttng/ringbuffer-config.h>
#include <usterr-signal-safe.h>
#include <ust-helper.h>

/*
 * The longuest possible namespace proc path is with the cgroup ns
 * and the maximum theoretical linux pid of 536870912 :
 *
 *  /proc/self/task/536870912/ns/cgroup
 */
#define LTTNG_PROC_NS_PATH_MAX 40

struct lttng_session;
struct lttng_channel;
struct lttng_event;
struct lttng_ctx_field;
struct lttng_ust_lib_ring_buffer_ctx;
struct lttng_ctx_value;
struct lttng_event_notifier;

LTTNG_HIDDEN
int ust_lock(void) __attribute__ ((warn_unused_result));
LTTNG_HIDDEN
void ust_lock_nocheck(void);
LTTNG_HIDDEN
void ust_unlock(void);

LTTNG_HIDDEN
void lttng_ust_fixup_tls(void);
LTTNG_HIDDEN
void lttng_fixup_event_tls(void);
LTTNG_HIDDEN
void lttng_fixup_vtid_tls(void);
LTTNG_HIDDEN
void lttng_fixup_procname_tls(void);
LTTNG_HIDDEN
void lttng_fixup_cgroup_ns_tls(void);
LTTNG_HIDDEN
void lttng_fixup_ipc_ns_tls(void);
LTTNG_HIDDEN
void lttng_fixup_net_ns_tls(void);
LTTNG_HIDDEN
void lttng_fixup_time_ns_tls(void);
LTTNG_HIDDEN
void lttng_fixup_uts_ns_tls(void);

LTTNG_HIDDEN
void lttng_ust_fixup_fd_tracker_tls(void);

const char *lttng_ust_obj_get_name(int id);

int lttng_get_notify_socket(void *owner);

LTTNG_HIDDEN
char* lttng_ust_sockinfo_get_procname(void *owner);

void lttng_ust_sockinfo_session_enabled(void *owner);

void lttng_ust_malloc_wrapper_init(void);

ssize_t lttng_ust_read(int fd, void *buf, size_t len);

size_t lttng_ust_dummy_get_size(struct lttng_ctx_field *field, size_t offset);
void lttng_ust_dummy_record(struct lttng_ctx_field *field,
		 struct lttng_ust_lib_ring_buffer_ctx *ctx,
		 struct lttng_channel *chan);
void lttng_ust_dummy_get_value(struct lttng_ctx_field *field,
		struct lttng_ctx_value *value);

LTTNG_HIDDEN
void lttng_event_notifier_notification_send(
		struct lttng_event_notifier *event_notifier,
		const char *stack_data);

LTTNG_HIDDEN
struct lttng_counter_transport *lttng_counter_transport_find(const char *name);
LTTNG_HIDDEN
void lttng_counter_transport_register(struct lttng_counter_transport *transport);
LTTNG_HIDDEN
void lttng_counter_transport_unregister(struct lttng_counter_transport *transport);

#ifdef HAVE_PERF_EVENT
LTTNG_HIDDEN
void lttng_ust_fixup_perf_counter_tls(void);
void lttng_perf_lock(void);
void lttng_perf_unlock(void);
#else /* #ifdef HAVE_PERF_EVENT */
static inline
void lttng_ust_fixup_perf_counter_tls(void)
{
}
static inline
void lttng_perf_lock(void)
{
}
static inline
void lttng_perf_unlock(void)
{
}
#endif /* #else #ifdef HAVE_PERF_EVENT */

#endif /* _LTTNG_TRACER_CORE_H */
