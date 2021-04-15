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
#include <lttng/ust-ringbuffer-context.h>
#include "common/logging.h"

struct lttng_ust_session;
struct lttng_ust_channel_buffer;
struct lttng_ust_ctx_field;
struct lttng_ust_ring_buffer_ctx;
struct lttng_ust_ctx_value;
struct lttng_ust_event_recorder;
struct lttng_ust_event_notifier;
struct lttng_ust_notification_ctx;

int ust_lock(void) __attribute__ ((warn_unused_result))
	__attribute__((visibility("hidden")));

void ust_lock_nocheck(void)
	__attribute__((visibility("hidden")));

void ust_unlock(void)
	__attribute__((visibility("hidden")));

void lttng_ust_fixup_tls(void)
	__attribute__((visibility("hidden")));

void lttng_fixup_event_tls(void)
	__attribute__((visibility("hidden")));

void lttng_fixup_vtid_tls(void)
	__attribute__((visibility("hidden")));

void lttng_fixup_procname_tls(void)
	__attribute__((visibility("hidden")));

void lttng_fixup_cgroup_ns_tls(void)
	__attribute__((visibility("hidden")));

void lttng_fixup_ipc_ns_tls(void)
	__attribute__((visibility("hidden")));

void lttng_fixup_net_ns_tls(void)
	__attribute__((visibility("hidden")));

void lttng_fixup_time_ns_tls(void)
	__attribute__((visibility("hidden")));

void lttng_fixup_uts_ns_tls(void)
	__attribute__((visibility("hidden")));

const char *lttng_ust_obj_get_name(int id)
	__attribute__((visibility("hidden")));

int lttng_get_notify_socket(void *owner)
	__attribute__((visibility("hidden")));

char* lttng_ust_sockinfo_get_procname(void *owner)
	__attribute__((visibility("hidden")));

void lttng_ust_sockinfo_session_enabled(void *owner)
	__attribute__((visibility("hidden")));

ssize_t lttng_ust_read(int fd, void *buf, size_t len)
	__attribute__((visibility("hidden")));

size_t lttng_ust_dummy_get_size(void *priv, size_t offset)
	__attribute__((visibility("hidden")));

void lttng_ust_dummy_record(void *priv, struct lttng_ust_ring_buffer_ctx *ctx,
		 struct lttng_ust_channel_buffer *chan)
	__attribute__((visibility("hidden")));

void lttng_ust_dummy_get_value(void *priv, struct lttng_ust_ctx_value *value)
	__attribute__((visibility("hidden")));

void lttng_event_notifier_notification_send(
		const struct lttng_ust_event_notifier *event_notifier,
		const char *stack_data,
		struct lttng_ust_notification_ctx *notif_ctx)
	__attribute__((visibility("hidden")));

struct lttng_counter_transport *lttng_counter_transport_find(const char *name)
	__attribute__((visibility("hidden")));

void lttng_counter_transport_register(struct lttng_counter_transport *transport)
	__attribute__((visibility("hidden")));

void lttng_counter_transport_unregister(struct lttng_counter_transport *transport)
	__attribute__((visibility("hidden")));

#ifdef HAVE_LINUX_PERF_EVENT_H
void lttng_ust_fixup_perf_counter_tls(void)
	__attribute__((visibility("hidden")));

void lttng_perf_lock(void)
	__attribute__((visibility("hidden")));

void lttng_perf_unlock(void)
	__attribute__((visibility("hidden")));
#else /* #ifdef HAVE_LINUX_PERF_EVENT_H */
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
#endif /* #else #ifdef HAVE_LINUX_PERF_EVENT_H */

#endif /* _LTTNG_TRACER_CORE_H */
