/*
 * SPDX-License-Identifier: MIT
 *
 * Copyright 2019 (c) Francis Deslauriers <francis.deslauriers@efficios.com>
 */

#ifndef _LTTNG_UST_EVENTS_INTERNAL_H
#define _LTTNG_UST_EVENTS_INTERNAL_H

#include "common/events.h"

/*
 * Allocate and initialize a `struct lttng_event_recorder_enabler` object.
 *
 * On success, returns a `struct lttng_event_recorder_enabler`,
 * On memory error, returns NULL.
 */
struct lttng_event_recorder_enabler *lttng_event_recorder_enabler_create(
		enum lttng_enabler_format_type format_type,
		const struct lttng_ust_abi_event *event_param,
		struct lttng_ust_channel_buffer *chan)
	__attribute__((visibility("hidden")));

#ifdef CONFIG_LTTNG_UST_EXPERIMENTAL_COUNTER
/*
 * Allocate and initialize a `struct lttng_event_counter_enabler` object.
 *
 * On success, returns a `struct lttng_event_counter_enabler`,
 * On memory error, returns NULL.
 */
struct lttng_event_counter_enabler *lttng_event_counter_enabler_create(
		enum lttng_enabler_format_type format_type,
		const struct lttng_ust_abi_counter_event *counter_event,
		const struct lttng_counter_key *key,
		struct lttng_ust_channel_counter *chan)
	__attribute__((visibility("hidden")));
#endif	 /* CONFIG_LTTNG_UST_EXPERIMENTAL_COUNTER */

/*
 * Destroy a `struct lttng_event_enabler_common` object.
 */
void lttng_event_enabler_destroy(struct lttng_event_enabler_common *event_enabler)
	__attribute__((visibility("hidden")));

/*
 * Enable a `struct lttng_event_enabler_common` object and all events related to this
 * enabler.
 */
int lttng_event_enabler_enable(struct lttng_event_enabler_common *enabler)
	__attribute__((visibility("hidden")));

/*
 * Disable a `struct lttng_event_enabler_common` object and all events related to this
 * enabler.
 */
int lttng_event_enabler_disable(struct lttng_event_enabler_common *enabler)
	__attribute__((visibility("hidden")));

/*
 * Attach filter bytecode program to `struct lttng_event_enabler_common` and all
 * events related to this enabler.
 */
int lttng_event_enabler_attach_filter_bytecode(
		struct lttng_event_enabler_common *enabler,
		struct lttng_ust_bytecode_node **bytecode)
	__attribute__((visibility("hidden")));

/*
 * Attach an application context to an event enabler.
 *
 * Not implemented.
 */
int lttng_event_enabler_attach_context(struct lttng_event_enabler_session_common *enabler,
		struct lttng_ust_abi_context *ctx)
	__attribute__((visibility("hidden")));

/*
 * Attach exclusion list to `struct lttng_event_enabler_common` and all
 * events related to this enabler.
 */
int lttng_event_enabler_attach_exclusion(struct lttng_event_enabler_common *enabler,
		struct lttng_ust_excluder_node **excluder)
	__attribute__((visibility("hidden")));

/*
 * Synchronize bytecodes for the enabler and the instance (event or
 * event_notifier).
 *
 * This function goes over all bytecode programs of the enabler (event or
 * event_notifier enabler) to ensure each is linked to the provided instance.
 */
void lttng_enabler_link_bytecode(const struct lttng_ust_event_desc *event_desc,
		struct lttng_ust_ctx **ctx,
		struct cds_list_head *instance_bytecode_runtime_head,
		struct cds_list_head *enabler_bytecode_runtime_head)
	__attribute__((visibility("hidden")));

/*
 * Allocate and initialize a `struct lttng_event_notifier_group` object.
 *
 * On success, returns a `struct lttng_triggre_group`,
 * on memory error, returns NULL.
 */
struct lttng_event_notifier_group *lttng_event_notifier_group_create(void)
	__attribute__((visibility("hidden")));

/*
 * Destroy a `struct lttng_event_notifier_group` object.
 */
void lttng_event_notifier_group_destroy(
		struct lttng_event_notifier_group *event_notifier_group)
	__attribute__((visibility("hidden")));

/*
 * Allocate and initialize a `struct lttng_event_notifier_enabler` object.
 *
 * On success, returns a `struct lttng_event_notifier_enabler`,
 * On memory error, returns NULL.
 */
struct lttng_event_notifier_enabler *lttng_event_notifier_enabler_create(
		struct lttng_event_notifier_group *event_notifier_group,
		enum lttng_enabler_format_type format_type,
		struct lttng_ust_abi_event_notifier *event_notifier_param)
	__attribute__((visibility("hidden")));

/*
 * Attach capture bytecode program to `struct lttng_event_notifier_enabler` and
 * all event_notifiers related to this enabler.
 */
int lttng_event_notifier_enabler_attach_capture_bytecode(
		struct lttng_event_notifier_enabler *event_notifier_enabler,
		struct lttng_ust_bytecode_node **bytecode)
	__attribute__((visibility("hidden")));

void lttng_free_event_filter_runtime(struct lttng_ust_event_common *event)
	__attribute__((visibility("hidden")));

/*
 * Connect the probe on all enablers matching this event description.
 * Called on library load.
 */
int lttng_fix_pending_event_notifiers(void)
	__attribute__((visibility("hidden")));

struct lttng_ust_channel_counter *lttng_ust_counter_create(
		const char *counter_transport_name,
		size_t number_dimensions,
		const struct lttng_counter_dimension *dimensions,
		int64_t global_sum_step,
		bool coalesce_hits)
	__attribute__((visibility("hidden")));

#ifdef HAVE_LINUX_PERF_EVENT_H

int lttng_add_perf_counter_to_ctx(uint32_t type,
				  uint64_t config,
				  const char *name,
				  struct lttng_ust_ctx **ctx)
	__attribute__((visibility("hidden")));

int lttng_perf_counter_init(void)
	__attribute__((visibility("hidden")));

void lttng_perf_counter_exit(void)
	__attribute__((visibility("hidden")));

#else /* #ifdef HAVE_LINUX_PERF_EVENT_H */

static inline
int lttng_add_perf_counter_to_ctx(uint32_t type __attribute__((unused)),
				  uint64_t config __attribute__((unused)),
				  const char *name __attribute__((unused)),
				  struct lttng_ust_ctx **ctx __attribute__((unused)))
{
	return -ENOSYS;
}
static inline
int lttng_perf_counter_init(void)
{
	return 0;
}
static inline
void lttng_perf_counter_exit(void)
{
}
#endif /* #else #ifdef HAVE_LINUX_PERF_EVENT_H */

int lttng_probes_get_event_list(struct lttng_ust_tracepoint_list *list)
	__attribute__((visibility("hidden")));

void lttng_probes_prune_event_list(struct lttng_ust_tracepoint_list *list)
	__attribute__((visibility("hidden")));

int lttng_probes_get_field_list(struct lttng_ust_field_list *list)
	__attribute__((visibility("hidden")));

void lttng_probes_prune_field_list(struct lttng_ust_field_list *list)
	__attribute__((visibility("hidden")));

struct lttng_ust_abi_tracepoint_iter *
	lttng_ust_tracepoint_list_get_iter_next(struct lttng_ust_tracepoint_list *list)
	__attribute__((visibility("hidden")));

struct lttng_ust_abi_field_iter *
	lttng_ust_field_list_get_iter_next(struct lttng_ust_field_list *list)
	__attribute__((visibility("hidden")));

struct lttng_ust_session *lttng_session_create(void)
	__attribute__((visibility("hidden")));

int lttng_session_enable(struct lttng_ust_session *session)
	__attribute__((visibility("hidden")));

int lttng_session_disable(struct lttng_ust_session *session)
	__attribute__((visibility("hidden")));

int lttng_session_statedump(struct lttng_ust_session *session)
	__attribute__((visibility("hidden")));

void lttng_session_destroy(struct lttng_ust_session *session)
	__attribute__((visibility("hidden")));

/*
 * Called with ust lock held.
 */
int lttng_session_active(void)
	__attribute__((visibility("hidden")));

struct cds_list_head *lttng_get_sessions(void)
	__attribute__((visibility("hidden")));

void lttng_handle_pending_statedump(void *owner)
	__attribute__((visibility("hidden")));

int lttng_channel_enable(struct lttng_ust_channel_common *lttng_channel)
	__attribute__((visibility("hidden")));

int lttng_channel_disable(struct lttng_ust_channel_common *lttng_channel)
	__attribute__((visibility("hidden")));

void lttng_probe_provider_unregister_events(const struct lttng_ust_probe_desc *desc)
	__attribute__((visibility("hidden")));

int lttng_fix_pending_events(void)
	__attribute__((visibility("hidden")));

struct cds_list_head *lttng_get_probe_list_head(void)
	__attribute__((visibility("hidden")));

int lttng_abi_create_root_handle(void)
	__attribute__((visibility("hidden")));

const struct lttng_ust_abi_objd_ops *lttng_ust_abi_objd_ops(int id)
	__attribute__((visibility("hidden")));

int lttng_ust_abi_objd_unref(int id, int is_owner)
	__attribute__((visibility("hidden")));

void lttng_ust_abi_exit(void)
	__attribute__((visibility("hidden")));

void lttng_ust_abi_events_exit(void)
	__attribute__((visibility("hidden")));

void lttng_ust_abi_objd_table_owner_cleanup(void *owner)
	__attribute__((visibility("hidden")));

int lttng_ust_interpret_event_filter(const struct lttng_ust_event_common *event,
		const char *interpreter_stack_data,
		struct lttng_ust_probe_ctx *probe_ctx,
		void *filter_ctx)
	__attribute__((visibility("hidden")));

int lttng_ust_session_uuid_validate(struct lttng_ust_session *session,
		unsigned char *uuid)
	__attribute__((visibility("hidden")));

bool lttng_ust_validate_event_name(const struct lttng_ust_event_desc *desc)
	__attribute__((visibility("hidden")));

void lttng_ust_format_event_name(const struct lttng_ust_event_desc *desc,
		char *name)
	__attribute__((visibility("hidden")));

int lttng_ust_add_app_context_to_ctx_rcu(const char *name, struct lttng_ust_ctx **ctx)
	__attribute__((visibility("hidden")));

int lttng_ust_context_set_provider_rcu(struct lttng_ust_ctx **_ctx,
		const char *name,
		size_t (*get_size)(void *priv, struct lttng_ust_probe_ctx *probe_ctx,
			size_t offset),
		void (*record)(void *priv, struct lttng_ust_probe_ctx *probe_ctx,
			struct lttng_ust_ring_buffer_ctx *ctx,
			struct lttng_ust_channel_buffer *chan),
		void (*get_value)(void *priv, struct lttng_ust_probe_ctx *probe_ctx,
			struct lttng_ust_ctx_value *value))
	__attribute__((visibility("hidden")));

void lttng_ust_context_set_session_provider(const char *name,
		size_t (*get_size)(void *priv, struct lttng_ust_probe_ctx *probe_ctx,
			size_t offset),
		void (*record)(void *priv, struct lttng_ust_probe_ctx *probe_ctx,
			struct lttng_ust_ring_buffer_ctx *ctx,
			struct lttng_ust_channel_buffer *chan),
		void (*get_value)(void *priv, struct lttng_ust_probe_ctx *probe_ctx,
			struct lttng_ust_ctx_value *value))
	__attribute__((visibility("hidden")));

#endif /* _LTTNG_UST_EVENTS_INTERNAL_H */
