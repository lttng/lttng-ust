/*
 * SPDX-License-Identifier: MIT
 *
 * Copyright 2019 (c) Francis Deslauriers <francis.deslauriers@efficios.com>
 */

#ifndef _LTTNG_UST_EVENTS_INTERNAL_H
#define _LTTNG_UST_EVENTS_INTERNAL_H

#include <stdint.h>

#include <urcu/list.h>
#include <urcu/hlist.h>

#include <ust-helper.h>
#include <lttng/ust-events.h>


struct lttng_ust_abi_obj;

union lttng_ust_abi_args {
	struct {
		void *chan_data;
		int wakeup_fd;
	} channel;
	struct {
		int shm_fd;
		int wakeup_fd;
	} stream;
	struct {
		struct lttng_ust_abi_field_iter entry;
	} field_list;
	struct {
		char *ctxname;
	} app_context;
	struct {
		int event_notifier_notif_fd;
	} event_notifier_handle;
	struct {
		void *counter_data;
	} counter;
	struct {
		int shm_fd;
	} counter_shm;
};

struct lttng_ust_abi_objd_ops {
	long (*cmd)(int objd, unsigned int cmd, unsigned long arg,
		union lttng_ust_abi_args *args, void *owner);
	int (*release)(int objd);
};

enum lttng_enabler_format_type {
	LTTNG_ENABLER_FORMAT_STAR_GLOB,
	LTTNG_ENABLER_FORMAT_EVENT,
};

/*
 * Enabler field, within whatever object is enabling an event. Target of
 * backward reference.
 */
struct lttng_enabler {
	enum lttng_enabler_format_type format_type;

	/* head list of struct lttng_ust_filter_bytecode_node */
	struct cds_list_head filter_bytecode_head;
	/* head list of struct lttng_ust_excluder_node */
	struct cds_list_head excluder_head;

	struct lttng_ust_abi_event event_param;
	unsigned int enabled:1;
};

struct lttng_event_enabler {
	struct lttng_enabler base;
	struct cds_list_head node;	/* per-session list of enablers */
	struct lttng_channel *chan;
	/*
	 * Unused, but kept around to make it explicit that the tracer can do
	 * it.
	 */
	struct lttng_ctx *ctx;
};

struct lttng_event_notifier_enabler {
	struct lttng_enabler base;
	uint64_t error_counter_index;
	struct cds_list_head node;	/* per-app list of event_notifier enablers */
	struct cds_list_head capture_bytecode_head;
	struct lttng_event_notifier_group *group; /* weak ref */
	uint64_t user_token;		/* User-provided token */
	uint64_t num_captures;
};

enum lttng_ust_bytecode_node_type {
	LTTNG_UST_BYTECODE_NODE_TYPE_FILTER,
	LTTNG_UST_BYTECODE_NODE_TYPE_CAPTURE,
};

struct lttng_ust_bytecode_node {
	enum lttng_ust_bytecode_node_type type;
	struct cds_list_head node;
	struct lttng_enabler *enabler;
	struct  {
		uint32_t len;
		uint32_t reloc_offset;
		uint64_t seqnum;
		char data[];
	} bc;
};

struct lttng_ust_excluder_node {
	struct cds_list_head node;
	struct lttng_enabler *enabler;
	/*
	 * struct lttng_ust_event_exclusion had variable sized array,
	 * must be last field.
	 */
	struct lttng_ust_abi_event_exclusion excluder;
};

/* Data structures used by the tracer. */

struct tp_list_entry {
	struct lttng_ust_abi_tracepoint_iter tp;
	struct cds_list_head head;
};

struct lttng_ust_tracepoint_list {
	struct tp_list_entry *iter;
	struct cds_list_head head;
};

struct tp_field_list_entry {
	struct lttng_ust_abi_field_iter field;
	struct cds_list_head head;
};

struct lttng_ust_field_list {
	struct tp_field_list_entry *iter;
	struct cds_list_head head;
};

/*
 * Objects in a linked-list of enablers, owned by an event or event_notifier.
 * This is used because an event (or a event_notifier) can be enabled by more
 * than one enabler and we want a quick way to iterate over all enablers of an
 * object.
 *
 * For example, event rules "my_app:a*" and "my_app:ab*" will both match the
 * event with the name "my_app:abc".
 */
struct lttng_enabler_ref {
	struct cds_list_head node;		/* enabler ref list */
	struct lttng_enabler *ref;		/* backward ref */
};

#define LTTNG_COUNTER_DIMENSION_MAX	8
struct lttng_counter_dimension {
	uint64_t size;
	uint64_t underflow_index;
	uint64_t overflow_index;
	uint8_t has_underflow;
	uint8_t has_overflow;
};

struct lttng_counter {
	int objd;
	struct lttng_event_notifier_group *event_notifier_group;    /* owner */
	struct lttng_counter_transport *transport;
	struct lib_counter *counter;
	struct lttng_counter_ops *ops;
};

struct lttng_event_notifier_group {
	int objd;
	void *owner;
	int notification_fd;
	struct cds_list_head node;		/* Event notifier group handle list */
	struct cds_list_head enablers_head;
	struct cds_list_head event_notifiers_head;	/* list of event_notifiers */
	struct lttng_ust_event_notifier_ht event_notifiers_ht; /* hashtable of event_notifiers */
	struct lttng_ctx *ctx;			/* contexts for filters. */

	struct lttng_counter *error_counter;
	size_t error_counter_len;
};

struct lttng_transport {
	char *name;
	struct cds_list_head node;
	struct lttng_channel_ops ops;
	const struct lttng_ust_lib_ring_buffer_config *client_config;
};

struct lttng_counter_transport {
	char *name;
	struct cds_list_head node;
	struct lttng_counter_ops ops;
	const struct lib_counter_config *client_config;
};

struct lttng_ust_event_common_private {
	struct lttng_ust_event_common *pub;	/* Public event interface */

	const struct lttng_event_desc *desc;
	/* Backward references: list of lttng_enabler_ref (ref to enablers) */
	struct cds_list_head enablers_ref_head;
	int registered;			/* has reg'd tracepoint probe */
	uint64_t user_token;
};

struct lttng_ust_event_recorder_private {
	struct lttng_ust_event_common_private parent;

	struct lttng_ust_event_recorder *pub;	/* Public event interface */
	struct cds_list_head node;		/* Event list in session */
	struct cds_hlist_node hlist;		/* session ht of events */
};

struct lttng_ust_event_notifier_private {
	struct lttng_ust_event_common_private parent;

	struct lttng_ust_event_notifier *pub;	/* Public event notifier interface */
	struct cds_hlist_node hlist;		/* hashtable of event_notifiers */
	struct cds_list_head node;		/* event_notifier list in session */
	struct lttng_event_notifier_group *group; /* weak ref */
	size_t num_captures;			/* Needed to allocate the msgpack array. */
	uint64_t error_counter_index;
};

struct lttng_ust_bytecode_runtime_private {
	struct bytecode_runtime *pub;	/* Public bytecode runtime interface */

	struct lttng_ust_bytecode_node *bc;
	int link_failed;
	/*
	 * Pointer to a URCU-protected pointer owned by an `struct
	 * lttng_session`or `struct lttng_event_notifier_group`.
	 */
	struct lttng_ctx **pctx;
};

struct lttng_ust_session_private {
	struct lttng_session *pub;		/* Public session interface */

	int been_active;			/* Been active ? */
	int objd;				/* Object associated */
	struct cds_list_head chan_head;		/* Channel list head */
	struct cds_list_head events_head;	/* list of events */
	struct cds_list_head node;		/* Session list */

	/* New UST 2.1 */
	/* List of enablers */
	struct cds_list_head enablers_head;
	struct lttng_ust_event_ht events_ht;	/* ht of events */
	void *owner;				/* object owner */
	int tstate:1;				/* Transient enable state */

	/* New UST 2.4 */
	int statedump_pending:1;

	/* New UST 2.8 */
	struct lttng_ust_enum_ht enums_ht;	/* ht of enumerations */
	struct cds_list_head enums_head;
	struct lttng_ctx *ctx;			/* contexts for filters. */
};

static inline
struct lttng_enabler *lttng_event_enabler_as_enabler(
		struct lttng_event_enabler *event_enabler)
{
	return &event_enabler->base;
}

static inline
struct lttng_enabler *lttng_event_notifier_enabler_as_enabler(
		struct lttng_event_notifier_enabler *event_notifier_enabler)
{
	return &event_notifier_enabler->base;
}

/*
 * Allocate and initialize a `struct lttng_event_enabler` object.
 *
 * On success, returns a `struct lttng_event_enabler`,
 * On memory error, returns NULL.
 */
LTTNG_HIDDEN
struct lttng_event_enabler *lttng_event_enabler_create(
		enum lttng_enabler_format_type format_type,
		struct lttng_ust_abi_event *event_param,
		struct lttng_channel *chan);

/*
 * Destroy a `struct lttng_event_enabler` object.
 */
LTTNG_HIDDEN
void lttng_event_enabler_destroy(struct lttng_event_enabler *enabler);

/*
 * Enable a `struct lttng_event_enabler` object and all events related to this
 * enabler.
 */
LTTNG_HIDDEN
int lttng_event_enabler_enable(struct lttng_event_enabler *enabler);

/*
 * Disable a `struct lttng_event_enabler` object and all events related to this
 * enabler.
 */
LTTNG_HIDDEN
int lttng_event_enabler_disable(struct lttng_event_enabler *enabler);

/*
 * Attach filter bytecode program to `struct lttng_event_enabler` and all
 * events related to this enabler.
 */
LTTNG_HIDDEN
int lttng_event_enabler_attach_filter_bytecode(
		struct lttng_event_enabler *enabler,
		struct lttng_ust_bytecode_node **bytecode);

/*
 * Attach an application context to an event enabler.
 *
 * Not implemented.
 */
LTTNG_HIDDEN
int lttng_event_enabler_attach_context(struct lttng_event_enabler *enabler,
		struct lttng_ust_abi_context *ctx);

/*
 * Attach exclusion list to `struct lttng_event_enabler` and all
 * events related to this enabler.
 */
LTTNG_HIDDEN
int lttng_event_enabler_attach_exclusion(struct lttng_event_enabler *enabler,
		struct lttng_ust_excluder_node **excluder);

/*
 * Synchronize bytecodes for the enabler and the instance (event or
 * event_notifier).
 *
 * This function goes over all bytecode programs of the enabler (event or
 * event_notifier enabler) to ensure each is linked to the provided instance.
 */
LTTNG_HIDDEN
void lttng_enabler_link_bytecode(const struct lttng_event_desc *event_desc,
		struct lttng_ctx **ctx,
		struct cds_list_head *instance_bytecode_runtime_head,
		struct cds_list_head *enabler_bytecode_runtime_head);

/*
 * Allocate and initialize a `struct lttng_event_notifier_group` object.
 *
 * On success, returns a `struct lttng_triggre_group`,
 * on memory error, returns NULL.
 */
LTTNG_HIDDEN
struct lttng_event_notifier_group *lttng_event_notifier_group_create(void);

/*
 * Destroy a `struct lttng_event_notifier_group` object.
 */
LTTNG_HIDDEN
void lttng_event_notifier_group_destroy(
		struct lttng_event_notifier_group *event_notifier_group);

/*
 * Allocate and initialize a `struct lttng_event_notifier_enabler` object.
 *
 * On success, returns a `struct lttng_event_notifier_enabler`,
 * On memory error, returns NULL.
 */
LTTNG_HIDDEN
struct lttng_event_notifier_enabler *lttng_event_notifier_enabler_create(
		struct lttng_event_notifier_group *event_notifier_group,
		enum lttng_enabler_format_type format_type,
		struct lttng_ust_abi_event_notifier *event_notifier_param);

/*
 * Destroy a `struct lttng_event_notifier_enabler` object.
 */
LTTNG_HIDDEN
void lttng_event_notifier_enabler_destroy(
		struct lttng_event_notifier_enabler *event_notifier_enabler);

/*
 * Enable a `struct lttng_event_notifier_enabler` object and all event
 * notifiers related to this enabler.
 */
LTTNG_HIDDEN
int lttng_event_notifier_enabler_enable(
		struct lttng_event_notifier_enabler *event_notifier_enabler);

/*
 * Disable a `struct lttng_event_notifier_enabler` object and all event
 * notifiers related to this enabler.
 */
LTTNG_HIDDEN
int lttng_event_notifier_enabler_disable(
		struct lttng_event_notifier_enabler *event_notifier_enabler);

/*
 * Attach filter bytecode program to `struct lttng_event_notifier_enabler` and
 * all event notifiers related to this enabler.
 */
LTTNG_HIDDEN
int lttng_event_notifier_enabler_attach_filter_bytecode(
		struct lttng_event_notifier_enabler *event_notifier_enabler,
		struct lttng_ust_bytecode_node **bytecode);

/*
 * Attach capture bytecode program to `struct lttng_event_notifier_enabler` and
 * all event_notifiers related to this enabler.
 */
LTTNG_HIDDEN
int lttng_event_notifier_enabler_attach_capture_bytecode(
		struct lttng_event_notifier_enabler *event_notifier_enabler,
		struct lttng_ust_bytecode_node **bytecode);

/*
 * Attach exclusion list to `struct lttng_event_notifier_enabler` and all
 * event notifiers related to this enabler.
 */
LTTNG_HIDDEN
int lttng_event_notifier_enabler_attach_exclusion(
		struct lttng_event_notifier_enabler *event_notifier_enabler,
		struct lttng_ust_excluder_node **excluder);

LTTNG_HIDDEN
void lttng_free_event_recorder_filter_runtime(struct lttng_ust_event_recorder *event_recorder);

LTTNG_HIDDEN
void lttng_free_event_notifier_filter_runtime(
		struct lttng_ust_event_notifier *event_notifier);

/*
 * Connect the probe on all enablers matching this event description.
 * Called on library load.
 */
LTTNG_HIDDEN
int lttng_fix_pending_event_notifiers(void);

LTTNG_HIDDEN
struct lttng_counter *lttng_ust_counter_create(
		const char *counter_transport_name,
		size_t number_dimensions, const struct lttng_counter_dimension *dimensions);

#ifdef HAVE_PERF_EVENT

LTTNG_HIDDEN
int lttng_add_perf_counter_to_ctx(uint32_t type,
				  uint64_t config,
				  const char *name,
				  struct lttng_ctx **ctx);
LTTNG_HIDDEN
int lttng_perf_counter_init(void);
LTTNG_HIDDEN
void lttng_perf_counter_exit(void);

#else /* #ifdef HAVE_PERF_EVENT */

static inline
int lttng_add_perf_counter_to_ctx(uint32_t type,
				  uint64_t config,
				  const char *name,
				  struct lttng_ctx **ctx)
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
#endif /* #else #ifdef HAVE_PERF_EVENT */

LTTNG_HIDDEN
int lttng_probes_get_event_list(struct lttng_ust_tracepoint_list *list);
LTTNG_HIDDEN
void lttng_probes_prune_event_list(struct lttng_ust_tracepoint_list *list);

LTTNG_HIDDEN
int lttng_probes_get_field_list(struct lttng_ust_field_list *list);
LTTNG_HIDDEN
void lttng_probes_prune_field_list(struct lttng_ust_field_list *list);

LTTNG_HIDDEN
struct lttng_ust_abi_tracepoint_iter *
	lttng_ust_tracepoint_list_get_iter_next(struct lttng_ust_tracepoint_list *list);
LTTNG_HIDDEN
struct lttng_ust_abi_field_iter *
	lttng_ust_field_list_get_iter_next(struct lttng_ust_field_list *list);

LTTNG_HIDDEN
struct lttng_session *lttng_session_create(void);
LTTNG_HIDDEN
int lttng_session_enable(struct lttng_session *session);
LTTNG_HIDDEN
int lttng_session_disable(struct lttng_session *session);
LTTNG_HIDDEN
int lttng_session_statedump(struct lttng_session *session);
LTTNG_HIDDEN
void lttng_session_destroy(struct lttng_session *session);

LTTNG_HIDDEN
struct cds_list_head *lttng_get_sessions(void);

LTTNG_HIDDEN
void lttng_handle_pending_statedump(void *owner);

LTTNG_HIDDEN
struct lttng_channel *lttng_channel_create(struct lttng_session *session,
				       const char *transport_name,
				       void *buf_addr,
				       size_t subbuf_size, size_t num_subbuf,
				       unsigned int switch_timer_interval,
				       unsigned int read_timer_interval,
				       int **shm_fd, int **wait_fd,
				       uint64_t **memory_map_size,
				       struct lttng_channel *chan_priv_init);

LTTNG_HIDDEN
int lttng_channel_enable(struct lttng_channel *channel);
LTTNG_HIDDEN
int lttng_channel_disable(struct lttng_channel *channel);

LTTNG_HIDDEN
void lttng_transport_register(struct lttng_transport *transport);
LTTNG_HIDDEN
void lttng_transport_unregister(struct lttng_transport *transport);

LTTNG_HIDDEN
void lttng_probe_provider_unregister_events(struct lttng_probe_desc *desc);

LTTNG_HIDDEN
int lttng_fix_pending_events(void);

LTTNG_HIDDEN
struct cds_list_head *lttng_get_probe_list_head(void);

LTTNG_HIDDEN
struct lttng_enum *lttng_ust_enum_get_from_desc(struct lttng_session *session,
		const struct lttng_enum_desc *enum_desc);

LTTNG_HIDDEN
int lttng_abi_create_root_handle(void);

LTTNG_HIDDEN
const struct lttng_ust_abi_objd_ops *lttng_ust_abi_objd_ops(int id);
LTTNG_HIDDEN
int lttng_ust_abi_objd_unref(int id, int is_owner);
LTTNG_HIDDEN
void lttng_ust_abi_exit(void);
LTTNG_HIDDEN
void lttng_ust_abi_events_exit(void);
LTTNG_HIDDEN
void lttng_ust_abi_objd_table_owner_cleanup(void *owner);

#endif /* _LTTNG_UST_EVENTS_INTERNAL_H */
