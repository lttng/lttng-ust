/*
 * SPDX-License-Identifier: MIT
 *
 * Copyright 2019 (c) Francis Deslauriers <francis.deslauriers@efficios.com>
 */

#ifndef _LTTNG_UST_EVENTS_INTERNAL_H
#define _LTTNG_UST_EVENTS_INTERNAL_H

#include <limits.h>
#include <stdint.h>

#include <urcu/list.h>
#include <urcu/hlist.h>

#include <lttng/ust-events.h>

#include "common/macros.h"
#include "common/ust-context-provider.h"

struct lttng_ust_abi_obj;
struct lttng_event_notifier_group;

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
	struct lttng_ust_channel_buffer *chan;
	/*
	 * Unused, but kept around to make it explicit that the tracer can do
	 * it.
	 */
	struct lttng_ust_ctx *ctx;
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

enum lttng_ust_bytecode_type {
	LTTNG_UST_BYTECODE_TYPE_FILTER,
	LTTNG_UST_BYTECODE_TYPE_CAPTURE,
};

struct lttng_ust_bytecode_node {
	enum lttng_ust_bytecode_type type;
	struct cds_list_head node;
	struct lttng_enabler *enabler;
	struct  {
		uint32_t len;
		uint32_t reloc_offset;
		uint64_t seqnum;
		char data[];
	} bc;
};

/*
 * Bytecode interpreter return value.
 */
enum lttng_ust_bytecode_interpreter_ret {
	LTTNG_UST_BYTECODE_INTERPRETER_ERROR = -1,
	LTTNG_UST_BYTECODE_INTERPRETER_OK = 0,
};

struct lttng_interpreter_output;
struct lttng_ust_bytecode_runtime_private;

enum lttng_ust_bytecode_filter_result {
	LTTNG_UST_BYTECODE_FILTER_ACCEPT = 0,
	LTTNG_UST_BYTECODE_FILTER_REJECT = 1,
};

struct lttng_ust_bytecode_filter_ctx {
	enum lttng_ust_bytecode_filter_result result;
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

struct lttng_counter_ops {
	struct lib_counter *(*counter_create)(size_t nr_dimensions,
			const struct lttng_counter_dimension *dimensions,
			int64_t global_sum_step,
			int global_counter_fd,
			int nr_counter_cpu_fds,
			const int *counter_cpu_fds,
			bool is_daemon);
	void (*counter_destroy)(struct lib_counter *counter);
	int (*counter_add)(struct lib_counter *counter,
			const size_t *dimension_indexes, int64_t v);
	int (*counter_read)(struct lib_counter *counter,
			const size_t *dimension_indexes, int cpu,
			int64_t *value, bool *overflow, bool *underflow);
	int (*counter_aggregate)(struct lib_counter *counter,
			const size_t *dimension_indexes, int64_t *value,
			bool *overflow, bool *underflow);
	int (*counter_clear)(struct lib_counter *counter, const size_t *dimension_indexes);
};

struct lttng_counter {
	int objd;
	struct lttng_event_notifier_group *event_notifier_group;    /* owner */
	struct lttng_counter_transport *transport;
	struct lib_counter *counter;
	struct lttng_counter_ops *ops;
};

#define LTTNG_UST_EVENT_HT_BITS		12
#define LTTNG_UST_EVENT_HT_SIZE		(1U << LTTNG_UST_EVENT_HT_BITS)

struct lttng_ust_event_ht {
	struct cds_hlist_head table[LTTNG_UST_EVENT_HT_SIZE];
};

#define LTTNG_UST_EVENT_NOTIFIER_HT_BITS		12
#define LTTNG_UST_EVENT_NOTIFIER_HT_SIZE		(1U << LTTNG_UST_EVENT_NOTIFIER_HT_BITS)
struct lttng_ust_event_notifier_ht {
	struct cds_hlist_head table[LTTNG_UST_EVENT_NOTIFIER_HT_SIZE];
};

#define LTTNG_UST_ENUM_HT_BITS		12
#define LTTNG_UST_ENUM_HT_SIZE		(1U << LTTNG_UST_ENUM_HT_BITS)

struct lttng_ust_enum_ht {
	struct cds_hlist_head table[LTTNG_UST_ENUM_HT_SIZE];
};

struct lttng_event_notifier_group {
	int objd;
	void *owner;
	int notification_fd;
	struct cds_list_head node;		/* Event notifier group handle list */
	struct cds_list_head enablers_head;
	struct cds_list_head event_notifiers_head; /* list of event_notifiers */
	struct lttng_ust_event_notifier_ht event_notifiers_ht; /* hashtable of event_notifiers */
	struct lttng_ust_ctx *ctx;		/* contexts for filters. */

	struct lttng_counter *error_counter;
	size_t error_counter_len;
};

struct lttng_transport {
	const char *name;
	struct cds_list_head node;
	struct lttng_ust_channel_buffer_ops ops;
	const struct lttng_ust_lib_ring_buffer_config *client_config;
};

struct lttng_counter_transport {
	const char *name;
	struct cds_list_head node;
	struct lttng_counter_ops ops;
	const struct lib_counter_config *client_config;
};

struct lttng_ust_event_common_private {
	struct lttng_ust_event_common *pub;	/* Public event interface */

	const struct lttng_ust_event_desc *desc;
	/* Backward references: list of lttng_enabler_ref (ref to enablers) */
	struct cds_list_head enablers_ref_head;
	int registered;				/* has reg'd tracepoint probe */
	uint64_t user_token;

	int has_enablers_without_filter_bytecode;
	/* list of struct lttng_ust_bytecode_runtime, sorted by seqnum */
	struct cds_list_head filter_bytecode_runtime_head;
};

struct lttng_ust_event_recorder_private {
	struct lttng_ust_event_common_private parent;

	struct lttng_ust_event_recorder *pub;	/* Public event interface */
	struct cds_list_head node;		/* Event recorder list */
	struct cds_hlist_node hlist;		/* Hash table of event recorders */
	struct lttng_ust_ctx *ctx;
	unsigned int id;
};

struct lttng_ust_event_notifier_private {
	struct lttng_ust_event_common_private parent;

	struct lttng_ust_event_notifier *pub;	/* Public event notifier interface */
	struct lttng_event_notifier_group *group; /* weak ref */
	size_t num_captures;			/* Needed to allocate the msgpack array. */
	uint64_t error_counter_index;
	struct cds_list_head node;		/* Event notifier list */
	struct cds_hlist_node hlist;		/* Hash table of event notifiers */
	struct cds_list_head capture_bytecode_runtime_head;
};

struct lttng_ust_bytecode_runtime {
	enum lttng_ust_bytecode_type type;
	struct lttng_ust_bytecode_node *bc;
	int link_failed;
	int (*interpreter_func)(struct lttng_ust_bytecode_runtime *bytecode_runtime,
			const char *interpreter_stack_data,
			void *ctx);
	struct cds_list_head node;		/* list of bytecode runtime in event */
	/*
	 * Pointer to a URCU-protected pointer owned by an `struct
	 * lttng_session`or `struct lttng_event_notifier_group`.
	 */
	struct lttng_ust_ctx **pctx;
};

struct lttng_ust_session_private {
	struct lttng_ust_session *pub;		/* Public session interface */

	int been_active;			/* Been active ? */
	int objd;				/* Object associated */
	struct cds_list_head chan_head;		/* Channel list head */
	struct cds_list_head events_head;	/* list of events */
	struct cds_list_head node;		/* Session list */

	/* List of enablers */
	struct cds_list_head enablers_head;
	struct lttng_ust_event_ht events_ht;	/* ht of events */
	void *owner;				/* object owner */
	int tstate:1;				/* Transient enable state */

	int statedump_pending:1;

	struct lttng_ust_enum_ht enums_ht;	/* ht of enumerations */
	struct cds_list_head enums_head;
	struct lttng_ust_ctx *ctx;		/* contexts for filters. */

	unsigned char uuid[LTTNG_UST_UUID_LEN];	/* Trace session unique ID */
	bool uuid_set;				/* Is uuid set ? */
};

struct lttng_enum {
	const struct lttng_ust_enum_desc *desc;
	struct lttng_ust_session *session;
	struct cds_list_head node;		/* Enum list in session */
	struct cds_hlist_node hlist;		/* Session ht of enums */
	uint64_t id;				/* Enumeration ID in sessiond */
};

struct lttng_ust_shm_handle;

struct lttng_ust_channel_buffer_ops_private {
	struct lttng_ust_channel_buffer_ops *pub;	/* Public channel buffer ops interface */

	struct lttng_ust_channel_buffer *(*channel_create)(const char *name,
			void *buf_addr,
			size_t subbuf_size, size_t num_subbuf,
			unsigned int switch_timer_interval,
			unsigned int read_timer_interval,
			unsigned char *uuid,
			uint32_t chan_id,
			const int *stream_fds, int nr_stream_fds,
			int64_t blocking_timeout);
	void (*channel_destroy)(struct lttng_ust_channel_buffer *chan);
	/*
	 * packet_avail_size returns the available size in the current
	 * packet. Note that the size returned is only a hint, since it
	 * may change due to concurrent writes.
	 */
	size_t (*packet_avail_size)(struct lttng_ust_channel_buffer *chan);
	int (*is_finalized)(struct lttng_ust_channel_buffer *chan);
	int (*is_disabled)(struct lttng_ust_channel_buffer *chan);
	int (*flush_buffer)(struct lttng_ust_channel_buffer *chan);
};

struct lttng_ust_channel_common_private {
	struct lttng_ust_channel_common *pub;	/* Public channel interface */

	int objd;				/* Object associated with channel. */
	int tstate:1;				/* Transient enable state */
};

struct lttng_ust_channel_buffer_private {
	struct lttng_ust_channel_common_private parent;

	struct lttng_ust_channel_buffer *pub;	/* Public channel buffer interface */
	struct cds_list_head node;		/* Channel list in session */
	int header_type;			/* 0: unset, 1: compact, 2: large */
	unsigned int id;			/* Channel ID */
	enum lttng_ust_abi_chan_type type;
	struct lttng_ust_ctx *ctx;
	struct lttng_ust_lib_ring_buffer_channel *rb_chan;	/* Ring buffer channel */
	unsigned char uuid[LTTNG_UST_UUID_LEN];	/* Trace session unique ID */
};

/*
 * IMPORTANT: this structure is part of the ABI between the consumer
 * daemon and the UST library within traced applications. Changing it
 * breaks the UST communication protocol.
 *
 * TODO: remove unused fields on next UST communication protocol
 * breaking update.
 */
struct lttng_ust_abi_channel_config {
	void *unused1;
	int unused2;
	void *unused3;
	void *unused4;
	int unused5;
	struct cds_list_head unused6;
	void *unused7;
	int unused8;
	void *unused9;

	/* Channel ID */
	unsigned int id;
	enum lttng_ust_abi_chan_type unused10;
	unsigned char uuid[LTTNG_UST_UUID_LEN]; /* Trace session unique ID */
	int unused11:1;
};

/* Global (filter), event and channel contexts. */
struct lttng_ust_ctx {
	struct lttng_ust_ctx_field *fields;
	unsigned int nr_fields;
	unsigned int allocated_fields;
	unsigned int largest_align;
};

struct lttng_ust_registered_probe {
	const struct lttng_ust_probe_desc *desc;

	struct cds_list_head head;		/* chain registered probes */
	struct cds_list_head lazy_init_head;
	int lazy;				/* lazy registration */
};

/*
 * Context field
 */

struct lttng_ust_ctx_field {
	const struct lttng_ust_event_field *event_field;
	size_t (*get_size)(void *priv, size_t offset);
	void (*record)(void *priv, struct lttng_ust_lib_ring_buffer_ctx *ctx,
		       struct lttng_ust_channel_buffer *chan);
	void (*get_value)(void *priv, struct lttng_ust_ctx_value *value);
	void (*destroy)(void *priv);
	void *priv;
};

static inline
const struct lttng_ust_type_integer *lttng_ust_get_type_integer(const struct lttng_ust_type_common *type)
{
	if (type->type != lttng_ust_type_integer)
		return NULL;
	return caa_container_of(type, const struct lttng_ust_type_integer, parent);
}

static inline
const struct lttng_ust_type_float *lttng_ust_get_type_float(const struct lttng_ust_type_common *type)
{
	if (type->type != lttng_ust_type_float)
		return NULL;
	return caa_container_of(type, const struct lttng_ust_type_float, parent);
}

static inline
const struct lttng_ust_type_string *lttng_ust_get_type_string(const struct lttng_ust_type_common *type)
{
	if (type->type != lttng_ust_type_string)
		return NULL;
	return caa_container_of(type, const struct lttng_ust_type_string, parent);
}

static inline
const struct lttng_ust_type_enum *lttng_ust_get_type_enum(const struct lttng_ust_type_common *type)
{
	if (type->type != lttng_ust_type_enum)
		return NULL;
	return caa_container_of(type, const struct lttng_ust_type_enum, parent);
}

static inline
const struct lttng_ust_type_array *lttng_ust_get_type_array(const struct lttng_ust_type_common *type)
{
	if (type->type != lttng_ust_type_array)
		return NULL;
	return caa_container_of(type, const struct lttng_ust_type_array, parent);
}

static inline
const struct lttng_ust_type_sequence *lttng_ust_get_type_sequence(const struct lttng_ust_type_common *type)
{
	if (type->type != lttng_ust_type_sequence)
		return NULL;
	return caa_container_of(type, const struct lttng_ust_type_sequence, parent);
}

static inline
const struct lttng_ust_type_struct *lttng_ust_get_type_struct(const struct lttng_ust_type_common *type)
{
	if (type->type != lttng_ust_type_struct)
		return NULL;
	return caa_container_of(type, const struct lttng_ust_type_struct, parent);
}

#define lttng_ust_static_type_integer(_size, _alignment, _signedness, _byte_order, _base)		\
	((const struct lttng_ust_type_common *) __LTTNG_COMPOUND_LITERAL(const struct lttng_ust_type_integer, { \
		.parent = {										\
			.type = lttng_ust_type_integer,							\
		},											\
		.struct_size = sizeof(struct lttng_ust_type_integer),					\
		.size = (_size),									\
		.alignment = (_alignment),								\
		.signedness = (_signedness),								\
		.reverse_byte_order = (_byte_order) != BYTE_ORDER,					\
		.base = (_base),									\
	}))

#define lttng_ust_static_type_array_text(_length)							\
	((const struct lttng_ust_type_common *) __LTTNG_COMPOUND_LITERAL(const struct lttng_ust_type_array, { \
		.parent = {										\
			.type = lttng_ust_type_array,							\
		},											\
		.struct_size = sizeof(struct lttng_ust_type_array),					\
		.length = (_length),									\
		.alignment = 0,										\
		.encoding = lttng_ust_string_encoding_UTF8,						\
		.elem_type = lttng_ust_static_type_integer(sizeof(char) * CHAR_BIT,			\
				lttng_ust_rb_alignof(char) * CHAR_BIT, lttng_ust_is_signed_type(char),	\
				BYTE_ORDER, 10),							\
	}))

#define lttng_ust_static_event_field(_name, _type, _nowrite, _nofilter)					\
	__LTTNG_COMPOUND_LITERAL(const struct lttng_ust_event_field, {					\
		.struct_size = sizeof(struct lttng_ust_event_field),					\
		.name = (_name),									\
		.type = (_type),									\
		.nowrite = (_nowrite),									\
		.nofilter = (_nofilter),								\
	})

#define lttng_ust_static_ctx_field(_event_field, _get_size, _record, _get_value, _destroy, _priv)	\
	__LTTNG_COMPOUND_LITERAL(const struct lttng_ust_ctx_field, {					\
		.event_field = (_event_field),								\
		.get_size = (_get_size),								\
		.record = (_record),									\
		.get_value = (_get_value),								\
		.destroy = (_destroy),									\
		.priv = (_priv),									\
	})

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
struct lttng_event_enabler *lttng_event_enabler_create(
		enum lttng_enabler_format_type format_type,
		struct lttng_ust_abi_event *event_param,
		struct lttng_ust_channel_buffer *chan)
	__attribute__((visibility("hidden")));

/*
 * Destroy a `struct lttng_event_enabler` object.
 */
void lttng_event_enabler_destroy(struct lttng_event_enabler *enabler)
	__attribute__((visibility("hidden")));

/*
 * Enable a `struct lttng_event_enabler` object and all events related to this
 * enabler.
 */
int lttng_event_enabler_enable(struct lttng_event_enabler *enabler)
	__attribute__((visibility("hidden")));

/*
 * Disable a `struct lttng_event_enabler` object and all events related to this
 * enabler.
 */
int lttng_event_enabler_disable(struct lttng_event_enabler *enabler)
	__attribute__((visibility("hidden")));

/*
 * Attach filter bytecode program to `struct lttng_event_enabler` and all
 * events related to this enabler.
 */
int lttng_event_enabler_attach_filter_bytecode(
		struct lttng_event_enabler *enabler,
		struct lttng_ust_bytecode_node **bytecode)
	__attribute__((visibility("hidden")));

/*
 * Attach an application context to an event enabler.
 *
 * Not implemented.
 */
int lttng_event_enabler_attach_context(struct lttng_event_enabler *enabler,
		struct lttng_ust_abi_context *ctx)
	__attribute__((visibility("hidden")));

/*
 * Attach exclusion list to `struct lttng_event_enabler` and all
 * events related to this enabler.
 */
int lttng_event_enabler_attach_exclusion(struct lttng_event_enabler *enabler,
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
 * Destroy a `struct lttng_event_notifier_enabler` object.
 */
void lttng_event_notifier_enabler_destroy(
		struct lttng_event_notifier_enabler *event_notifier_enabler)
	__attribute__((visibility("hidden")));

/*
 * Enable a `struct lttng_event_notifier_enabler` object and all event
 * notifiers related to this enabler.
 */
int lttng_event_notifier_enabler_enable(
		struct lttng_event_notifier_enabler *event_notifier_enabler)
	__attribute__((visibility("hidden")));

/*
 * Disable a `struct lttng_event_notifier_enabler` object and all event
 * notifiers related to this enabler.
 */
int lttng_event_notifier_enabler_disable(
		struct lttng_event_notifier_enabler *event_notifier_enabler)
	__attribute__((visibility("hidden")));

/*
 * Attach filter bytecode program to `struct lttng_event_notifier_enabler` and
 * all event notifiers related to this enabler.
 */
int lttng_event_notifier_enabler_attach_filter_bytecode(
		struct lttng_event_notifier_enabler *event_notifier_enabler,
		struct lttng_ust_bytecode_node **bytecode)
	__attribute__((visibility("hidden")));

/*
 * Attach capture bytecode program to `struct lttng_event_notifier_enabler` and
 * all event_notifiers related to this enabler.
 */
int lttng_event_notifier_enabler_attach_capture_bytecode(
		struct lttng_event_notifier_enabler *event_notifier_enabler,
		struct lttng_ust_bytecode_node **bytecode)
	__attribute__((visibility("hidden")));

/*
 * Attach exclusion list to `struct lttng_event_notifier_enabler` and all
 * event notifiers related to this enabler.
 */
int lttng_event_notifier_enabler_attach_exclusion(
		struct lttng_event_notifier_enabler *event_notifier_enabler,
		struct lttng_ust_excluder_node **excluder)
	__attribute__((visibility("hidden")));

void lttng_free_event_filter_runtime(struct lttng_ust_event_common *event)
	__attribute__((visibility("hidden")));

/*
 * Connect the probe on all enablers matching this event description.
 * Called on library load.
 */
int lttng_fix_pending_event_notifiers(void)
	__attribute__((visibility("hidden")));

struct lttng_counter *lttng_ust_counter_create(
		const char *counter_transport_name,
		size_t number_dimensions, const struct lttng_counter_dimension *dimensions)
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
int lttng_add_perf_counter_to_ctx(uint32_t type,
				  uint64_t config,
				  const char *name,
				  struct lttng_ust_ctx **ctx)
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

void lttng_transport_register(struct lttng_transport *transport)
	__attribute__((visibility("hidden")));

void lttng_transport_unregister(struct lttng_transport *transport)
	__attribute__((visibility("hidden")));

/* This is ABI between liblttng-ust and liblttng-ust-ctl */
struct lttng_transport *lttng_ust_transport_find(const char *name);

/* This is ABI between liblttng-ust and liblttng-ust-dl */
void lttng_ust_dl_update(void *ip);

void lttng_probe_provider_unregister_events(const struct lttng_ust_probe_desc *desc)
	__attribute__((visibility("hidden")));

int lttng_fix_pending_events(void)
	__attribute__((visibility("hidden")));

struct cds_list_head *lttng_get_probe_list_head(void)
	__attribute__((visibility("hidden")));

struct lttng_enum *lttng_ust_enum_get_from_desc(struct lttng_ust_session *session,
		const struct lttng_ust_enum_desc *enum_desc)
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

struct lttng_ust_channel_buffer *lttng_ust_alloc_channel_buffer(void)
	__attribute__((visibility("hidden")));

void lttng_ust_free_channel_common(struct lttng_ust_channel_common *chan)
	__attribute__((visibility("hidden")));

int lttng_ust_interpret_event_filter(struct lttng_ust_event_common *event,
		const char *interpreter_stack_data,
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
		size_t (*get_size)(void *priv, size_t offset),
		void (*record)(void *priv, struct lttng_ust_lib_ring_buffer_ctx *ctx,
			struct lttng_ust_channel_buffer *chan),
		void (*get_value)(void *priv, struct lttng_ust_ctx_value *value),
		void *priv)
	__attribute__((visibility("hidden")));

void lttng_ust_context_set_session_provider(const char *name,
		size_t (*get_size)(void *priv, size_t offset),
		void (*record)(void *priv, struct lttng_ust_lib_ring_buffer_ctx *ctx,
			struct lttng_ust_channel_buffer *chan),
		void (*get_value)(void *priv, struct lttng_ust_ctx_value *value),
		void *priv)
	__attribute__((visibility("hidden")));

#endif /* _LTTNG_UST_EVENTS_INTERNAL_H */
