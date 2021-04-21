/*
 * SPDX-License-Identifier: MIT
 *
 * Copyright 2019 (c) Francis Deslauriers <francis.deslauriers@efficios.com>
 */

#ifndef _UST_COMMON_UST_EVENTS_H
#define _UST_COMMON_UST_EVENTS_H

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
	const struct lttng_ust_ring_buffer_config *client_config;
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
	struct lttng_ust_ring_buffer_channel *rb_chan;	/* Ring buffer channel */
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
	void (*record)(void *priv, struct lttng_ust_ring_buffer_ctx *ctx,
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
	((const struct lttng_ust_type_common *) LTTNG_UST_COMPOUND_LITERAL(const struct lttng_ust_type_integer, { \
		.parent = {										\
			.type = lttng_ust_type_integer,							\
		},											\
		.struct_size = sizeof(struct lttng_ust_type_integer),					\
		.size = (_size),									\
		.alignment = (_alignment),								\
		.signedness = (_signedness),								\
		.reverse_byte_order = (_byte_order) != LTTNG_UST_BYTE_ORDER,					\
		.base = (_base),									\
	}))

#define lttng_ust_static_type_array_text(_length)							\
	((const struct lttng_ust_type_common *) LTTNG_UST_COMPOUND_LITERAL(const struct lttng_ust_type_array, { \
		.parent = {										\
			.type = lttng_ust_type_array,							\
		},											\
		.struct_size = sizeof(struct lttng_ust_type_array),					\
		.length = (_length),									\
		.alignment = 0,										\
		.encoding = lttng_ust_string_encoding_UTF8,						\
		.elem_type = lttng_ust_static_type_integer(sizeof(char) * CHAR_BIT,			\
				lttng_ust_rb_alignof(char) * CHAR_BIT, lttng_ust_is_signed_type(char),	\
				LTTNG_UST_BYTE_ORDER, 10),							\
	}))

#define lttng_ust_static_event_field(_name, _type, _nowrite, _nofilter)					\
	LTTNG_UST_COMPOUND_LITERAL(const struct lttng_ust_event_field, {				\
		.struct_size = sizeof(struct lttng_ust_event_field),					\
		.name = (_name),									\
		.type = (_type),									\
		.nowrite = (_nowrite),									\
		.nofilter = (_nofilter),								\
	})

#define lttng_ust_static_ctx_field(_event_field, _get_size, _record, _get_value, _destroy, _priv)	\
	LTTNG_UST_COMPOUND_LITERAL(const struct lttng_ust_ctx_field, {				\
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



/* This is ABI between liblttng-ust and liblttng-ust-ctl */
struct lttng_transport *lttng_ust_transport_find(const char *name);

/* This is ABI between liblttng-ust and liblttng-ust-dl */
void lttng_ust_dl_update(void *ip);

struct lttng_enum *lttng_ust_enum_get_from_desc(struct lttng_ust_session *session,
		const struct lttng_ust_enum_desc *enum_desc)
	__attribute__((visibility("hidden")));


#endif /* _UST_COMMON_UST_EVENTS_H */
