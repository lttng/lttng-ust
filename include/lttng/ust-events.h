#ifndef _LTTNG_UST_EVENTS_H
#define _LTTNG_UST_EVENTS_H

/*
 * lttng/ust-events.h
 *
 * Copyright 2010 (c) - Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 *
 * Holds LTTng per-session event registry.
 *
 * THIS MATERIAL IS PROVIDED AS IS, WITH ABSOLUTELY NO WARRANTY EXPRESSED
 * OR IMPLIED.  ANY USE IS AT YOUR OWN RISK.
 *
 * Permission is hereby granted to use or copy this program
 * for any purpose,  provided the above notices are retained on all copies.
 * Permission to modify the code and to distribute modified code is granted,
 * provided the above notices are retained, and a notice that the code was
 * modified is included with the above copyright notice.
 */

#include <urcu/list.h>
#include <urcu/hlist.h>
#include <uuid/uuid.h>
#include <stdint.h>
#include <lttng/ust-abi.h>
#include <lttng/ust-tracer.h>
#include <endian.h>
#include <float.h>

struct ltt_channel;
struct ltt_session;
struct lttng_ust_lib_ring_buffer_ctx;

/*
 * LTTng client type enumeration. Used by the consumer to map the
 * callbacks from its own address space.
 */
enum lttng_client_types {
	LTTNG_CLIENT_METADATA = 0,
	LTTNG_CLIENT_DISCARD = 1,
	LTTNG_CLIENT_OVERWRITE = 2,
	LTTNG_NR_CLIENT_TYPES,
};

/* Type description */

/* Update the astract_types name table in lttng-types.c along with this enum */
enum abstract_types {
	atype_integer,
	atype_enum,
	atype_array,
	atype_sequence,
	atype_string,
	atype_float,
	NR_ABSTRACT_TYPES,
};

/* Update the string_encodings name table in lttng-types.c along with this enum */
enum lttng_string_encodings {
	lttng_encode_none = 0,
	lttng_encode_UTF8 = 1,
	lttng_encode_ASCII = 2,
	NR_STRING_ENCODINGS,
};

struct lttng_enum_entry {
	unsigned long long start, end;	/* start and end are inclusive */
	const char *string;
};

#define __type_integer(_type, _byte_order, _base, _encoding)	\
	{							\
	    .atype = atype_integer,				\
	    .u.basic.integer =					\
		{						\
		  .size = sizeof(_type) * CHAR_BIT,		\
		  .alignment = lttng_alignof(_type) * CHAR_BIT,	\
		  .signedness = lttng_is_signed_type(_type),	\
		  .reverse_byte_order = _byte_order != __BYTE_ORDER,	\
		  .base = _base,				\
		  .encoding = lttng_encode_##_encoding,		\
		},						\
	}							\

struct lttng_integer_type {
	unsigned int size;		/* in bits */
	unsigned short alignment;	/* in bits */
	unsigned int signedness:1;
	unsigned int reverse_byte_order:1;
	unsigned int base;		/* 2, 8, 10, 16, for pretty print */
	enum lttng_string_encodings encoding;
};

/*
 * Only float and double are supported. long double is not supported at
 * the moment.
 */
#define _float_mant_dig(_type)						\
	(sizeof(_type) == sizeof(float) ? FLT_MANT_DIG			\
		: (sizeof(_type) == sizeof(double) ? DBL_MANT_DIG	\
		: 0))

#define __type_float(_type)					\
	{							\
	    .atype = atype_float,				\
	    .u.basic._float =					\
		{						\
		  .exp_dig = sizeof(_type) * CHAR_BIT		\
				- _float_mant_dig(_type),	\
		  .mant_dig = _float_mant_dig(_type),		\
		  .alignment = lttng_alignof(_type) * CHAR_BIT,	\
		  .reverse_byte_order = __BYTE_ORDER != __FLOAT_WORD_ORDER, \
		},						\
	}							\

struct lttng_float_type {
	unsigned int exp_dig;		/* exponent digits, in bits */
	unsigned int mant_dig;		/* mantissa digits, in bits */
	unsigned short alignment;	/* in bits */
	unsigned int reverse_byte_order:1;
};

union _lttng_basic_type {
	struct lttng_integer_type integer;
	struct {
		const char *name;
	} enumeration;
	struct {
		enum lttng_string_encodings encoding;
	} string;
	struct lttng_float_type _float;
};

struct lttng_basic_type {
	enum abstract_types atype;
	union {
		union _lttng_basic_type basic;
	} u;
};

struct lttng_type {
	enum abstract_types atype;
	union {
		union _lttng_basic_type basic;
		struct {
			struct lttng_basic_type elem_type;
			unsigned int length;		/* num. elems. */
		} array;
		struct {
			struct lttng_basic_type length_type;
			struct lttng_basic_type elem_type;
		} sequence;
	} u;
};

struct lttng_enum {
	const char *name;
	struct lttng_type container_type;
	const struct lttng_enum_entry *entries;
	unsigned int len;
};

/* Event field description */

struct lttng_event_field {
	const char *name;
	struct lttng_type type;
};

struct lttng_ctx_field {
	struct lttng_event_field event_field;
	size_t (*get_size)(size_t offset);
	void (*record)(struct lttng_ctx_field *field,
		       struct lttng_ust_lib_ring_buffer_ctx *ctx,
		       struct ltt_channel *chan);
	union {
	} u;
	void (*destroy)(struct lttng_ctx_field *field);
};

struct lttng_ctx {
	struct lttng_ctx_field *fields;
	unsigned int nr_fields;
	unsigned int allocated_fields;
};

struct tracepoint_loglevel_entry  {
	const char *identifier;
	long value;
};

struct loglevel_entry;

/*
 * Entry describing a per-session active loglevel, along with the event
 * attribute and channel information configuring the events that need to
 * be enabled.
 */
struct session_loglevel {
	struct ltt_channel *chan;
	struct lttng_ctx *ctx;	/* TODO */
	struct lttng_ust_event event_param;
	struct cds_list_head events;	/* list of events enabled */
	struct cds_list_head list;	/* per-session list of loglevels */
	struct cds_list_head session_list;
	struct loglevel_entry *entry;
	unsigned int enabled:1;
};

/*
 * Entry describing an active loglevel (per name) for all sessions.
 */
struct loglevel_entry {
	struct cds_hlist_node hlist;
	struct cds_list_head session_list;
	char name[0];
};

/*
 * Entry describing a per-session active wildcard, along with the event
 * attribute and channel information configuring the events that need to
 * be enabled.
 */
struct session_wildcard {
	struct ltt_channel *chan;
	struct lttng_ctx *ctx;	/* TODO */
	struct lttng_ust_event event_param;
	struct cds_list_head events;	/* list of events enabled */
	struct cds_list_head list;	/* per-session list of wildcards */
	struct cds_list_head session_list;
	struct wildcard_entry *entry;
	unsigned int enabled:1;
};

/*
 * Entry describing an active wildcard (per name) for all sessions.
 */
struct wildcard_entry {
	struct cds_list_head list;
	struct cds_list_head session_list;
	char name[0];
};

struct lttng_event_desc {
	const char *name;
	void *probe_callback;
	const struct lttng_event_ctx *ctx;	/* context */
	const struct lttng_event_field *fields;	/* event payload */
	unsigned int nr_fields;
	const struct tracepoint_loglevel_entry **loglevel;
};

struct lttng_probe_desc {
	const char *provider;
	const struct lttng_event_desc **event_desc;
	unsigned int nr_events;
	const struct tracepoint_loglevel_entry **loglevels;
	unsigned int nr_loglevels;
	struct cds_list_head head;		/* chain registered probes */
};

struct tp_list_entry {
	struct lttng_ust_tracepoint_iter tp;
	struct cds_list_head head;
};

struct lttng_ust_tracepoint_list {
	struct tp_list_entry *iter;
	struct cds_list_head head;
};

struct ust_pending_probe;

/*
 * ltt_event structure is referred to by the tracing fast path. It must be
 * kept small.
 * Note about loglevel_list: this list is only used to enable/disable
 * events on a per-loglevel basis. The events created internally by the
 * loglevel are only freed when the session is destroyed.
 */
struct ltt_event {
	unsigned int id;
	struct ltt_channel *chan;
	int enabled;
	const struct lttng_event_desc *desc;
	void *filter;
	struct lttng_ctx *ctx;
	enum lttng_ust_instrumentation instrumentation;
	union {
	} u;
	struct cds_list_head list;		/* Event list */
	struct cds_list_head loglevel_list;	/* Event list for loglevel */
	struct cds_list_head wildcard_list;	/* Event list for wildcard */
	struct ust_pending_probe *pending_probe;
	unsigned int metadata_dumped:1;
};

struct channel;
struct lttng_ust_shm_handle;

struct ltt_channel_ops {
	struct ltt_channel *(*channel_create)(const char *name,
				void *buf_addr,
				size_t subbuf_size, size_t num_subbuf,
				unsigned int switch_timer_interval,
				unsigned int read_timer_interval,
				int *shm_fd, int *wait_fd,
				uint64_t *memory_map_size,
				struct ltt_channel *chan_priv_init);
	void (*channel_destroy)(struct ltt_channel *ltt_chan);
	struct lttng_ust_lib_ring_buffer *(*buffer_read_open)(struct channel *chan,
				struct lttng_ust_shm_handle *handle,
				int *shm_fd, int *wait_fd,
				uint64_t *memory_map_size);
	void (*buffer_read_close)(struct lttng_ust_lib_ring_buffer *buf,
				struct lttng_ust_shm_handle *handle);
	int (*event_reserve)(struct lttng_ust_lib_ring_buffer_ctx *ctx,
			     uint32_t event_id);
	void (*event_commit)(struct lttng_ust_lib_ring_buffer_ctx *ctx);
	void (*event_write)(struct lttng_ust_lib_ring_buffer_ctx *ctx, const void *src,
			    size_t len);
	/*
	 * packet_avail_size returns the available size in the current
	 * packet. Note that the size returned is only a hint, since it
	 * may change due to concurrent writes.
	 */
	size_t (*packet_avail_size)(struct channel *chan,
				    struct lttng_ust_shm_handle *handle);
	//wait_queue_head_t *(*get_reader_wait_queue)(struct channel *chan);
	//wait_queue_head_t *(*get_hp_wait_queue)(struct channel *chan);
	int (*is_finalized)(struct channel *chan);
	int (*is_disabled)(struct channel *chan);
	int (*flush_buffer)(struct channel *chan, struct lttng_ust_shm_handle *handle);
};

struct ltt_channel {
	/*
	 * The pointers located in this private data are NOT safe to be
	 * dereferenced by the consumer. The only operations the
	 * consumer process is designed to be allowed to do is to read
	 * and perform subbuffer flush.
	 */
	struct channel *chan;		/* Channel buffers */
	int enabled;
	struct lttng_ctx *ctx;
	/* Event ID management */
	struct ltt_session *session;
	int objd;			/* Object associated to channel */
	unsigned int free_event_id;	/* Next event ID to allocate */
	unsigned int used_event_id;	/* Max allocated event IDs */
	struct cds_list_head list;	/* Channel list */
	struct ltt_channel_ops *ops;
	int header_type;		/* 0: unset, 1: compact, 2: large */
	struct lttng_ust_shm_handle *handle;	/* shared-memory handle */
	unsigned int metadata_dumped:1;

	/* Channel ID, available for consumer too */
	unsigned int id;
	/* Copy of session UUID for consumer (availability through shm) */
	uuid_t uuid;			/* Trace session unique ID */
};

struct ltt_session {
	int active;			/* Is trace session active ? */
	int been_active;		/* Has trace session been active ? */
	int objd;			/* Object associated to session */
	struct ltt_channel *metadata;	/* Metadata channel */
	struct cds_list_head chan;	/* Channel list head */
	struct cds_list_head events;	/* Event list head */
	struct cds_list_head loglevels;	/* Loglevel list head */
	struct cds_list_head wildcards;	/* Wildcard list head */
	struct cds_list_head list;	/* Session list */
	unsigned int free_chan_id;	/* Next chan ID to allocate */
	uuid_t uuid;			/* Trace session unique ID */
	unsigned int metadata_dumped:1;
};

struct ltt_transport {
	char *name;
	struct cds_list_head node;
	struct ltt_channel_ops ops;
};

struct ltt_session *ltt_session_create(void);
int ltt_session_enable(struct ltt_session *session);
int ltt_session_disable(struct ltt_session *session);
void ltt_session_destroy(struct ltt_session *session);

struct ltt_channel *ltt_channel_create(struct ltt_session *session,
				       const char *transport_name,
				       void *buf_addr,
				       size_t subbuf_size, size_t num_subbuf,
				       unsigned int switch_timer_interval,
				       unsigned int read_timer_interval,
				       int *shm_fd, int *wait_fd,
				       uint64_t *memory_map_size,
				       struct ltt_channel *chan_priv_init);
struct ltt_channel *ltt_global_channel_create(struct ltt_session *session,
				       int overwrite, void *buf_addr,
				       size_t subbuf_size, size_t num_subbuf,
				       unsigned int switch_timer_interval,
				       unsigned int read_timer_interval,
				       int *shm_fd, int *wait_fd,
				       uint64_t *memory_map_size);

int ltt_event_create(struct ltt_channel *chan,
		struct lttng_ust_event *event_param,
		void *filter,
		struct ltt_event **event);

int ltt_channel_enable(struct ltt_channel *channel);
int ltt_channel_disable(struct ltt_channel *channel);
int ltt_event_enable(struct ltt_event *event);
int ltt_event_disable(struct ltt_event *event);

void ltt_transport_register(struct ltt_transport *transport);
void ltt_transport_unregister(struct ltt_transport *transport);

void synchronize_trace(void);

int ltt_probe_register(struct lttng_probe_desc *desc);
void ltt_probe_unregister(struct lttng_probe_desc *desc);
int pending_probe_fix_events(const struct lttng_event_desc *desc);
const struct lttng_event_desc *ltt_event_get(const char *name);
void ltt_event_put(const struct lttng_event_desc *desc);
int ltt_probes_init(void);
void ltt_probes_exit(void);
int lttng_find_context(struct lttng_ctx *ctx, const char *name);
struct lttng_ctx_field *lttng_append_context(struct lttng_ctx **ctx_p);
void lttng_remove_context_field(struct lttng_ctx **ctx_p,
				struct lttng_ctx_field *field);
void lttng_destroy_context(struct lttng_ctx *ctx);
int lttng_add_vtid_to_ctx(struct lttng_ctx **ctx);
int lttng_add_vpid_to_ctx(struct lttng_ctx **ctx);
int lttng_add_pthread_id_to_ctx(struct lttng_ctx **ctx);
int lttng_add_procname_to_ctx(struct lttng_ctx **ctx);
void lttng_context_vtid_reset(void);
void lttng_context_vpid_reset(void);

const struct lttng_ust_lib_ring_buffer_client_cb *lttng_client_callbacks_metadata;
const struct lttng_ust_lib_ring_buffer_client_cb *lttng_client_callbacks_discard;
const struct lttng_ust_lib_ring_buffer_client_cb *lttng_client_callbacks_overwrite;

struct ltt_transport *ltt_transport_find(const char *name);

int ltt_probes_get_event_list(struct lttng_ust_tracepoint_list *list);
void ltt_probes_prune_event_list(struct lttng_ust_tracepoint_list *list);
struct lttng_ust_tracepoint_iter *
	lttng_ust_tracepoint_list_get_iter_next(struct lttng_ust_tracepoint_list *list);

struct loglevel_entry *get_loglevel(const char *name);
struct loglevel_entry *get_loglevel_value(int64_t value);
struct session_loglevel *add_loglevel(const char *name,
	struct ltt_channel *chan,
	struct lttng_ust_event *event_param);
void _remove_loglevel(struct session_loglevel *loglevel);
int ltt_loglevel_enable(struct session_loglevel *loglevel);
int ltt_loglevel_disable(struct session_loglevel *loglevel);
int ltt_loglevel_create(struct ltt_channel *chan,
	struct lttng_ust_event *event_param,
	struct session_loglevel **sl);

struct wildcard_entry *match_wildcard(const char *name);
struct session_wildcard *add_wildcard(const char *name,
	struct ltt_channel *chan,
	struct lttng_ust_event *event_param);
void _remove_wildcard(struct session_wildcard *wildcard);
int ltt_wildcard_enable(struct session_wildcard *wildcard);
int ltt_wildcard_disable(struct session_wildcard *wildcard);
int ltt_wildcard_create(struct ltt_channel *chan,
	struct lttng_ust_event *event_param,
	struct session_wildcard **sl);

#endif /* _LTTNG_UST_EVENTS_H */
