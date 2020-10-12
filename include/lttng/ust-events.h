#ifndef _LTTNG_UST_EVENTS_H
#define _LTTNG_UST_EVENTS_H

/*
 * lttng/ust-events.h
 *
 * Copyright 2010-2012 (c) - Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 *
 * Holds LTTng per-session event registry.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#include <urcu/list.h>
#include <urcu/hlist.h>
#include <stddef.h>
#include <stdint.h>
#include <lttng/ust-config.h>
#include <lttng/ust-abi.h>
#include <lttng/ust-tracer.h>
#include <lttng/ust-endian.h>
#include <float.h>
#include <errno.h>
#include <urcu/ref.h>
#include <pthread.h>

#ifndef LTTNG_PACKED
#error "LTTNG_PACKED should be defined"
#endif

#ifdef __cplusplus
extern "C" {
#endif

#define LTTNG_UST_UUID_LEN		16

/*
 * Tracepoint provider version. Compatibility based on the major number.
 * Older tracepoint providers can always register to newer lttng-ust
 * library, but the opposite is rejected: a newer tracepoint provider is
 * rejected by an older lttng-ust library.
 */
#define LTTNG_UST_PROVIDER_MAJOR	2
#define LTTNG_UST_PROVIDER_MINOR	0

struct lttng_channel;
struct lttng_session;
struct lttng_ust_lib_ring_buffer_ctx;
struct lttng_ust_context_app;
struct lttng_event_field;
struct lttng_event_notifier_group;

/*
 * Data structures used by tracepoint event declarations, and by the
 * tracer. Those structures have padding for future extension.
 */

/*
 * LTTng client type enumeration. Used by the consumer to map the
 * callbacks from its own address space.
 */
enum lttng_client_types {
	LTTNG_CLIENT_METADATA = 0,
	LTTNG_CLIENT_DISCARD = 1,
	LTTNG_CLIENT_OVERWRITE = 2,
	LTTNG_CLIENT_DISCARD_RT = 3,
	LTTNG_CLIENT_OVERWRITE_RT = 4,
	LTTNG_NR_CLIENT_TYPES,
};

/* Type description */

/* Update the astract_types name table in lttng-types.c along with this enum */
enum lttng_abstract_types {
	atype_integer,
	atype_enum,	/* legacy */
	atype_array,	/* legacy */
	atype_sequence,	/* legacy */
	atype_string,
	atype_float,
	atype_dynamic,
	atype_struct,	/* legacy */
	atype_enum_nestable,
	atype_array_nestable,
	atype_sequence_nestable,
	atype_struct_nestable,
	NR_ABSTRACT_TYPES,
};

/* Update the string_encodings name table in lttng-types.c along with this enum */
enum lttng_string_encodings {
	lttng_encode_none = 0,
	lttng_encode_UTF8 = 1,
	lttng_encode_ASCII = 2,
	NR_STRING_ENCODINGS,
};

struct lttng_enum_value {
	unsigned long long value;
	unsigned int signedness:1;
};

enum lttng_enum_entry_options {
	LTTNG_ENUM_ENTRY_OPTION_IS_AUTO = 1U << 0,
};

#define LTTNG_UST_ENUM_ENTRY_PADDING	16
struct lttng_enum_entry {
	struct lttng_enum_value start, end; /* start and end are inclusive */
	const char *string;
	union {
		struct {
			unsigned int options;
		} LTTNG_PACKED extra;
		char padding[LTTNG_UST_ENUM_ENTRY_PADDING];
	} u;
};

#define __type_integer(_type, _byte_order, _base, _encoding)	\
	{							\
	  .atype = atype_integer,				\
	  .u =							\
		{						\
		  .integer =					\
			{					\
			  .size = sizeof(_type) * CHAR_BIT,	\
			  .alignment = lttng_alignof(_type) * CHAR_BIT,	\
			  .signedness = lttng_is_signed_type(_type), \
			  .reverse_byte_order = _byte_order != BYTE_ORDER, \
			  .base = _base,			\
			  .encoding = lttng_encode_##_encoding,	\
			}					\
		},						\
	}							\

#define LTTNG_UST_INTEGER_TYPE_PADDING	24
struct lttng_integer_type {
	unsigned int size;		/* in bits */
	unsigned short alignment;	/* in bits */
	unsigned int signedness:1;
	unsigned int reverse_byte_order:1;
	unsigned int base;		/* 2, 8, 10, 16, for pretty print */
	enum lttng_string_encodings encoding;
	char padding[LTTNG_UST_INTEGER_TYPE_PADDING];
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
	  .atype = atype_float,					\
	  .u =							\
		{						\
		  ._float =					\
			{					\
			  .exp_dig = sizeof(_type) * CHAR_BIT	\
					  - _float_mant_dig(_type), \
			  .mant_dig = _float_mant_dig(_type),	\
			  .alignment = lttng_alignof(_type) * CHAR_BIT, \
			  .reverse_byte_order = BYTE_ORDER != FLOAT_WORD_ORDER,	\
			}					\
		}						\
	}							\

#define LTTNG_UST_FLOAT_TYPE_PADDING	24
struct lttng_float_type {
	unsigned int exp_dig;		/* exponent digits, in bits */
	unsigned int mant_dig;		/* mantissa digits, in bits */
	unsigned short alignment;	/* in bits */
	unsigned int reverse_byte_order:1;
	char padding[LTTNG_UST_FLOAT_TYPE_PADDING];
};

/* legacy */
#define LTTNG_UST_BASIC_TYPE_PADDING	128
union _lttng_basic_type {
	struct lttng_integer_type integer;	/* legacy */
	struct {
		const struct lttng_enum_desc *desc;	/* Enumeration mapping */
		struct lttng_integer_type container_type;
	} enumeration;				/* legacy */
	struct {
		enum lttng_string_encodings encoding;
	} string;				/* legacy */
	struct lttng_float_type _float;		/* legacy */
	char padding[LTTNG_UST_BASIC_TYPE_PADDING];
};

/* legacy */
struct lttng_basic_type {
	enum lttng_abstract_types atype;
	union {
		union _lttng_basic_type basic;
	} u;
};

#define LTTNG_UST_TYPE_PADDING	128
struct lttng_type {
	enum lttng_abstract_types atype;
	union {
		/* provider ABI 2.0 */
		struct lttng_integer_type integer;
		struct lttng_float_type _float;
		struct {
			enum lttng_string_encodings encoding;
		} string;
		struct {
			const struct lttng_enum_desc *desc;	/* Enumeration mapping */
			struct lttng_type *container_type;
		} enum_nestable;
		struct {
			const struct lttng_type *elem_type;
			unsigned int length;			/* Num. elems. */
			unsigned int alignment;
		} array_nestable;
		struct {
			const char *length_name;		/* Length field name. */
			const struct lttng_type *elem_type;
			unsigned int alignment;			/* Alignment before elements. */
		} sequence_nestable;
		struct {
			unsigned int nr_fields;
			const struct lttng_event_field *fields;	/* Array of fields. */
			unsigned int alignment;
		} struct_nestable;

		union {
			/* legacy provider ABI 1.0 */
			union _lttng_basic_type basic;	/* legacy */
			struct {
				struct lttng_basic_type elem_type;
				unsigned int length;		/* Num. elems. */
			} array;			/* legacy */
			struct {
				struct lttng_basic_type length_type;
				struct lttng_basic_type elem_type;
			} sequence;			/* legacy */
			struct {
				unsigned int nr_fields;
				struct lttng_event_field *fields;	/* Array of fields. */
			} _struct;			/* legacy */
		} legacy;
		char padding[LTTNG_UST_TYPE_PADDING];
	} u;
};

#define LTTNG_UST_ENUM_TYPE_PADDING	24
struct lttng_enum_desc {
	const char *name;
	const struct lttng_enum_entry *entries;
	unsigned int nr_entries;
	char padding[LTTNG_UST_ENUM_TYPE_PADDING];
};

/*
 * Event field description
 *
 * IMPORTANT: this structure is part of the ABI between the probe and
 * UST. Fields need to be only added at the end, never reordered, never
 * removed.
 */

#define LTTNG_UST_EVENT_FIELD_PADDING	28
struct lttng_event_field {
	const char *name;
	struct lttng_type type;
	unsigned int nowrite;	/* do not write into trace */
	union {
		struct {
			unsigned int nofilter:1;	/* do not consider for filter */
		} ext;
		char padding[LTTNG_UST_EVENT_FIELD_PADDING];
	} u;
};

enum lttng_ust_dynamic_type {
	LTTNG_UST_DYNAMIC_TYPE_NONE,
	LTTNG_UST_DYNAMIC_TYPE_S8,
	LTTNG_UST_DYNAMIC_TYPE_S16,
	LTTNG_UST_DYNAMIC_TYPE_S32,
	LTTNG_UST_DYNAMIC_TYPE_S64,
	LTTNG_UST_DYNAMIC_TYPE_U8,
	LTTNG_UST_DYNAMIC_TYPE_U16,
	LTTNG_UST_DYNAMIC_TYPE_U32,
	LTTNG_UST_DYNAMIC_TYPE_U64,
	LTTNG_UST_DYNAMIC_TYPE_FLOAT,
	LTTNG_UST_DYNAMIC_TYPE_DOUBLE,
	LTTNG_UST_DYNAMIC_TYPE_STRING,
	_NR_LTTNG_UST_DYNAMIC_TYPES,
};

struct lttng_ctx_value {
	enum lttng_ust_dynamic_type sel;
	union {
		int64_t s64;
		uint64_t u64;
		const char *str;
		double d;
	} u;
};

struct lttng_perf_counter_field;

#define LTTNG_UST_CTX_FIELD_PADDING	40
struct lttng_ctx_field {
	struct lttng_event_field event_field;
	size_t (*get_size)(struct lttng_ctx_field *field, size_t offset);
	void (*record)(struct lttng_ctx_field *field,
		       struct lttng_ust_lib_ring_buffer_ctx *ctx,
		       struct lttng_channel *chan);
	void (*get_value)(struct lttng_ctx_field *field,
			 struct lttng_ctx_value *value);
	union {
		struct lttng_perf_counter_field *perf_counter;
		char padding[LTTNG_UST_CTX_FIELD_PADDING];
	} u;
	void (*destroy)(struct lttng_ctx_field *field);
	char *field_name;	/* Has ownership, dynamically allocated. */
};

#define LTTNG_UST_CTX_PADDING	20
struct lttng_ctx {
	struct lttng_ctx_field *fields;
	unsigned int nr_fields;
	unsigned int allocated_fields;
	unsigned int largest_align;
	char padding[LTTNG_UST_CTX_PADDING];
};

#define LTTNG_UST_EVENT_DESC_PADDING	40
struct lttng_event_desc {
	const char *name;
	void (*probe_callback)(void);
	const struct lttng_event_ctx *ctx;	/* context */
	const struct lttng_event_field *fields;	/* event payload */
	unsigned int nr_fields;
	const int **loglevel;
	const char *signature;	/* Argument types/names received */
	union {
		struct {
			const char **model_emf_uri;
			void (*event_notifier_callback)(void);
		} ext;
		char padding[LTTNG_UST_EVENT_DESC_PADDING];
	} u;
};

#define LTTNG_UST_PROBE_DESC_PADDING	12
struct lttng_probe_desc {
	const char *provider;
	const struct lttng_event_desc **event_desc;
	unsigned int nr_events;
	struct cds_list_head head;		/* chain registered probes */
	struct cds_list_head lazy_init_head;
	int lazy;				/* lazy registration */
	uint32_t major;
	uint32_t minor;
	char padding[LTTNG_UST_PROBE_DESC_PADDING];
};

/* Data structures used by the tracer. */

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

	struct lttng_ust_event event_param;
	unsigned int enabled:1;
};

struct tp_list_entry {
	struct lttng_ust_tracepoint_iter tp;
	struct cds_list_head head;
};

struct lttng_ust_tracepoint_list {
	struct tp_list_entry *iter;
	struct cds_list_head head;
};

struct tp_field_list_entry {
	struct lttng_ust_field_iter field;
	struct cds_list_head head;
};

struct lttng_ust_field_list {
	struct tp_field_list_entry *iter;
	struct cds_list_head head;
};

struct ust_pending_probe;
struct lttng_event;

/*
 * Bytecode interpreter return value masks.
 */
enum lttng_bytecode_interpreter_ret {
	LTTNG_INTERPRETER_DISCARD = 0,
	LTTNG_INTERPRETER_RECORD_FLAG = (1ULL << 0),
	/* Other bits are kept for future use. */
};

struct lttng_interpreter_output;

/*
 * This structure is used in the probes. More specifically, the `filter` and
 * `node` fields are explicity used in the probes. When modifying this
 * structure we must not change the layout of these two fields as it is
 * considered ABI.
 */
struct lttng_bytecode_runtime {
	/* Associated bytecode */
	struct lttng_ust_bytecode_node *bc;
	union {
		uint64_t (*filter)(void *interpreter_data,
				const char *interpreter_stack_data);
		uint64_t (*capture)(void *interpreter_data,
				const char *interpreter_stack_data,
				struct lttng_interpreter_output *interpreter_output);
	} interpreter_funcs;
	int link_failed;
	struct cds_list_head node;	/* list of bytecode runtime in event */
	/*
	 * Pointer to a URCU-protected pointer owned by an `struct
	 * lttng_session`or `struct lttng_event_notifier_group`.
	 */
	struct lttng_ctx **pctx;
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

/*
 * lttng_event structure is referred to by the tracing fast path. It
 * must be kept small.
 *
 * IMPORTANT: this structure is part of the ABI between the probe and
 * UST. Fields need to be only added at the end, never reordered, never
 * removed.
 */
struct lttng_event {
	/* LTTng-UST 2.0 starts here */
	unsigned int id;
	struct lttng_channel *chan;
	int enabled;
	const struct lttng_event_desc *desc;
	void *_deprecated1;
	struct lttng_ctx *ctx;
	enum lttng_ust_instrumentation instrumentation;
	struct cds_list_head node;		/* Event list in session */
	struct cds_list_head _deprecated2;
	void *_deprecated3;
	unsigned int _deprecated4:1;

	/* LTTng-UST 2.1 starts here */
	/* list of struct lttng_bytecode_runtime, sorted by seqnum */
	struct cds_list_head filter_bytecode_runtime_head;
	int has_enablers_without_bytecode;
	/* Backward references: list of lttng_enabler_ref (ref to enablers) */
	struct cds_list_head enablers_ref_head;
	struct cds_hlist_node hlist;	/* session ht of events */
	int registered;			/* has reg'd tracepoint probe */
};

struct lttng_event_notifier {
	uint64_t user_token;
	uint64_t error_counter_index;
	int enabled;
	int registered;			/* has reg'd tracepoint probe */
	size_t num_captures;		/* Needed to allocate the msgpack array. */
	struct cds_list_head filter_bytecode_runtime_head;
	struct cds_list_head capture_bytecode_runtime_head;
	int has_enablers_without_bytecode;
	struct cds_list_head enablers_ref_head;
	const struct lttng_event_desc *desc;
	struct cds_hlist_node hlist;	/* hashtable of event_notifiers */
	struct cds_list_head node;	/* event_notifier list in session */
	struct lttng_event_notifier_group *group; /* weak ref */
};

struct lttng_enum {
	const struct lttng_enum_desc *desc;
	struct lttng_session *session;
	struct cds_list_head node;	/* Enum list in session */
	struct cds_hlist_node hlist;	/* Session ht of enums */
	uint64_t id;			/* Enumeration ID in sessiond */
};

struct channel;
struct lttng_ust_shm_handle;

/*
 * IMPORTANT: this structure is part of the ABI between the probe and
 * UST. Fields need to be only added at the end, never reordered, never
 * removed.
 */
struct lttng_channel_ops {
	struct lttng_channel *(*channel_create)(const char *name,
			void *buf_addr,
			size_t subbuf_size, size_t num_subbuf,
			unsigned int switch_timer_interval,
			unsigned int read_timer_interval,
			unsigned char *uuid,
			uint32_t chan_id,
			const int *stream_fds, int nr_stream_fds,
			int64_t blocking_timeout);
	void (*channel_destroy)(struct lttng_channel *chan);
	union {
		void *_deprecated1;
		/*
		 * has_strcpy is needed by probe providers version 1.0 to
		 * dynamically detect whether the LTTng-UST tracepoint
		 * provider ABI implements event_strcpy. Starting from
		 * probe providers version 2.0, the check is not needed,
		 * but backward compatibility is provided for older versions.
		 */
		unsigned long has_strcpy:1;		/* ABI has strcpy */
	} u;
	void *_deprecated2;
	int (*event_reserve)(struct lttng_ust_lib_ring_buffer_ctx *ctx,
			     uint32_t event_id);
	void (*event_commit)(struct lttng_ust_lib_ring_buffer_ctx *ctx);
	void (*event_write)(struct lttng_ust_lib_ring_buffer_ctx *ctx,
			const void *src, size_t len);
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
	void (*event_strcpy)(struct lttng_ust_lib_ring_buffer_ctx *ctx,
			const char *src, size_t len);
};

/*
 * IMPORTANT: this structure is part of the ABI between the probe and
 * UST. Fields need to be only added at the end, never reordered, never
 * removed.
 */
struct lttng_channel {
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
	struct lttng_session *session;
	int objd;			/* Object associated to channel */
	unsigned int _deprecated1;
	unsigned int _deprecated2;
	struct cds_list_head node;	/* Channel list in session */
	const struct lttng_channel_ops *ops;
	int header_type;		/* 0: unset, 1: compact, 2: large */
	struct lttng_ust_shm_handle *handle;	/* shared-memory handle */
	unsigned int _deprecated3:1;

	/* Channel ID */
	unsigned int id;
	enum lttng_ust_chan_type type;
	unsigned char uuid[LTTNG_UST_UUID_LEN]; /* Trace session unique ID */
	int tstate:1;			/* Transient enable state */
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

#define LTTNG_UST_STACK_CTX_PADDING	32
struct lttng_stack_ctx {
	struct lttng_event *event;
	struct lttng_ctx *chan_ctx;	/* RCU dereferenced. */
	struct lttng_ctx *event_ctx;	/* RCU dereferenced. */
	char padding[LTTNG_UST_STACK_CTX_PADDING];
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

/*
 * IMPORTANT: this structure is part of the ABI between the probe and
 * UST. Fields need to be only added at the end, never reordered, never
 * removed.
 */
struct lttng_session {
	int active;				/* Is trace session active ? */
	int been_active;			/* Been active ? */
	int objd;				/* Object associated */
	void *_deprecated1;
	struct cds_list_head chan_head;		/* Channel list head */
	struct cds_list_head events_head;	/* list of events */
	struct cds_list_head _deprecated2;
	struct cds_list_head node;		/* Session list */
	int _deprecated3;
	unsigned int _deprecated4:1;

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

struct lttng_session *lttng_session_create(void);
int lttng_session_enable(struct lttng_session *session);
int lttng_session_disable(struct lttng_session *session);
int lttng_session_statedump(struct lttng_session *session);
void lttng_session_destroy(struct lttng_session *session);

void lttng_event_notifier_notification_send(
		struct lttng_event_notifier *event_notifier,
		const char *stack_data);

struct lttng_channel *lttng_channel_create(struct lttng_session *session,
				       const char *transport_name,
				       void *buf_addr,
				       size_t subbuf_size, size_t num_subbuf,
				       unsigned int switch_timer_interval,
				       unsigned int read_timer_interval,
				       int **shm_fd, int **wait_fd,
				       uint64_t **memory_map_size,
				       struct lttng_channel *chan_priv_init);

int lttng_channel_enable(struct lttng_channel *channel);
int lttng_channel_disable(struct lttng_channel *channel);

int lttng_attach_context(struct lttng_ust_context *context_param,
		union ust_args *uargs,
		struct lttng_ctx **ctx, struct lttng_session *session);
void lttng_transport_register(struct lttng_transport *transport);
void lttng_transport_unregister(struct lttng_transport *transport);

void lttng_counter_transport_register(struct lttng_counter_transport *transport);
void lttng_counter_transport_unregister(struct lttng_counter_transport *transport);

struct lttng_counter *lttng_ust_counter_create(
		const char *counter_transport_name,
		size_t number_dimensions, const struct lttng_counter_dimension *dimensions);

void synchronize_trace(void);

int lttng_probe_register(struct lttng_probe_desc *desc);
void lttng_probe_unregister(struct lttng_probe_desc *desc);
void lttng_probe_provider_unregister_events(struct lttng_probe_desc *desc);
int lttng_fix_pending_events(void);
int lttng_probes_init(void);
void lttng_probes_exit(void);
int lttng_find_context(struct lttng_ctx *ctx, const char *name);
int lttng_get_context_index(struct lttng_ctx *ctx, const char *name);
struct lttng_ctx_field *lttng_append_context(struct lttng_ctx **ctx_p);
void lttng_context_update(struct lttng_ctx *ctx);
void lttng_remove_context_field(struct lttng_ctx **ctx_p,
				struct lttng_ctx_field *field);
void lttng_destroy_context(struct lttng_ctx *ctx);
int lttng_add_vtid_to_ctx(struct lttng_ctx **ctx);
int lttng_add_vpid_to_ctx(struct lttng_ctx **ctx);
int lttng_add_pthread_id_to_ctx(struct lttng_ctx **ctx);
int lttng_add_procname_to_ctx(struct lttng_ctx **ctx);
int lttng_add_ip_to_ctx(struct lttng_ctx **ctx);
int lttng_add_cpu_id_to_ctx(struct lttng_ctx **ctx);
int lttng_add_dyntest_to_ctx(struct lttng_ctx **ctx);
int lttng_add_cgroup_ns_to_ctx(struct lttng_ctx **ctx);
int lttng_add_ipc_ns_to_ctx(struct lttng_ctx **ctx);
int lttng_add_mnt_ns_to_ctx(struct lttng_ctx **ctx);
int lttng_add_net_ns_to_ctx(struct lttng_ctx **ctx);
int lttng_add_pid_ns_to_ctx(struct lttng_ctx **ctx);
int lttng_add_time_ns_to_ctx(struct lttng_ctx **ctx);
int lttng_add_user_ns_to_ctx(struct lttng_ctx **ctx);
int lttng_add_uts_ns_to_ctx(struct lttng_ctx **ctx);
int lttng_add_vuid_to_ctx(struct lttng_ctx **ctx);
int lttng_add_veuid_to_ctx(struct lttng_ctx **ctx);
int lttng_add_vsuid_to_ctx(struct lttng_ctx **ctx);
int lttng_add_vgid_to_ctx(struct lttng_ctx **ctx);
int lttng_add_vegid_to_ctx(struct lttng_ctx **ctx);
int lttng_add_vsgid_to_ctx(struct lttng_ctx **ctx);
void lttng_context_vtid_reset(void);
void lttng_context_vpid_reset(void);
void lttng_context_procname_reset(void);
void lttng_context_cgroup_ns_reset(void);
void lttng_context_ipc_ns_reset(void);
void lttng_context_mnt_ns_reset(void);
void lttng_context_net_ns_reset(void);
void lttng_context_pid_ns_reset(void);
void lttng_context_time_ns_reset(void);
void lttng_context_user_ns_reset(void);
void lttng_context_uts_ns_reset(void);
void lttng_context_vuid_reset(void);
void lttng_context_veuid_reset(void);
void lttng_context_vsuid_reset(void);
void lttng_context_vgid_reset(void);
void lttng_context_vegid_reset(void);
void lttng_context_vsgid_reset(void);

#ifdef LTTNG_UST_HAVE_PERF_EVENT
int lttng_add_perf_counter_to_ctx(uint32_t type,
				  uint64_t config,
				  const char *name,
				  struct lttng_ctx **ctx);
int lttng_perf_counter_init(void);
void lttng_perf_counter_exit(void);
#else /* #ifdef LTTNG_UST_HAVE_PERF_EVENT */
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
#endif /* #else #ifdef LTTNG_UST_HAVE_PERF_EVENT */

extern const struct lttng_ust_client_lib_ring_buffer_client_cb *lttng_client_callbacks_metadata;
extern const struct lttng_ust_client_lib_ring_buffer_client_cb *lttng_client_callbacks_discard;
extern const struct lttng_ust_client_lib_ring_buffer_client_cb *lttng_client_callbacks_overwrite;

struct lttng_transport *lttng_transport_find(const char *name);
struct lttng_counter_transport *lttng_counter_transport_find(const char *name);

int lttng_probes_get_event_list(struct lttng_ust_tracepoint_list *list);
void lttng_probes_prune_event_list(struct lttng_ust_tracepoint_list *list);
struct lttng_ust_tracepoint_iter *
	lttng_ust_tracepoint_list_get_iter_next(struct lttng_ust_tracepoint_list *list);
int lttng_probes_get_field_list(struct lttng_ust_field_list *list);
void lttng_probes_prune_field_list(struct lttng_ust_field_list *list);
struct lttng_ust_field_iter *
	lttng_ust_field_list_get_iter_next(struct lttng_ust_field_list *list);

void lttng_free_event_filter_runtime(struct lttng_event *event);

struct cds_list_head *lttng_get_probe_list_head(void);
int lttng_session_active(void);

typedef int (*t_statedump_func_ptr)(struct lttng_session *session);
void lttng_handle_pending_statedump(void *owner);
struct cds_list_head *_lttng_get_sessions(void);

struct lttng_enum *lttng_ust_enum_get_from_desc(struct lttng_session *session,
		const struct lttng_enum_desc *enum_desc);

void lttng_ust_dl_update(void *ip);
void lttng_ust_fixup_fd_tracker_tls(void);

/* For backward compatibility. Leave those exported symbols in place. */
extern struct lttng_ctx *lttng_static_ctx;
struct lttng_ust_filter_bytecode_node;
struct lttng_ust_excluder_node;
void lttng_context_init(void);
void lttng_context_exit(void);
void lttng_filter_event_link_bytecode(struct lttng_event *event);
struct lttng_enabler *lttng_enabler_create(
		enum lttng_enabler_format_type format_type,
		struct lttng_ust_event *event_param,
		struct lttng_channel *chan);
int lttng_enabler_enable(struct lttng_enabler *enabler);
int lttng_enabler_disable(struct lttng_enabler *enabler);
int lttng_enabler_attach_bytecode(struct lttng_enabler *enabler,
		struct lttng_ust_filter_bytecode_node *bytecode);
int lttng_enabler_attach_context(struct lttng_enabler *enabler,
		struct lttng_ust_context *ctx);
int lttng_enabler_attach_exclusion(struct lttng_enabler *enabler,
		struct lttng_ust_excluder_node *excluder);
void lttng_enabler_event_link_bytecode(struct lttng_event *event,
		struct lttng_enabler *enabler);
void lttng_filter_sync_state(struct lttng_bytecode_runtime *runtime);
int lttng_session_context_init(struct lttng_ctx **ctx);


#ifdef __cplusplus
}
#endif

#endif /* _LTTNG_UST_EVENTS_H */
