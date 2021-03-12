/*
 * SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2010-2012 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 *
 * Holds LTTng per-session event registry.
 */

#ifndef _LTTNG_UST_EVENTS_H
#define _LTTNG_UST_EVENTS_H

#include <urcu/list.h>
#include <urcu/hlist.h>
#include <stddef.h>
#include <stdint.h>
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
struct lttng_event_field;
struct lttng_event_notifier;
struct lttng_event_notifier_group;

/*
 * Data structures used by tracepoint event declarations, and by the
 * tracer. Those structures have padding for future extension.
 */

/* Type description */

/* Update the astract_types name table in lttng-types.c along with this enum */
enum lttng_abstract_types {
	atype_integer,
	atype_string,
	atype_float,
	atype_dynamic,
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

/*
 * Bytecode interpreter return value masks.
 */
enum lttng_bytecode_interpreter_ret {
	LTTNG_INTERPRETER_DISCARD = 0,
	LTTNG_INTERPRETER_RECORD_FLAG = (1ULL << 0),
	/* Other bits are kept for future use. */
};

struct lttng_interpreter_output;
struct lttng_ust_bytecode_runtime_private;

/*
 * This structure is used in the probes. More specifically, the
 * `interpreter_funcs` and `node` fields are explicity used in the
 * probes. When modifying this structure we must not change the layout
 * of these two fields as it is considered ABI.
 */
struct lttng_bytecode_runtime {
	struct lttng_ust_bytecode_runtime_private *priv;

	/* Associated bytecode */
	union {
		uint64_t (*filter)(void *interpreter_data,
				const char *interpreter_stack_data);
		uint64_t (*capture)(void *interpreter_data,
				const char *interpreter_stack_data,
				struct lttng_interpreter_output *interpreter_output);
	} interpreter_funcs;
	struct cds_list_head node;	/* list of bytecode runtime in event */
};

/*
 * lttng_event structure is referred to by the tracing fast path. It
 * must be kept small.
 *
 * IMPORTANT: this structure is part of the ABI between the probe and
 * UST. Fields need to be only added at the end, never reordered, never
 * removed.
 */

struct lttng_ust_event_common_private;

struct lttng_ust_event_common {
	uint32_t struct_size;				/* Size of this structure. */
	struct lttng_ust_event_common_private *priv;	/* Private event interface */

	int enabled;
	int has_enablers_without_bytecode;
	/* list of struct lttng_bytecode_runtime, sorted by seqnum */
	struct cds_list_head filter_bytecode_runtime_head;
};

struct lttng_ust_event_recorder_private;

struct lttng_ust_event_recorder {
	uint32_t struct_size;				/* Size of this structure. */
	struct lttng_ust_event_common *parent;
	struct lttng_ust_event_recorder_private *priv;	/* Private event record interface */

	unsigned int id;
	struct lttng_channel *chan;
	struct lttng_ctx *ctx;
};

struct lttng_ust_event_notifier_private;

struct lttng_event_notifier {
	uint32_t struct_size;				/* Size of this structure. */
	struct lttng_ust_event_common *parent;
	struct lttng_ust_event_notifier_private *priv;	/* Private event notifier interface */

	void (*notification_send)(struct lttng_event_notifier *event_notifier,
		const char *stack_data);
	struct cds_list_head capture_bytecode_runtime_head;
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
	struct cds_list_head node;	/* Channel list in session */
	const struct lttng_channel_ops *ops;
	int header_type;		/* 0: unset, 1: compact, 2: large */
	struct lttng_ust_shm_handle *handle;	/* shared-memory handle */

	/* Channel ID */
	unsigned int id;
	enum lttng_ust_chan_type type;
	unsigned char uuid[LTTNG_UST_UUID_LEN]; /* Trace session unique ID */
	int tstate:1;			/* Transient enable state */
};

struct lttng_counter_dimension;

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
	struct lttng_ust_event_recorder *event_recorder;
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

struct lttng_ust_session_private;

/*
 * IMPORTANT: this structure is part of the ABI between the probe and
 * UST. Fields need to be only added at the end, never reordered, never
 * removed.
 */
struct lttng_session {
	uint32_t struct_size;			/* Size of this structure */
	struct lttng_ust_session_private *priv;	/* Private session interface */

	int active;				/* Is trace session active ? */
};

int lttng_probe_register(struct lttng_probe_desc *desc);
void lttng_probe_unregister(struct lttng_probe_desc *desc);

/*
 * Can be used by applications that change their procname to clear the ust cached value.
 */
void lttng_context_procname_reset(void);

struct lttng_transport *lttng_transport_find(const char *name);

int lttng_session_active(void);

void lttng_ust_dl_update(void *ip);

#ifdef __cplusplus
}
#endif

#endif /* _LTTNG_UST_EVENTS_H */
