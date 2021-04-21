/*
 * SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2010-2012 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 *
 * Holds LTTng per-session event registry.
 */

#ifndef _LTTNG_UST_EVENTS_H
#define _LTTNG_UST_EVENTS_H

#include <stddef.h>
#include <stdint.h>
#include <lttng/ust-abi.h>
#include <lttng/ust-tracer.h>
#include <lttng/ust-endian.h>
#include <float.h>
#include <errno.h>
#include <urcu/ref.h>
#include <pthread.h>
#include <limits.h>

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

struct lttng_ust_channel_buffer;
struct lttng_ust_session;
struct lttng_ust_ring_buffer_ctx;
struct lttng_ust_event_field;
struct lttng_ust_registered_probe;

/*
 * Data structures used by tracepoint event declarations, and by the
 * tracer.
 */

/* Type description */

enum lttng_ust_type {
	lttng_ust_type_integer,
	lttng_ust_type_string,
	lttng_ust_type_float,
	lttng_ust_type_dynamic,
	lttng_ust_type_enum,
	lttng_ust_type_array,
	lttng_ust_type_sequence,
	lttng_ust_type_struct,
	NR_LTTNG_UST_TYPE,
};

enum lttng_ust_string_encoding {
	lttng_ust_string_encoding_none = 0,
	lttng_ust_string_encoding_UTF8 = 1,
	lttng_ust_string_encoding_ASCII = 2,
	NR_LTTNG_UST_STRING_ENCODING,
};

struct lttng_ust_enum_value {
	unsigned long long value;
	unsigned int signedness:1;
};

enum lttng_ust_enum_entry_option {
	LTTNG_UST_ENUM_ENTRY_OPTION_IS_AUTO = 1U << 0,
};

/*
 * Enumeration entry description
 *
 * IMPORTANT: this structure is part of the ABI between the probe and
 * UST. Fields need to be only added at the end, never reordered, never
 * removed.
 *
 * The field @struct_size should be used to determine the size of the
 * structure. It should be queried before using additional fields added
 * at the end of the structure.
 */

struct lttng_ust_enum_entry {
	uint32_t struct_size;

	struct lttng_ust_enum_value start, end; /* start and end are inclusive */
	const char *string;
	unsigned int options;

	/* End of base ABI. Fields below should be used after checking struct_size. */
};

/*
 * struct lttng_ust_type_common is fixed-size. Its children inherits
 * from it by embedding struct lttng_ust_type_common as its first field.
 */
struct lttng_ust_type_common {
	enum lttng_ust_type type;
};

struct lttng_ust_type_integer {
	struct lttng_ust_type_common parent;
	uint32_t struct_size;
	unsigned int size;		/* in bits */
	unsigned short alignment;	/* in bits */
	unsigned int signedness:1;
	unsigned int reverse_byte_order:1;
	unsigned int base;		/* 2, 8, 10, 16, for pretty print */
};

#define lttng_ust_type_integer_define(_type, _byte_order, _base)	\
	((struct lttng_ust_type_common *) LTTNG_UST_COMPOUND_LITERAL(struct lttng_ust_type_integer, { \
		.parent = {						\
			.type = lttng_ust_type_integer,			\
		},							\
		.struct_size = sizeof(struct lttng_ust_type_integer),	\
		.size = sizeof(_type) * CHAR_BIT,			\
		.alignment = lttng_ust_rb_alignof(_type) * CHAR_BIT,	\
		.signedness = lttng_ust_is_signed_type(_type),		\
		.reverse_byte_order = _byte_order != LTTNG_UST_BYTE_ORDER,	\
		.base = _base,						\
	}))

struct lttng_ust_type_float {
	struct lttng_ust_type_common parent;
	uint32_t struct_size;
	unsigned int exp_dig;		/* exponent digits, in bits */
	unsigned int mant_dig;		/* mantissa digits, in bits */
	unsigned short alignment;	/* in bits */
	unsigned int reverse_byte_order:1;
};

/*
 * Only float and double are supported. long double is not supported at
 * the moment.
 */
#define lttng_ust_float_mant_dig(_type)					\
	(sizeof(_type) == sizeof(float) ? FLT_MANT_DIG			\
		: (sizeof(_type) == sizeof(double) ? DBL_MANT_DIG	\
		: 0))

#define lttng_ust_type_float_define(_type)				\
	((struct lttng_ust_type_common *) LTTNG_UST_COMPOUND_LITERAL(struct lttng_ust_type_float, { \
		.parent = {						\
			.type = lttng_ust_type_float,			\
		},							\
		.struct_size = sizeof(struct lttng_ust_type_float),	\
		.exp_dig = sizeof(_type) * CHAR_BIT			\
			- lttng_ust_float_mant_dig(_type),		\
		.mant_dig = lttng_ust_float_mant_dig(_type),		\
		.alignment = lttng_ust_rb_alignof(_type) * CHAR_BIT,	\
		.reverse_byte_order = LTTNG_UST_BYTE_ORDER != LTTNG_UST_FLOAT_WORD_ORDER,	\
	}))


struct lttng_ust_type_string {
	struct lttng_ust_type_common parent;
	uint32_t struct_size;
	enum lttng_ust_string_encoding encoding;
};

struct lttng_ust_type_enum {
	struct lttng_ust_type_common parent;
	uint32_t struct_size;
	const struct lttng_ust_enum_desc *desc;	/* Enumeration mapping */
	const struct lttng_ust_type_common *container_type;
};

/*
 * The alignment field in structure, array, and sequence types is a
 * minimum alignment requirement. The actual alignment of a type may be
 * larger than this explicit alignment value if its nested types have a
 * larger alignment.
 */

struct lttng_ust_type_array {
	struct lttng_ust_type_common parent;
	uint32_t struct_size;
	const struct lttng_ust_type_common *elem_type;
	unsigned int length;		/* Num. elems. */
	unsigned int alignment;		/* Minimum alignment for this type. */
	enum lttng_ust_string_encoding encoding;
};

struct lttng_ust_type_sequence {
	struct lttng_ust_type_common parent;
	uint32_t struct_size;
	const char *length_name;	/* Length field name. */
	const struct lttng_ust_type_common *elem_type;
	unsigned int alignment;		/* Minimum alignment before elements. */
	enum lttng_ust_string_encoding encoding;
};

struct lttng_ust_type_struct {
	struct lttng_ust_type_common parent;
	uint32_t struct_size;
	unsigned int nr_fields;
	const struct lttng_ust_event_field * const *fields;	/* Array of pointers to fields. */
	unsigned int alignment;					/* Minimum alignment for this type. */
};

/*
 * Enumeration description
 *
 * IMPORTANT: this structure is part of the ABI between the probe and
 * UST. Fields need to be only added at the end, never reordered, never
 * removed.
 *
 * The field @struct_size should be used to determine the size of the
 * structure. It should be queried before using additional fields added
 * at the end of the structure.
 */

struct lttng_ust_enum_desc {
	uint32_t struct_size;

	const char *name;
	const struct lttng_ust_enum_entry * const *entries;
	unsigned int nr_entries;

	/* End of base ABI. Fields below should be used after checking struct_size. */
};

/*
 * Event field description
 *
 * IMPORTANT: this structure is part of the ABI between the probe and
 * UST. Fields need to be only added at the end, never reordered, never
 * removed.
 *
 * The field @struct_size should be used to determine the size of the
 * structure. It should be queried before using additional fields added
 * at the end of the structure.
 */

struct lttng_ust_event_field {
	uint32_t struct_size;

	const char *name;
	const struct lttng_ust_type_common *type;
	unsigned int nowrite:1,		/* do not write into trace */
		nofilter:1;		/* do not consider for filter */

	/* End of base ABI. Fields below should be used after checking struct_size. */
};


/*
 * IMPORTANT: this structure is part of the ABI between the probe and
 * UST. Fields need to be only added at the end, never reordered, never
 * removed.
 *
 * The field @struct_size should be used to determine the size of the
 * structure. It should be queried before using additional fields added
 * at the end of the structure.
 */
struct lttng_ust_event_desc {
	uint32_t struct_size;				/* Size of this structure. */

	const char *event_name;
	const struct lttng_ust_probe_desc *probe_desc;
	void (*probe_callback)(void);
	const struct lttng_ust_event_field * const *fields;	/* event payload */
	unsigned int nr_fields;
	const int **loglevel;
	const char *signature;				/* Argument types/names received */
	const char **model_emf_uri;

	/* End of base ABI. Fields below should be used after checking struct_size. */
};

/*
 * IMPORTANT: this structure is part of the ABI between the probe and
 * UST. Fields need to be only added at the end, never reordered, never
 * removed.
 *
 * The field @struct_size should be used to determine the size of the
 * structure. It should be queried before using additional fields added
 * at the end of the structure.
 */
struct lttng_ust_probe_desc {
	uint32_t struct_size;			/* Size of this structure. */

	const char *provider_name;
	const struct lttng_ust_event_desc * const *event_desc;
	unsigned int nr_events;
	uint32_t major;
	uint32_t minor;

	/* End of base ABI. Fields below should be used after checking struct_size. */
};

/* Data structures used by the tracer. */

/*
 * lttng_event structure is referred to by the tracing fast path. It
 * must be kept small.
 *
 * IMPORTANT: this structure is part of the ABI between the probe and
 * UST. Fields need to be only added at the end, never reordered, never
 * removed.
 */

struct lttng_ust_event_common_private;

enum lttng_ust_event_type {
	LTTNG_UST_EVENT_TYPE_RECORDER = 0,
	LTTNG_UST_EVENT_TYPE_NOTIFIER = 1,
};

/*
 * Result of the run_filter() callback.
 */
enum lttng_ust_event_filter_result {
	LTTNG_UST_EVENT_FILTER_ACCEPT = 0,
	LTTNG_UST_EVENT_FILTER_REJECT = 1,
};

/*
 * IMPORTANT: this structure is part of the ABI between the probe and
 * UST. Fields need to be only added at the end, never reordered, never
 * removed.
 *
 * struct lttng_ust_event_common is the common ancestor of the various
 * public event actions. Inheritance is done by composition: The parent
 * has a pointer to its child, and the child has a pointer to its
 * parent. Inheritance of those public structures is done by composition
 * to ensure both parent and child structures can be extended.
 *
 * The field @struct_size should be used to determine the size of the
 * structure. It should be queried before using additional fields added
 * at the end of the structure.
 */
struct lttng_ust_event_common {
	uint32_t struct_size;				/* Size of this structure. */

	struct lttng_ust_event_common_private *priv;	/* Private event interface */

	enum lttng_ust_event_type type;
	void *child;					/* Pointer to child, for inheritance by aggregation. */

	int enabled;
	int eval_filter;				/* Need to evaluate filters */
	int (*run_filter)(const struct lttng_ust_event_common *event,
		const char *stack_data,
		void *filter_ctx);

	/* End of base ABI. Fields below should be used after checking struct_size. */
};

struct lttng_ust_event_recorder_private;

/*
 * IMPORTANT: this structure is part of the ABI between the probe and
 * UST. Fields need to be only added at the end, never reordered, never
 * removed.
 *
 * struct lttng_ust_event_recorder is the action for recording events
 * into a ring buffer. It inherits from struct lttng_ust_event_common
 * by composition to ensure both parent and child structure are
 * extensible.
 *
 * The field @struct_size should be used to determine the size of the
 * structure. It should be queried before using additional fields added
 * at the end of the structure.
 */
struct lttng_ust_event_recorder {
	uint32_t struct_size;				/* Size of this structure. */

	struct lttng_ust_event_common *parent;		/* Inheritance by aggregation. */
	struct lttng_ust_event_recorder_private *priv;	/* Private event record interface */

	struct lttng_ust_channel_buffer *chan;

	/* End of base ABI. Fields below should be used after checking struct_size. */
};

/*
 * IMPORTANT: this structure is part of the ABI between the probe and
 * UST. Fields need to be only added at the end, never reordered, never
 * removed.
 *
 * The field @struct_size should be used to determine the size of the
 * structure. It should be queried before using additional fields added
 * at the end of the structure.
 */
struct lttng_ust_notification_ctx {
	uint32_t struct_size;		/* Size of this structure. */
	int eval_capture;		/* Capture evaluation available. */

	/* End of base ABI. Fields below should be used after checking struct_size. */
};

struct lttng_ust_event_notifier_private;

/*
 * IMPORTANT: this structure is part of the ABI between the probe and
 * UST. Fields need to be only added at the end, never reordered, never
 * removed.
 *
 * struct lttng_ust_event_notifier is the action for sending
 * notifications. It inherits from struct lttng_ust_event_common
 * by composition to ensure both parent and child structure are
 * extensible.
 *
 * The field @struct_size should be used to determine the size of the
 * structure. It should be queried before using additional fields added
 * at the end of the structure.
 */
struct lttng_ust_event_notifier {
	uint32_t struct_size;				/* Size of this structure. */

	struct lttng_ust_event_common *parent;		/* Inheritance by aggregation. */
	struct lttng_ust_event_notifier_private *priv;	/* Private event notifier interface */

	int eval_capture;				/* Need to evaluate capture */
	void (*notification_send)(const struct lttng_ust_event_notifier *event_notifier,
		const char *stack_data,
		struct lttng_ust_notification_ctx *notif_ctx);

	/* End of base ABI. Fields below should be used after checking struct_size. */
};

struct lttng_ust_ring_buffer_channel;
struct lttng_ust_channel_buffer_ops_private;

/*
 * IMPORTANT: this structure is part of the ABI between the probe and
 * UST. Fields need to be only added at the end, never reordered, never
 * removed.
 *
 * The field @struct_size should be used to determine the size of the
 * structure. It should be queried before using additional fields added
 * at the end of the structure.
 */
struct lttng_ust_channel_buffer_ops {
	uint32_t struct_size;

	struct lttng_ust_channel_buffer_ops_private *priv;	/* Private channel buffer ops interface */

	int (*event_reserve)(struct lttng_ust_ring_buffer_ctx *ctx);
	void (*event_commit)(struct lttng_ust_ring_buffer_ctx *ctx);
	void (*event_write)(struct lttng_ust_ring_buffer_ctx *ctx,
			const void *src, size_t len, size_t alignment);
	void (*event_strcpy)(struct lttng_ust_ring_buffer_ctx *ctx,
			const char *src, size_t len);
	void (*event_pstrcpy_pad)(struct lttng_ust_ring_buffer_ctx *ctx,
			const char *src, size_t len);

	/* End of base ABI. Fields below should be used after checking struct_size. */
};

enum lttng_ust_channel_type {
	LTTNG_UST_CHANNEL_TYPE_BUFFER = 0,
};

struct lttng_ust_channel_common_private;

/*
 * IMPORTANT: this structure is part of the ABI between the probe and
 * UST. Fields need to be only added at the end, never reordered, never
 * removed.
 *
 * The field @struct_size should be used to determine the size of the
 * structure. It should be queried before using additional fields added
 * at the end of the structure.
 */
struct lttng_ust_channel_common {
	uint32_t struct_size;				/* Size of this structure. */

	struct lttng_ust_channel_common_private *priv;	/* Private channel interface */

	enum lttng_ust_channel_type type;
	void *child;					/* Pointer to child, for inheritance by aggregation. */

	int enabled;
	struct lttng_ust_session *session;

	/* End of base ABI. Fields below should be used after checking struct_size. */
};

struct lttng_ust_channel_buffer_private;

/*
 * IMPORTANT: this structure is part of the ABI between the probe and
 * UST. Fields need to be only added at the end, never reordered, never
 * removed.
 *
 * The field @struct_size should be used to determine the size of the
 * structure. It should be queried before using additional fields added
 * at the end of the structure.
 */
struct lttng_ust_channel_buffer {
	uint32_t struct_size;				/* Size of this structure. */

	struct lttng_ust_channel_common *parent;	/* Inheritance by aggregation. */
	struct lttng_ust_channel_buffer_private *priv;	/* Private channel buffer interface */

	struct lttng_ust_channel_buffer_ops *ops;

	/* End of base ABI. Fields below should be used after checking struct_size. */
};

/*
 * IMPORTANT: this structure is part of the ABI between the probe and
 * UST. Fields need to be only added at the end, never reordered, never
 * removed.
 *
 * The field @struct_size should be used to determine the size of the
 * structure. It should be queried before using additional fields added
 * at the end of the structure.
 */
struct lttng_ust_stack_ctx {
	uint32_t struct_size;			/* Size of this structure */

	struct lttng_ust_event_recorder *event_recorder;

	/* End of base ABI. Fields below should be used after checking struct_size. */
};

struct lttng_ust_session_private;

/*
 * IMPORTANT: this structure is part of the ABI between the probe and
 * UST. Fields need to be only added at the end, never reordered, never
 * removed.
 *
 * The field @struct_size should be used to determine the size of the
 * structure. It should be queried before using additional fields added
 * at the end of the structure.
 */
struct lttng_ust_session {
	uint32_t struct_size;			/* Size of this structure */

	struct lttng_ust_session_private *priv;	/* Private session interface */

	int active;				/* Is trace session active ? */

	/* End of base ABI. Fields below should be used after checking struct_size. */
};

/*
 * On successful registration of a probe, a pointer to an opaque
 * structure is returned. This pointer should be passed to
 * lttng_ust_probe_unregister for unregistration.
 * lttng_ust_probe_register returns NULL on error.
 */
struct lttng_ust_registered_probe *lttng_ust_probe_register(const struct lttng_ust_probe_desc *desc);

void lttng_ust_probe_unregister(struct lttng_ust_registered_probe *reg_probe);

/*
 * Applications that change their procname and need the new value to be
 * reflected in the procname event context have to call this function to clear
 * the internally cached value. This should not be called from a signal
 * handler.
 */
void lttng_ust_context_procname_reset(void);

#ifdef __cplusplus
}
#endif

#endif /* _LTTNG_UST_EVENTS_H */
