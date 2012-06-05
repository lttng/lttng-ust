/*
 * Copyright (c) 2011-2012 - Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
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
 */

#include <stdio.h>
#include <urcu/compiler.h>
#include <lttng/ust-events.h>
#include <lttng/ringbuffer-config.h>
#include <string.h>

/*
 * Macro declarations used for all stages.
 */

#undef ctf_integer
#define ctf_integer(_type, _item, _src)				\
	ctf_integer_ext(_type, _item, _src, BYTE_ORDER, 10)

#undef ctf_integer_hex
#define ctf_integer_hex(_type, _item, _src)			\
	ctf_integer_ext(_type, _item, _src, BYTE_ORDER, 16)

#undef ctf_integer_network
#define ctf_integer_network(_type, _item, _src)			\
	ctf_integer_ext(_type, _item, _src, BIG_ENDIAN, 10)

#undef ctf_integer_network_hex
#define ctf_integer_network_hex(_type, _item, _src)		\
	ctf_integer_ext(_type, _item, _src, BIG_ENDIAN, 16)

/* ctf_float is redefined at each step */

#undef ctf_array
#define ctf_array(_type, _item, _src, _length)			\
	ctf_array_encoded(_type, _item, _src, _length, none)

#undef ctf_array_text
#define ctf_array_text(_type, _item, _src, _length)		\
	ctf_array_encoded(_type, _item, _src, _length, UTF8)

#undef ctf_sequence
#define ctf_sequence(_type, _item, _src, _length_type, _src_length)	\
	ctf_sequence_encoded(_type, _item, _src,			\
			_length_type, _src_length, none)

#undef ctf_sequence_text
#define ctf_sequence_text(_type, _item, _src, _length_type, _src_length) \
	ctf_sequence_encoded(_type, _item, _src,			 \
			_length_type, _src_length, UTF8)

/* ctf_string is redefined at each step */

/*
 * TRACEPOINT_EVENT_CLASS declares a class of tracepoints receiving the
 * same arguments and having the same field layout.
 *
 * TRACEPOINT_EVENT_INSTANCE declares an instance of a tracepoint, with
 * its own provider and name. It refers to a class (template).
 *
 * TRACEPOINT_EVENT declared both a class and an instance and does a
 * direct mapping from the instance to the class.
 */

#undef TRACEPOINT_EVENT
#define TRACEPOINT_EVENT(_provider, _name, _args, _fields)	\
	TRACEPOINT_EVENT_CLASS(_provider, _name,		\
			 _TP_PARAMS(_args),			\
			 _TP_PARAMS(_fields))			\
	TRACEPOINT_EVENT_INSTANCE(_provider, _name, _name,	\
			 _TP_PARAMS(_args))

/* Helpers */
#define _TP_ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]))

#define _tp_max_t(type, x, y)				\
	({						\
		type __max1 = (x);              	\
		type __max2 = (y);              	\
		__max1 > __max2 ? __max1: __max2;	\
	})

/*
 * Stage 0 of tracepoint event generation.
 *
 * Check that each TRACEPOINT_EVENT provider argument match the
 * TRACEPOINT_PROVIDER by creating dummy callbacks.
 */

/* Reset all macros within TRACEPOINT_EVENT */
#include <lttng/ust-tracepoint-event-reset.h>

static inline
void _TP_COMBINE_TOKENS(__tracepoint_provider_mismatch_, TRACEPOINT_PROVIDER)(void)
{
}

#undef TRACEPOINT_EVENT_CLASS
#define TRACEPOINT_EVENT_CLASS(_provider, _name, _args, _fields) 	\
	__tracepoint_provider_mismatch_##_provider();

#undef TRACEPOINT_EVENT_INSTANCE
#define TRACEPOINT_EVENT_INSTANCE(_provider, _template, _name, _args)	\
	__tracepoint_provider_mismatch_##_provider();

static __attribute__((unused))
void _TP_COMBINE_TOKENS(__tracepoint_provider_check_, TRACEPOINT_PROVIDER)(void)
{
#include TRACEPOINT_INCLUDE
}

/*
 * Stage 0.1 of tracepoint event generation.
 *
 * Check that each TRACEPOINT_EVENT provider:name does not exceed the
 * tracepoint name length limit.
 */

/* Reset all macros within TRACEPOINT_EVENT */
#include <lttng/ust-tracepoint-event-reset.h>

#undef TRACEPOINT_EVENT_INSTANCE
#define TRACEPOINT_EVENT_INSTANCE(_provider, _template, _name, _args)	\
static const char							\
	__tp_name_len_check##_provider##___##_name[LTTNG_UST_SYM_NAME_LEN] \
	__attribute__((unused)) =					\
		#_provider ":" #_name;

#include TRACEPOINT_INCLUDE

/*
 * Stage 1 of tracepoint event generation.
 *
 * Create event field type metadata section.
 * Each event produce an array of fields.
 */

/* Reset all macros within TRACEPOINT_EVENT */
#include <lttng/ust-tracepoint-event-reset.h>

#undef ctf_integer_ext
#define ctf_integer_ext(_type, _item, _src, _byte_order, _base)	\
	{							\
	  .name = #_item,					\
	  .type = __type_integer(_type, _byte_order, _base, none),\
	},

#undef ctf_float
#define ctf_float(_type, _item, _src)				\
	{							\
	  .name = #_item,					\
	  .type = __type_float(_type),				\
	},

#undef ctf_array_encoded
#define ctf_array_encoded(_type, _item, _src, _length, _encoding) \
	{							\
	  .name = #_item,					\
	  .type =						\
		{						\
		  .atype = atype_array,				\
		  .u.array =					\
			{					\
			    .length = _length,			\
			    .elem_type = __type_integer(_type, BYTE_ORDER, 10, _encoding), \
			},					\
		},						\
	},

#undef ctf_sequence_encoded
#define ctf_sequence_encoded(_type, _item, _src,	\
			_length_type, _src_length, _encoding)	\
	{							\
	  .name = #_item,					\
	  .type =						\
		{						\
		  .atype = atype_sequence,			\
		  .u.sequence =					\
			{					\
			    .length_type = __type_integer(_length_type, BYTE_ORDER, 10, none), \
			    .elem_type = __type_integer(_type, BYTE_ORDER, 10, _encoding), \
			},					\
		},						\
	},

#undef ctf_string
#define ctf_string(_item, _src)					\
	{							\
	  .name = #_item,					\
	  .type =						\
		{						\
		  .atype = atype_string,			\
		  .u.basic.string.encoding = lttng_encode_UTF8,	\
		},						\
	},

#undef TP_FIELDS
#define TP_FIELDS(args...) args	/* Only one used in this phase */

#undef TRACEPOINT_EVENT_CLASS
#define TRACEPOINT_EVENT_CLASS(_provider, _name, _args, _fields)		   	     \
	static const struct lttng_event_field __event_fields___##_provider##___##_name[] = { \
		_fields									     \
	};

#include TRACEPOINT_INCLUDE

/*
 * Stage 2 of tracepoint event generation.
 *
 * Create probe callback prototypes.
 */

/* Reset all macros within TRACEPOINT_EVENT */
#include <lttng/ust-tracepoint-event-reset.h>

#undef TP_ARGS
#define TP_ARGS(args...) args

#undef TRACEPOINT_EVENT_CLASS
#define TRACEPOINT_EVENT_CLASS(_provider, _name, _args, _fields)		\
static void __event_probe__##_provider##___##_name(_TP_ARGS_DATA_PROTO(_args));

#include TRACEPOINT_INCLUDE

/*
 * Stage 3 of tracepoint event generation.
 *
 * Create static inline function that calculates event size.
 */

/* Reset all macros within TRACEPOINT_EVENT */
#include <lttng/ust-tracepoint-event-reset.h>

#undef ctf_integer_ext
#define ctf_integer_ext(_type, _item, _src, _byte_order, _base)		       \
	__event_len += lib_ring_buffer_align(__event_len, lttng_alignof(_type)); \
	__event_len += sizeof(_type);

#undef ctf_float
#define ctf_float(_type, _item, _src)		      			       \
	__event_len += lib_ring_buffer_align(__event_len, lttng_alignof(_type)); \
	__event_len += sizeof(_type);

#undef ctf_array_encoded
#define ctf_array_encoded(_type, _item, _src, _length, _encoding)	       \
	__event_len += lib_ring_buffer_align(__event_len, lttng_alignof(_type)); \
	__event_len += sizeof(_type) * (_length);

#undef ctf_sequence_encoded
#define ctf_sequence_encoded(_type, _item, _src, _length_type,	\
			_src_length, _encoding)			\
	__event_len += lib_ring_buffer_align(__event_len, lttng_alignof(_length_type));   \
	__event_len += sizeof(_length_type);				       \
	__event_len += lib_ring_buffer_align(__event_len, lttng_alignof(_type)); \
	__dynamic_len[__dynamic_len_idx] = (_src_length);		       \
	__event_len += sizeof(_type) * __dynamic_len[__dynamic_len_idx];       \
	__dynamic_len_idx++;

#undef ctf_string
#define ctf_string(_item, _src)						       \
	__event_len += __dynamic_len[__dynamic_len_idx++] = strlen(_src) + 1;

#undef TP_ARGS
#define TP_ARGS(args...) args

#undef TP_FIELDS
#define TP_FIELDS(args...) args

#undef TRACEPOINT_EVENT_CLASS
#define TRACEPOINT_EVENT_CLASS(_provider, _name, _args, _fields)      \
static inline size_t __event_get_size__##_provider##___##_name(size_t *__dynamic_len, _TP_ARGS_DATA_PROTO(_args)) \
{									      \
	size_t __event_len = 0;						      \
	unsigned int __dynamic_len_idx = 0;				      \
									      \
	if (0)								      \
		(void) __dynamic_len_idx;	/* don't warn if unused */    \
	_fields								      \
	return __event_len;						      \
}

#include TRACEPOINT_INCLUDE

/*
 * Stage 4 of tracepoint event generation.
 *
 * Create static inline function that calculates event payload alignment.
 */

/* Reset all macros within TRACEPOINT_EVENT */
#include <lttng/ust-tracepoint-event-reset.h>

#undef ctf_integer_ext
#define ctf_integer_ext(_type, _item, _src, _byte_order, _base)		       \
	__event_align = _tp_max_t(size_t, __event_align, lttng_alignof(_type));

#undef ctf_float
#define ctf_float(_type, _item, _src)					       \
	__event_align = _tp_max_t(size_t, __event_align, lttng_alignof(_type));

#undef ctf_array_encoded
#define ctf_array_encoded(_type, _item, _src, _length, _encoding)	       \
	__event_align = _tp_max_t(size_t, __event_align, lttng_alignof(_type));

#undef ctf_sequence_encoded
#define ctf_sequence_encoded(_type, _item, _src, _length_type,	\
			_src_length, _encoding)			\
	__event_align = _tp_max_t(size_t, __event_align, lttng_alignof(_length_type));	  \
	__event_align = _tp_max_t(size_t, __event_align, lttng_alignof(_type));

#undef ctf_string
#define ctf_string(_item, _src)

#undef TP_ARGS
#define TP_ARGS(args...) args

#undef TP_FIELDS
#define TP_FIELDS(args...) args

#undef TRACEPOINT_EVENT_CLASS
#define TRACEPOINT_EVENT_CLASS(_provider, _name, _args, _fields)	      \
static inline								      \
size_t __event_get_align__##_provider##___##_name(_TP_ARGS_PROTO(_args))      \
{									      \
	size_t __event_align = 1;					      \
	_fields								      \
	return __event_align;						      \
}

#include TRACEPOINT_INCLUDE


/*
 * Stage 5 of tracepoint event generation.
 *
 * Create the probe function. This function calls event size calculation
 * and writes event data into the buffer.
 */

/* Reset all macros within TRACEPOINT_EVENT */
#include <lttng/ust-tracepoint-event-reset.h>

#undef ctf_integer_ext
#define ctf_integer_ext(_type, _item, _src, _byte_order, _base)	        \
	{								\
		_type __tmp = (_src);					\
		lib_ring_buffer_align_ctx(&__ctx, lttng_alignof(__tmp));\
		__chan->ops->event_write(&__ctx, &__tmp, sizeof(__tmp));\
	}

#undef ctf_float
#define ctf_float(_type, _item, _src)				        \
	{								\
		_type __tmp = (_src);					\
		lib_ring_buffer_align_ctx(&__ctx, lttng_alignof(__tmp));\
		__chan->ops->event_write(&__ctx, &__tmp, sizeof(__tmp));\
	}

#undef ctf_array_encoded
#define ctf_array_encoded(_type, _item, _src, _length, _encoding)       \
	lib_ring_buffer_align_ctx(&__ctx, lttng_alignof(_type));	\
	__chan->ops->event_write(&__ctx, _src, sizeof(_type) * (_length));

#undef ctf_sequence_encoded
#define ctf_sequence_encoded(_type, _item, _src, _length_type,		\
			_src_length, _encoding)			\
	{								\
		_length_type __tmpl = __dynamic_len[__dynamic_len_idx];	\
		lib_ring_buffer_align_ctx(&__ctx, lttng_alignof(_length_type));\
		__chan->ops->event_write(&__ctx, &__tmpl, sizeof(_length_type));\
	}								\
	lib_ring_buffer_align_ctx(&__ctx, lttng_alignof(_type));	\
	__chan->ops->event_write(&__ctx, _src,				\
		sizeof(_type) * __get_dynamic_len(dest));

#undef ctf_string
#define ctf_string(_item, _src)					        \
	lib_ring_buffer_align_ctx(&__ctx, lttng_alignof(*(_src)));	\
	__chan->ops->event_write(&__ctx, _src, __get_dynamic_len(dest));

/* Beware: this get len actually consumes the len value */
#undef __get_dynamic_len
#define __get_dynamic_len(field)	__dynamic_len[__dynamic_len_idx++]

#undef TP_ARGS
#define TP_ARGS(args...) args

#undef TP_FIELDS
#define TP_FIELDS(args...) args

#undef TRACEPOINT_EVENT_CLASS
#define TRACEPOINT_EVENT_CLASS(_provider, _name, _args, _fields)	      \
static void __event_probe__##_provider##___##_name(_TP_ARGS_DATA_PROTO(_args))\
{									      \
	struct ltt_event *__event = __tp_data;				      \
	struct ltt_channel *__chan = __event->chan;			      \
	struct lttng_ust_lib_ring_buffer_ctx __ctx;			      \
	size_t __event_len, __event_align;				      \
	size_t __dynamic_len_idx = 0;					      \
	size_t __dynamic_len[_TP_ARRAY_SIZE(__event_fields___##_provider##___##_name)];	      \
	int __ret;							      \
									      \
	if (0)								      \
		(void) __dynamic_len_idx;	/* don't warn if unused */    \
	if (caa_unlikely(!CMM_ACCESS_ONCE(__chan->session->active)))	      \
		return;							      \
	if (caa_unlikely(!CMM_ACCESS_ONCE(__chan->enabled)))		      \
		return;							      \
	if (caa_unlikely(!CMM_ACCESS_ONCE(__event->enabled)))		      \
		return;							      \
	__event_len = __event_get_size__##_provider##___##_name(__dynamic_len,\
		 _TP_ARGS_DATA_VAR(_args));				      \
	__event_align = __event_get_align__##_provider##___##_name(_TP_ARGS_VAR(_args)); \
	lib_ring_buffer_ctx_init(&__ctx, __chan->chan, __event, __event_len,  \
				 __event_align, -1, __chan->handle);	      \
	__ret = __chan->ops->event_reserve(&__ctx, __event->id);	      \
	if (__ret < 0)							      \
		return;							      \
	_fields								      \
	__chan->ops->event_commit(&__ctx);				      \
}

#include TRACEPOINT_INCLUDE

#undef __get_dynamic_len

/*
 * Stage 5.1 of tracepoint event generation.
 *
 * Create probe signature
 */

/* Reset all macros within TRACEPOINT_EVENT */
#include <lttng/ust-tracepoint-event-reset.h>

#undef TP_ARGS
#define TP_ARGS(args...) args

#define _TP_EXTRACT_STRING2(...)	#__VA_ARGS__

#undef TRACEPOINT_EVENT_CLASS
#define TRACEPOINT_EVENT_CLASS(_provider, _name, _args, _fields)	\
const char __tp_event_signature___##_provider##___##_name[] = 		\
		_TP_EXTRACT_STRING2(_args);

#include TRACEPOINT_INCLUDE

#undef _TP_EXTRACT_STRING2

/*
 * Stage 6 of tracepoint event generation.
 *
 * Tracepoint loglevel mapping definition generation. We generate a
 * symbol for each mapping for a provider/event to ensure at most a 1 to
 * 1 mapping between events and loglevels. If the symbol is repeated,
 * the compiler will complain.
 */

/* Reset all macros within TRACEPOINT_EVENT */
#include <lttng/ust-tracepoint-event-reset.h>

#undef TRACEPOINT_LOGLEVEL
#define TRACEPOINT_LOGLEVEL(__provider, __name, __loglevel)		   \
static const int _loglevel_value___##__provider##___##__name = __loglevel; \
static const int *_loglevel___##__provider##___##__name =		   \
		&_loglevel_value___##__provider##___##__name;

#include TRACEPOINT_INCLUDE

/*
 * Stage 7.1 of tracepoint event generation.
 *
 * Create events description structures. We use a weakref because
 * loglevels are optional. If not declared, the event will point to the
 * a loglevel that contains NULL.
 */

/* Reset all macros within TRACEPOINT_EVENT */
#include <lttng/ust-tracepoint-event-reset.h>

#undef TRACEPOINT_EVENT_INSTANCE
#define TRACEPOINT_EVENT_INSTANCE(_provider, _template, _name, _args)	       \
static const int *							       \
	__ref_loglevel___##_provider##___##_name			       \
	__attribute__((weakref ("_loglevel___" #_provider "___" #_name)));     \
const struct lttng_event_desc __event_desc___##_provider##_##_name = {	       \
	.fields = __event_fields___##_provider##___##_template,		       \
	.name = #_provider ":" #_name,					       \
	.probe_callback = (void *) &__event_probe__##_provider##___##_template,\
	.nr_fields = _TP_ARRAY_SIZE(__event_fields___##_provider##___##_template), \
	.loglevel = &__ref_loglevel___##_provider##___##_name,		       \
	.signature = __tp_event_signature___##_provider##___##_template,       \
};

#include TRACEPOINT_INCLUDE

/*
 * Stage 7.2 of tracepoint event generation.
 *
 * Create array of events.
 */

/* Reset all macros within TRACEPOINT_EVENT */
#include <lttng/ust-tracepoint-event-reset.h>

#undef TRACEPOINT_EVENT_INSTANCE
#define TRACEPOINT_EVENT_INSTANCE(_provider, _template, _name, _args)	       \
	&__event_desc___##_provider##_##_name,

static const struct lttng_event_desc *_TP_COMBINE_TOKENS(__event_desc___, TRACEPOINT_PROVIDER)[] = {
#include TRACEPOINT_INCLUDE
};


/*
 * Stage 8 of tracepoint event generation.
 *
 * Create a toplevel descriptor for the whole probe.
 */

/* non-const because list head will be modified when registered. */
static struct lttng_probe_desc _TP_COMBINE_TOKENS(__probe_desc___, TRACEPOINT_PROVIDER) = {
	.provider = __tp_stringify(TRACEPOINT_PROVIDER),
	.event_desc = _TP_COMBINE_TOKENS(__event_desc___, TRACEPOINT_PROVIDER),
	.nr_events = _TP_ARRAY_SIZE(_TP_COMBINE_TOKENS(__event_desc___, TRACEPOINT_PROVIDER)),
};

/*
 * Stage 9 of tracepoint event generation.
 *
 * Register/unregister probes at module load/unload.
 *
 * Generate the constructor as an externally visible symbol for use when
 * linking the probe statically.
 */

/* Reset all macros within TRACEPOINT_EVENT */
#include <lttng/ust-tracepoint-event-reset.h>
static void __attribute__((constructor))
_TP_COMBINE_TOKENS(__lttng_events_init__, TRACEPOINT_PROVIDER)(void)
{
	int ret;

	ret = ltt_probe_register(&_TP_COMBINE_TOKENS(__probe_desc___, TRACEPOINT_PROVIDER));
	assert(!ret);
}

static void __attribute__((destructor))
_TP_COMBINE_TOKENS(__lttng_events_exit__, TRACEPOINT_PROVIDER)(void)
{
	ltt_probe_unregister(&_TP_COMBINE_TOKENS(__probe_desc___, TRACEPOINT_PROVIDER));
}

int _TP_COMBINE_TOKENS(__tracepoint_provider_, TRACEPOINT_PROVIDER);
