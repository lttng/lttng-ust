/*
 * Copyright (C) 2009     Steven Rostedt <srostedt@redhat.com>
 * Copyright (C) 2011     Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation;
 * version 2.1 of the License.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301 USA
 */

#include <stdio.h>
#include <urcu/compiler.h>
#include <lttng/ust-events.h>
#include <lttng/usterr-signal-safe.h>
#include <lttng/ringbuffer-config.h>

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
 * TRACEPOINT_EVENT_CLASS can be used to add a generic function handlers
 * for events. That is, if all events have the same parameters and just
 * have distinct trace points.  Each tracepoint can be defined with
 * TRACEPOINT_EVENT_INSTANCE and that will map the
 * TRACEPOINT_EVENT_CLASS to the tracepoint.
 *
 * TRACEPOINT_EVENT is a one to one mapping between tracepoint and
 * template.
 */

#undef TRACEPOINT_EVENT
#define TRACEPOINT_EVENT(provider, name, args, fields)	\
	TRACEPOINT_EVENT_CLASS(provider, name,		\
			     TP_PARAMS(args),		\
			     TP_PARAMS(fields))		\
	TRACEPOINT_EVENT_INSTANCE(provider, name, name, TP_PARAMS(args))

/* Helpers */
#define _TP_ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]))

#define _tp_max_t(type, x, y)				\
	({						\
		type __max1 = (x);              	\
		type __max2 = (y);              	\
		__max1 > __max2 ? __max1: __max2;	\
	})

/*
 * Stage 0 of the trace events.
 *
 * Check that each TRACEPOINT_EVENT provider argument match the
 * TRACEPOINT_PROVIDER by creating dummy callbacks.
 */

/* Reset all macros within TRACEPOINT_EVENT */
#include <lttng/ust-tracepoint-event-reset.h>

#define TP_ID1(_token, _provider)	_token##_provider
#define TP_ID(_token, _provider)	TP_ID1(_token, _provider)

static inline
void TP_ID(__tracepoint_provider_mismatch_, TRACEPOINT_PROVIDER)(void)
{
}

#undef TRACEPOINT_EVENT_CLASS
#define TRACEPOINT_EVENT_CLASS(_provider, _name, _args, _fields) 	\
	__tracepoint_provider_mismatch_##_provider();

#undef TRACEPOINT_EVENT_INSTANCE
#define TRACEPOINT_EVENT_INSTANCE(_provider, _template, _name, _args)	\
	__tracepoint_provider_mismatch_##_provider();

static __attribute__((unused))
void TP_ID(__tracepoint_provider_check_, TRACEPOINT_PROVIDER)(void)
{
#include TRACEPOINT_INCLUDE(TRACEPOINT_INCLUDE_FILE)
}

#undef TP_ID1
#undef TP_ID

/*
 * Stage 1 of the trace events.
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

#include TRACEPOINT_INCLUDE(TRACEPOINT_INCLUDE_FILE)

/*
 * Stage 2 of the trace events.
 *
 * Create probe callback prototypes.
 */

/* Reset all macros within TRACEPOINT_EVENT */
#include <lttng/ust-tracepoint-event-reset.h>

#undef TP_ARGS
#define TP_ARGS(args...) args

#undef TRACEPOINT_EVENT_CLASS
#define TRACEPOINT_EVENT_CLASS(_provider, _name, _args, _fields)		\
static void __event_probe__##_provider##___##_name(_TP_ARGS_PROTO_DATA(_args));

#include TRACEPOINT_INCLUDE(TRACEPOINT_INCLUDE_FILE)

/*
 * Stage 3 of the trace events.
 *
 * Create an array of events.
 */

/* Reset all macros within TRACEPOINT_EVENT */
#include <lttng/ust-tracepoint-event-reset.h>

#undef TRACEPOINT_EVENT_INSTANCE
#define TRACEPOINT_EVENT_INSTANCE(_provider, _template, _name, _args)	       \
		{							       \
			.fields = __event_fields___##_provider##___##_template,\
			.name = #_provider ":" #_name,			       \
			.probe_callback = (void *) &__event_probe__##_provider##___##_template,\
			.nr_fields = _TP_ARRAY_SIZE(__event_fields___##_provider##___##_template), \
		},

#define TP_ID1(_token, _provider)	_token##_provider
#define TP_ID(_token, _provider)	TP_ID1(_token, _provider)

static const struct lttng_event_desc TP_ID(__event_desc___, TRACEPOINT_PROVIDER)[] = {
#include TRACEPOINT_INCLUDE(TRACEPOINT_INCLUDE_FILE)
};

#undef TP_ID1
#undef TP_ID


/*
 * Stage 4 of the trace events.
 *
 * Create a toplevel descriptor for the whole probe.
 */

#define TP_ID1(_token, _provider)	_token##_provider
#define TP_ID(_token, _provider)	TP_ID1(_token, _provider)

/* non-const because list head will be modified when registered. */
static struct lttng_probe_desc TP_ID(__probe_desc___, TRACEPOINT_PROVIDER) = {
	.event_desc = TP_ID(__event_desc___, TRACEPOINT_PROVIDER),
	.nr_events = _TP_ARRAY_SIZE(TP_ID(__event_desc___, TRACEPOINT_PROVIDER)),
};

#undef TP_ID1
#undef TP_ID

/*
 * Stage 5 of the trace events.
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
static inline size_t __event_get_size__##_provider##___##_name(size_t *__dynamic_len, _TP_ARGS_PROTO_DATA(_args)) \
{									      \
	size_t __event_len = 0;						      \
	unsigned int __dynamic_len_idx = 0;				      \
									      \
	if (0)								      \
		(void) __dynamic_len_idx;	/* don't warn if unused */    \
	_fields								      \
	return __event_len;						      \
}

#include TRACEPOINT_INCLUDE(TRACEPOINT_INCLUDE_FILE)

/*
 * Stage 6 of the trace events.
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

#include TRACEPOINT_INCLUDE(TRACEPOINT_INCLUDE_FILE)


/*
 * Stage 7 of the trace events.
 *
 * Create the probe function : call even size calculation and write event data
 * into the buffer.
 *
 * We use both the field and assignment macros to write the fields in the order
 * defined in the field declaration. The field declarations control the
 * execution order, jumping to the appropriate assignment block.
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
static void __event_probe__##_provider##___##_name(_TP_ARGS_PROTO_DATA(_args))\
{									      \
	struct ltt_event *__event = __tp_cb_data;			      \
	struct ltt_channel *__chan = __event->chan;			      \
	struct lttng_ust_lib_ring_buffer_ctx __ctx;				      \
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
		 _TP_ARGS_VARS_DATA(_args));				      \
	__event_align = __event_get_align__##_provider##___##_name(_TP_ARGS_VARS(_args)); \
	lib_ring_buffer_ctx_init(&__ctx, __chan->chan, __event, __event_len,  \
				 __event_align, -1, __chan->handle);	      \
	__ret = __chan->ops->event_reserve(&__ctx, __event->id);	      \
	if (__ret < 0)							      \
		return;							      \
	_fields								      \
	__chan->ops->event_commit(&__ctx);				      \
}

#include TRACEPOINT_INCLUDE(TRACEPOINT_INCLUDE_FILE)

#undef __get_dynamic_len

/*
 * Stage 8 of the trace events.
 *
 * Register/unregister probes at module load/unload.
 */

/* Reset all macros within TRACEPOINT_EVENT */
#include <lttng/ust-tracepoint-event-reset.h>

#define TP_ID1(_token, _provider)	_token##_provider
#define TP_ID(_token, _provider)	TP_ID1(_token, _provider)

static void __attribute__((constructor))
TP_ID(__lttng_events_init__, TRACEPOINT_PROVIDER)(void)
{
	int ret;

	ret = ltt_probe_register(&TP_ID(__probe_desc___, TRACEPOINT_PROVIDER));
	assert(!ret);
}

static void __attribute__((destructor))
TP_ID(__lttng_events_exit__, TRACEPOINT_PROVIDER)(void)
{
	ltt_probe_unregister(&TP_ID(__probe_desc___, TRACEPOINT_PROVIDER));
}

#undef TP_ID1
#undef TP_ID
