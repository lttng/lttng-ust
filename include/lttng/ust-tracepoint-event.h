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
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#include <stdio.h>
#include <stdlib.h>
#include <urcu/compiler.h>
#include <urcu/rculist.h>
#include <lttng/ust-events.h>
#include <lttng/ringbuffer-config.h>
#include <lttng/ust-compiler.h>
#include <lttng/tracepoint.h>
#include <string.h>

#undef tp_list_for_each_entry_rcu
#define tp_list_for_each_entry_rcu(pos, head, member)	\
	for (pos = cds_list_entry(tp_rcu_dereference_bp((head)->next), __typeof__(*pos), member);	\
	     &pos->member != (head);					\
	     pos = cds_list_entry(tp_rcu_dereference_bp(pos->member.next), __typeof__(*pos), member))

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

static inline lttng_ust_notrace
void _TP_COMBINE_TOKENS(__tracepoint_provider_mismatch_, TRACEPOINT_PROVIDER)(void);
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

static inline lttng_ust_notrace
void _TP_COMBINE_TOKENS(__tracepoint_provider_check_, TRACEPOINT_PROVIDER)(void);
static inline
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
#include <lttng/ust-tracepoint-event-write.h>
#include <lttng/ust-tracepoint-event-nowrite.h>

#undef _ctf_integer_ext
#define _ctf_integer_ext(_type, _item, _src, _byte_order, _base, _nowrite)	\
	{							\
	  .name = #_item,					\
	  .type = __type_integer(_type, _byte_order, _base, none),\
	  .nowrite = _nowrite,					\
	},

#undef _ctf_float
#define _ctf_float(_type, _item, _src, _nowrite)		\
	{							\
	  .name = #_item,					\
	  .type = __type_float(_type),				\
	  .nowrite = _nowrite,					\
	},

#undef _ctf_array_encoded
#define _ctf_array_encoded(_type, _item, _src, _length, _encoding, _nowrite) \
	{							\
	  .name = #_item,					\
	  .type =						\
		{						\
		  .atype = atype_array,				\
		  .u =						\
			{					\
			  .array =				\
				{				\
				  .elem_type = __type_integer(_type, BYTE_ORDER, 10, _encoding), \
				  .length = _length,		\
				}				\
			}					\
		},						\
	  .nowrite = _nowrite,					\
	},

#undef _ctf_sequence_encoded
#define _ctf_sequence_encoded(_type, _item, _src,	\
			_length_type, _src_length, _encoding, _nowrite)	\
	{							\
	  .name = #_item,					\
	  .type =						\
		{						\
		  .atype = atype_sequence,			\
		  .u =						\
			{					\
			  .sequence =				\
				{				\
				  .length_type = __type_integer(_length_type, BYTE_ORDER, 10, none), \
				  .elem_type = __type_integer(_type, BYTE_ORDER, 10, _encoding), \
				},				\
			},					\
		},						\
	  .nowrite = _nowrite,					\
	},

#undef _ctf_string
#define _ctf_string(_item, _src, _nowrite)			\
	{							\
	  .name = #_item,					\
	  .type =						\
		{						\
		  .atype = atype_string,			\
		  .u =						\
			{					\
			  .basic = { .string = { .encoding = lttng_encode_UTF8 } } \
			},					\
		},						\
	  .nowrite = _nowrite,					\
	},

#undef TP_FIELDS
#define TP_FIELDS(...) __VA_ARGS__	/* Only one used in this phase */

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
#define TP_ARGS(...) __VA_ARGS__

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
#include <lttng/ust-tracepoint-event-write.h>

#undef _ctf_integer_ext
#define _ctf_integer_ext(_type, _item, _src, _byte_order, _base, _nowrite)       \
	__event_len += lib_ring_buffer_align(__event_len, lttng_alignof(_type)); \
	__event_len += sizeof(_type);

#undef _ctf_float
#define _ctf_float(_type, _item, _src, _nowrite)				 \
	__event_len += lib_ring_buffer_align(__event_len, lttng_alignof(_type)); \
	__event_len += sizeof(_type);

#undef _ctf_array_encoded
#define _ctf_array_encoded(_type, _item, _src, _length, _encoding, _nowrite)     \
	__event_len += lib_ring_buffer_align(__event_len, lttng_alignof(_type)); \
	__event_len += sizeof(_type) * (_length);

#undef _ctf_sequence_encoded
#define _ctf_sequence_encoded(_type, _item, _src, _length_type,	\
			_src_length, _encoding, _nowrite)	\
	__event_len += lib_ring_buffer_align(__event_len, lttng_alignof(_length_type));   \
	__event_len += sizeof(_length_type);				       \
	__event_len += lib_ring_buffer_align(__event_len, lttng_alignof(_type)); \
	__dynamic_len[__dynamic_len_idx] = (_src_length);		       \
	__event_len += sizeof(_type) * __dynamic_len[__dynamic_len_idx];       \
	__dynamic_len_idx++;

#undef _ctf_string
#define _ctf_string(_item, _src, _nowrite)				       \
	__event_len += __dynamic_len[__dynamic_len_idx++] = strlen(_src) + 1;

#undef TP_ARGS
#define TP_ARGS(...) __VA_ARGS__

#undef TP_FIELDS
#define TP_FIELDS(...) __VA_ARGS__

#undef TRACEPOINT_EVENT_CLASS
#define TRACEPOINT_EVENT_CLASS(_provider, _name, _args, _fields)	      \
static inline lttng_ust_notrace						      \
size_t __event_get_size__##_provider##___##_name(size_t *__dynamic_len, _TP_ARGS_DATA_PROTO(_args)); \
static inline								      \
size_t __event_get_size__##_provider##___##_name(size_t *__dynamic_len, _TP_ARGS_DATA_PROTO(_args)) \
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
 * Stage 3.1 of tracepoint event generation.
 *
 * Create static inline function that layout the filter stack data.
 * We make both write and nowrite data available to the filter.
 */

/* Reset all macros within TRACEPOINT_EVENT */
#include <lttng/ust-tracepoint-event-reset.h>
#include <lttng/ust-tracepoint-event-write.h>
#include <lttng/ust-tracepoint-event-nowrite.h>

#undef _ctf_integer_ext
#define _ctf_integer_ext(_type, _item, _src, _byte_order, _base, _nowrite)     \
	if (lttng_is_signed_type(_type)) {				       \
		int64_t __ctf_tmp_int64;				       \
		switch (sizeof(_type)) {				       \
		case 1:							       \
		{							       \
			union { _type t; int8_t v; } __tmp = { (_type) (_src) }; \
			__ctf_tmp_int64 = (int64_t) __tmp.v;		       \
			break;						       \
		}							       \
		case 2:							       \
		{							       \
			union { _type t; int16_t v; } __tmp = { (_type) (_src) }; \
			__ctf_tmp_int64 = (int64_t) __tmp.v;		       \
			break;						       \
		}							       \
		case 4:							       \
		{							       \
			union { _type t; int32_t v; } __tmp = { (_type) (_src) }; \
			__ctf_tmp_int64 = (int64_t) __tmp.v;		       \
			break;						       \
		}							       \
		case 8:							       \
		{							       \
			union { _type t; int64_t v; } __tmp = { (_type) (_src) }; \
			__ctf_tmp_int64 = (int64_t) __tmp.v;		       \
			break;						       \
		}							       \
		default:						       \
			abort();					       \
		};							       \
		memcpy(__stack_data, &__ctf_tmp_int64, sizeof(int64_t));       \
	} else {							       \
		uint64_t __ctf_tmp_uint64;				       \
		switch (sizeof(_type)) {				       \
		case 1:							       \
		{							       \
			union { _type t; uint8_t v; } __tmp = { (_type) (_src) }; \
			__ctf_tmp_uint64 = (uint64_t) __tmp.v;		       \
			break;						       \
		}							       \
		case 2:							       \
		{							       \
			union { _type t; uint16_t v; } __tmp = { (_type) (_src) }; \
			__ctf_tmp_uint64 = (uint64_t) __tmp.v;		       \
			break;						       \
		}							       \
		case 4:							       \
		{							       \
			union { _type t; uint32_t v; } __tmp = { (_type) (_src) }; \
			__ctf_tmp_uint64 = (uint64_t) __tmp.v;		       \
			break;						       \
		}							       \
		case 8:							       \
		{							       \
			union { _type t; uint64_t v; } __tmp = { (_type) (_src) }; \
			__ctf_tmp_uint64 = (uint64_t) __tmp.v;		       \
			break;						       \
		}							       \
		default:						       \
			abort();					       \
		};							       \
		memcpy(__stack_data, &__ctf_tmp_uint64, sizeof(uint64_t));     \
	}								       \
	__stack_data += sizeof(int64_t);

#undef _ctf_float
#define _ctf_float(_type, _item, _src, _nowrite)			       \
	{								       \
		double __ctf_tmp_double = (double) (_type) (_src);	       \
		memcpy(__stack_data, &__ctf_tmp_double, sizeof(double));       \
		__stack_data += sizeof(double);				       \
	}

#undef _ctf_array_encoded
#define _ctf_array_encoded(_type, _item, _src, _length, _encoding, _nowrite)   \
	{								       \
		unsigned long __ctf_tmp_ulong = (unsigned long) (_length);     \
		const void *__ctf_tmp_ptr = (_src);			       \
		memcpy(__stack_data, &__ctf_tmp_ulong, sizeof(unsigned long)); \
		__stack_data += sizeof(unsigned long);			       \
		memcpy(__stack_data, &__ctf_tmp_ptr, sizeof(void *));	       \
		__stack_data += sizeof(void *);				       \
	}

#undef _ctf_sequence_encoded
#define _ctf_sequence_encoded(_type, _item, _src, _length_type,		       \
			_src_length, _encoding, _nowrite)		       \
	{								       \
		unsigned long __ctf_tmp_ulong = (unsigned long) (_src_length); \
		const void *__ctf_tmp_ptr = (_src);			       \
		memcpy(__stack_data, &__ctf_tmp_ulong, sizeof(unsigned long)); \
		__stack_data += sizeof(unsigned long);			       \
		memcpy(__stack_data, &__ctf_tmp_ptr, sizeof(void *));	       \
		__stack_data += sizeof(void *);				       \
	}

#undef _ctf_string
#define _ctf_string(_item, _src, _nowrite)				       \
	{								       \
		const void *__ctf_tmp_ptr = (_src);			       \
		memcpy(__stack_data, &__ctf_tmp_ptr, sizeof(void *));	       \
		__stack_data += sizeof(void *);				       \
	}

#undef TP_ARGS
#define TP_ARGS(...) __VA_ARGS__

#undef TP_FIELDS
#define TP_FIELDS(...) __VA_ARGS__

#undef TRACEPOINT_EVENT_CLASS
#define TRACEPOINT_EVENT_CLASS(_provider, _name, _args, _fields)	      \
static inline								      \
void __event_prepare_filter_stack__##_provider##___##_name(char *__stack_data,\
						 _TP_ARGS_DATA_PROTO(_args))  \
{									      \
	_fields								      \
}

#include TRACEPOINT_INCLUDE



/*
 * Stage 4 of tracepoint event generation.
 *
 * Create static inline function that calculates event payload alignment.
 */

/* Reset all macros within TRACEPOINT_EVENT */
#include <lttng/ust-tracepoint-event-reset.h>
#include <lttng/ust-tracepoint-event-write.h>

#undef _ctf_integer_ext
#define _ctf_integer_ext(_type, _item, _src, _byte_order, _base, _nowrite)     \
	__event_align = _tp_max_t(size_t, __event_align, lttng_alignof(_type));

#undef _ctf_float
#define _ctf_float(_type, _item, _src, _nowrite)			       \
	__event_align = _tp_max_t(size_t, __event_align, lttng_alignof(_type));

#undef _ctf_array_encoded
#define _ctf_array_encoded(_type, _item, _src, _length, _encoding, _nowrite)   \
	__event_align = _tp_max_t(size_t, __event_align, lttng_alignof(_type));

#undef _ctf_sequence_encoded
#define _ctf_sequence_encoded(_type, _item, _src, _length_type,	\
			_src_length, _encoding, _nowrite)	\
	__event_align = _tp_max_t(size_t, __event_align, lttng_alignof(_length_type));	  \
	__event_align = _tp_max_t(size_t, __event_align, lttng_alignof(_type));

#undef _ctf_string
#define _ctf_string(_item, _src, _nowrite)

#undef TP_ARGS
#define TP_ARGS(...) __VA_ARGS__

#undef TP_FIELDS
#define TP_FIELDS(...) __VA_ARGS__

#undef TRACEPOINT_EVENT_CLASS
#define TRACEPOINT_EVENT_CLASS(_provider, _name, _args, _fields)	      \
static inline lttng_ust_notrace						      \
size_t __event_get_align__##_provider##___##_name(_TP_ARGS_PROTO(_args));     \
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
#include <lttng/ust-tracepoint-event-write.h>

#undef _ctf_integer_ext
#define _ctf_integer_ext(_type, _item, _src, _byte_order, _base, _nowrite) \
	{								\
		_type __tmp = (_src);					\
		lib_ring_buffer_align_ctx(&__ctx, lttng_alignof(__tmp));\
		__chan->ops->event_write(&__ctx, &__tmp, sizeof(__tmp));\
	}

#undef _ctf_float
#define _ctf_float(_type, _item, _src, _nowrite)		        \
	{								\
		_type __tmp = (_src);					\
		lib_ring_buffer_align_ctx(&__ctx, lttng_alignof(__tmp));\
		__chan->ops->event_write(&__ctx, &__tmp, sizeof(__tmp));\
	}

#undef _ctf_array_encoded
#define _ctf_array_encoded(_type, _item, _src, _length, _encoding, _nowrite) \
	lib_ring_buffer_align_ctx(&__ctx, lttng_alignof(_type));	\
	__chan->ops->event_write(&__ctx, _src, sizeof(_type) * (_length));

#undef _ctf_sequence_encoded
#define _ctf_sequence_encoded(_type, _item, _src, _length_type,		\
			_src_length, _encoding, _nowrite)		\
	{								\
		_length_type __tmpl = __stackvar.__dynamic_len[__dynamic_len_idx]; \
		lib_ring_buffer_align_ctx(&__ctx, lttng_alignof(_length_type));\
		__chan->ops->event_write(&__ctx, &__tmpl, sizeof(_length_type));\
	}								\
	lib_ring_buffer_align_ctx(&__ctx, lttng_alignof(_type));	\
	__chan->ops->event_write(&__ctx, _src,				\
		sizeof(_type) * __get_dynamic_len(dest));

/*
 * __chan->ops->u.has_strcpy is a flag letting us know if the LTTng-UST
 * tracepoint provider ABI implements event_strcpy. This dynamic check
 * can be removed when the tracepoint provider ABI moves to 2.
 */
#if (LTTNG_UST_PROVIDER_MAJOR > 1)
#error "Tracepoint probe provider major version has changed. Please remove dynamic check for has_strcpy."
#endif

#undef _ctf_string
#define _ctf_string(_item, _src, _nowrite)			        \
	lib_ring_buffer_align_ctx(&__ctx, lttng_alignof(*(_src)));	\
	if (__chan->ops->u.has_strcpy)					\
		__chan->ops->event_strcpy(&__ctx, _src,			\
			__get_dynamic_len(dest));			\
	else								\
		__chan->ops->event_write(&__ctx, _src,			\
			__get_dynamic_len(dest));

/* Beware: this get len actually consumes the len value */
#undef __get_dynamic_len
#define __get_dynamic_len(field)	__stackvar.__dynamic_len[__dynamic_len_idx++]

#undef TP_ARGS
#define TP_ARGS(...) __VA_ARGS__

#undef TP_FIELDS
#define TP_FIELDS(...) __VA_ARGS__

/*
 * For state dump, check that "session" argument (mandatory) matches the
 * session this event belongs to. Ensures that we write state dump data only
 * into the started session, not into all sessions.
 */
#undef _TP_SESSION_CHECK
#ifdef TP_SESSION_CHECK
#define _TP_SESSION_CHECK(session, csession)   (session == csession)
#else /* TP_SESSION_CHECK */
#define _TP_SESSION_CHECK(session, csession)   1
#endif /* TP_SESSION_CHECK */

/*
 * Using twice size for filter stack data to hold size and pointer for
 * each field (worse case). For integers, max size required is 64-bit.
 * Same for double-precision floats. Those fit within
 * 2*sizeof(unsigned long) for all supported architectures.
 * Perform UNION (||) of filter runtime list.
 */
#undef TRACEPOINT_EVENT_CLASS
#define TRACEPOINT_EVENT_CLASS(_provider, _name, _args, _fields)	      \
static lttng_ust_notrace						      \
void __event_probe__##_provider##___##_name(_TP_ARGS_DATA_PROTO(_args));      \
static									      \
void __event_probe__##_provider##___##_name(_TP_ARGS_DATA_PROTO(_args))	      \
{									      \
	struct lttng_event *__event = (struct lttng_event *) __tp_data;			      \
	struct lttng_channel *__chan = __event->chan;			      \
	struct lttng_ust_lib_ring_buffer_ctx __ctx;			      \
	size_t __event_len, __event_align;				      \
	size_t __dynamic_len_idx = 0;					      \
	union {								      \
		size_t __dynamic_len[_TP_ARRAY_SIZE(__event_fields___##_provider##___##_name)]; \
		char __filter_stack_data[2 * sizeof(unsigned long) * _TP_ARRAY_SIZE(__event_fields___##_provider##___##_name)]; \
	} __stackvar;							      \
	int __ret;							      \
									      \
	if (0)								      \
		(void) __dynamic_len_idx;	/* don't warn if unused */    \
	if (!_TP_SESSION_CHECK(session, __chan->session))		      \
		return;							      \
	if (caa_unlikely(!CMM_ACCESS_ONCE(__chan->session->active)))	      \
		return;							      \
	if (caa_unlikely(!CMM_ACCESS_ONCE(__chan->enabled)))		      \
		return;							      \
	if (caa_unlikely(!CMM_ACCESS_ONCE(__event->enabled)))		      \
		return;							      \
	if (caa_unlikely(!TP_RCU_LINK_TEST()))				      \
		return;							      \
	if (caa_unlikely(!cds_list_empty(&__event->bytecode_runtime_head))) { \
		struct lttng_bytecode_runtime *bc_runtime;		      \
		int __filter_record = __event->has_enablers_without_bytecode; \
									      \
		__event_prepare_filter_stack__##_provider##___##_name(__stackvar.__filter_stack_data, \
			_TP_ARGS_DATA_VAR(_args));			      \
		tp_list_for_each_entry_rcu(bc_runtime, &__event->bytecode_runtime_head, node) { \
			if (caa_unlikely(bc_runtime->filter(bc_runtime,	      \
					__stackvar.__filter_stack_data) & LTTNG_FILTER_RECORD_FLAG)) \
				__filter_record = 1;			      \
		}							      \
		if (caa_likely(!__filter_record))			      \
			return;						      \
	}								      \
	__event_len = __event_get_size__##_provider##___##_name(__stackvar.__dynamic_len, \
		 _TP_ARGS_DATA_VAR(_args));				      \
	__event_align = __event_get_align__##_provider##___##_name(_TP_ARGS_VAR(_args)); \
	lib_ring_buffer_ctx_init(&__ctx, __chan->chan, __event, __event_len,  \
				 __event_align, -1, __chan->handle);	      \
	__ctx.ip = __builtin_return_address(0);				      \
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
#define TP_ARGS(...) __VA_ARGS__

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
 * Stage 6.1 of tracepoint event generation.
 *
 * Tracepoint UML URI info.
 */

/* Reset all macros within TRACEPOINT_EVENT */
#include <lttng/ust-tracepoint-event-reset.h>

#undef TRACEPOINT_MODEL_EMF_URI
#define TRACEPOINT_MODEL_EMF_URI(__provider, __name, __uri)		   \
static const char *_model_emf_uri___##__provider##___##__name = __uri;

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
static const char *							       \
	__ref_model_emf_uri___##_provider##___##_name			       \
	__attribute__((weakref ("_model_emf_uri___" #_provider "___" #_name)));\
const struct lttng_event_desc __event_desc___##_provider##_##_name = {	       \
	.name = #_provider ":" #_name,					       \
	.probe_callback = (void (*)(void)) &__event_probe__##_provider##___##_template,\
	.ctx = NULL,							       \
	.fields = __event_fields___##_provider##___##_template,		       \
	.nr_fields = _TP_ARRAY_SIZE(__event_fields___##_provider##___##_template), \
	.loglevel = &__ref_loglevel___##_provider##___##_name,		       \
	.signature = __tp_event_signature___##_provider##___##_template,       \
	.u = { .ext = { .model_emf_uri = &__ref_model_emf_uri___##_provider##___##_name } }, \
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
	.head = { NULL, NULL },
	.lazy_init_head = { NULL, NULL },
	.lazy = 0,
	.major = LTTNG_UST_PROVIDER_MAJOR,
	.minor = LTTNG_UST_PROVIDER_MINOR,
};

static int _TP_COMBINE_TOKENS(__probe_register_refcount___, TRACEPOINT_PROVIDER);

/*
 * Stage 9 of tracepoint event generation.
 *
 * Register/unregister probes at module load/unload.
 *
 * Generate the constructor as an externally visible symbol for use when
 * linking the probe statically.
 *
 * Register refcount is protected by libc dynamic loader mutex.
 */

/* Reset all macros within TRACEPOINT_EVENT */
#include <lttng/ust-tracepoint-event-reset.h>
static void lttng_ust_notrace __attribute__((constructor))
_TP_COMBINE_TOKENS(__lttng_events_init__, TRACEPOINT_PROVIDER)(void);
static void
_TP_COMBINE_TOKENS(__lttng_events_init__, TRACEPOINT_PROVIDER)(void)
{
	int ret;

	if (_TP_COMBINE_TOKENS(__probe_register_refcount___,
			TRACEPOINT_PROVIDER)++) {
		return;
	}
	/*
	 * __tracepoint_provider_check_ ## TRACEPOINT_PROVIDER() is a
	 * static inline function that ensures every probe PROVIDER
	 * argument match the provider within which they appear. It
	 * calls empty static inline functions, and therefore has no
	 * runtime effect. However, if it detects an error, a linker
	 * error will appear.
	 */
	_TP_COMBINE_TOKENS(__tracepoint_provider_check_, TRACEPOINT_PROVIDER)();
	ret = lttng_probe_register(&_TP_COMBINE_TOKENS(__probe_desc___, TRACEPOINT_PROVIDER));
	if (ret) {
		fprintf(stderr, "LTTng-UST: Error (%d) while registering tracepoint probe. Duplicate registration of tracepoint probes having the same name is not allowed.\n", ret);
		abort();
	}
}

static void lttng_ust_notrace __attribute__((destructor))
_TP_COMBINE_TOKENS(__lttng_events_exit__, TRACEPOINT_PROVIDER)(void);
static void
_TP_COMBINE_TOKENS(__lttng_events_exit__, TRACEPOINT_PROVIDER)(void)
{
	if (--_TP_COMBINE_TOKENS(__probe_register_refcount___,
			TRACEPOINT_PROVIDER)) {
		return;
	}
	lttng_probe_unregister(&_TP_COMBINE_TOKENS(__probe_desc___, TRACEPOINT_PROVIDER));
}

int _TP_COMBINE_TOKENS(__tracepoint_provider_, TRACEPOINT_PROVIDER);
