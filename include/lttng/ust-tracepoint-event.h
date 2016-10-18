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
#include <byteswap.h>
#include <string.h>

#define __LTTNG_UST_NULL_STRING	"(null)"

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
 * Stage 0.9 of tracepoint event generation
 *
 * Unfolding the enums
 */
#include <lttng/ust-tracepoint-event-reset.h>

/* Enumeration entry (single value) */
#undef ctf_enum_value
#define ctf_enum_value(_string, _value)					\
	{								\
		.start = {						\
			.value = lttng_is_signed_type(__typeof__(_value)) ? \
				(long long) (_value) : (_value),	\
			.signedness = lttng_is_signed_type(__typeof__(_value)), \
		},							\
		.end = {						\
			.value = lttng_is_signed_type(__typeof__(_value)) ? \
				(long long) (_value) : (_value),	\
			.signedness = lttng_is_signed_type(__typeof__(_value)), \
		},							\
		.string = (_string),					\
	},

/* Enumeration entry (range) */
#undef ctf_enum_range
#define ctf_enum_range(_string, _range_start, _range_end)		\
	{								\
		.start = {						\
			.value = lttng_is_signed_type(__typeof__(_range_start)) ? \
				(long long) (_range_start) : (_range_start), \
			.signedness = lttng_is_signed_type(__typeof__(_range_start)), \
		},							\
		.end = {						\
			.value = lttng_is_signed_type(__typeof__(_range_end)) ? \
				(long long) (_range_end) : (_range_end), \
			.signedness = lttng_is_signed_type(__typeof__(_range_end)), \
		},							\
		.string = (_string),					\
	},

/* Enumeration entry (automatic value; follows the rules of CTF) */
#undef ctf_enum_auto
#define ctf_enum_auto(_string)					\
	{								\
		.start = {						\
			.value = -1ULL, 				\
			.signedness = 0, 				\
		},							\
		.end = {						\
			.value = -1ULL,					\
			.signedness = 0, 				\
		},							\
		.string = (_string),					\
		.u = {							\
			.extra = {					\
				.options = LTTNG_ENUM_ENTRY_OPTION_IS_AUTO, \
			},						\
		},							\
	},

#undef TP_ENUM_VALUES
#define TP_ENUM_VALUES(...)						\
	__VA_ARGS__

#undef TRACEPOINT_ENUM
#define TRACEPOINT_ENUM(_provider, _name, _values)			\
	const struct lttng_enum_entry __enum_values__##_provider##_##_name[] = { \
		_values							\
		ctf_enum_value("", 0)	/* Dummy, 0-len array forbidden by C99. */ \
	};

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
#define _ctf_array_encoded(_type, _item, _src, _byte_order,	\
			_length, _encoding, _nowrite,		\
			_elem_type_base)			\
	{							\
	  .name = #_item,					\
	  .type =						\
		{						\
		  .atype = atype_array,				\
		  .u =						\
			{					\
			  .array =				\
				{				\
				  .elem_type = __type_integer(_type, _byte_order, _elem_type_base, _encoding), \
				  .length = _length,		\
				}				\
			}					\
		},						\
	  .nowrite = _nowrite,					\
	},

#undef _ctf_sequence_encoded
#define _ctf_sequence_encoded(_type, _item, _src, _byte_order,	\
			_length_type, _src_length, _encoding, _nowrite, \
			_elem_type_base)			\
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
				  .elem_type = __type_integer(_type, _byte_order, _elem_type_base, _encoding), \
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

#undef _ctf_enum
#define _ctf_enum(_provider, _name, _type, _item, _src, _nowrite) \
	{							\
		.name = #_item,					\
		.type = {					\
			.atype = atype_enum,			\
			.u = {					\
				.basic = {			\
					.enumeration = {	\
						.desc = &__enum_##_provider##_##_name, \
						.container_type = { \
							.size = sizeof(_type) * CHAR_BIT, \
							.alignment = lttng_alignof(_type) * CHAR_BIT, \
							.signedness = lttng_is_signed_type(_type), \
							.reverse_byte_order = 0, \
							.base = 10, \
							.encoding = lttng_encode_none, \
						},		\
					},			\
				 },				\
			},					\
		},						\
		.nowrite = _nowrite,				\
	},

#undef TP_FIELDS
#define TP_FIELDS(...) __VA_ARGS__	/* Only one used in this phase */

#undef TRACEPOINT_EVENT_CLASS
#define TRACEPOINT_EVENT_CLASS(_provider, _name, _args, _fields)		   	     \
	static const struct lttng_event_field __event_fields___##_provider##___##_name[] = { \
		_fields									     \
		ctf_integer(int, dummy, 0)	/* Dummy, C99 forbids 0-len array. */	     \
	};

#undef TRACEPOINT_ENUM
#define TRACEPOINT_ENUM(_provider, _name, _values)					\
	static const struct lttng_enum_desc __enum_##_provider##_##_name = {		\
		.name = #_provider "_" #_name,						\
		.entries = __enum_values__##_provider##_##_name,			\
		.nr_entries = _TP_ARRAY_SIZE(__enum_values__##_provider##_##_name) - 1,	\
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
 * Stage 3.0 of tracepoint event generation.
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
#define _ctf_array_encoded(_type, _item, _src, _byte_order, _length, _encoding,	 \
			_nowrite, _elem_type_base)				 \
	__event_len += lib_ring_buffer_align(__event_len, lttng_alignof(_type)); \
	__event_len += sizeof(_type) * (_length);

#undef _ctf_sequence_encoded
#define _ctf_sequence_encoded(_type, _item, _src, _byte_order, _length_type,	 \
			_src_length, _encoding, _nowrite, _elem_type_base)	 \
	__event_len += lib_ring_buffer_align(__event_len, lttng_alignof(_length_type));   \
	__event_len += sizeof(_length_type);				       \
	__event_len += lib_ring_buffer_align(__event_len, lttng_alignof(_type)); \
	__dynamic_len[__dynamic_len_idx] = (_src_length);		       \
	__event_len += sizeof(_type) * __dynamic_len[__dynamic_len_idx];       \
	__dynamic_len_idx++;

#undef _ctf_string
#define _ctf_string(_item, _src, _nowrite)				       \
	__event_len += __dynamic_len[__dynamic_len_idx++] =		       \
		strlen((_src) ? (_src) : __LTTNG_UST_NULL_STRING) + 1;

#undef _ctf_enum
#define _ctf_enum(_provider, _name, _type, _item, _src, _nowrite)		\
	_ctf_integer_ext(_type, _item, _src, BYTE_ORDER, 10, _nowrite)

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
			if (_byte_order != BYTE_ORDER)			       \
				__tmp.v = bswap_16(__tmp.v);		       \
			__ctf_tmp_int64 = (int64_t) __tmp.v;		       \
			break;						       \
		}							       \
		case 4:							       \
		{							       \
			union { _type t; int32_t v; } __tmp = { (_type) (_src) }; \
			if (_byte_order != BYTE_ORDER)			       \
				__tmp.v = bswap_32(__tmp.v);		       \
			__ctf_tmp_int64 = (int64_t) __tmp.v;		       \
			break;						       \
		}							       \
		case 8:							       \
		{							       \
			union { _type t; int64_t v; } __tmp = { (_type) (_src) }; \
			if (_byte_order != BYTE_ORDER)			       \
				__tmp.v = bswap_64(__tmp.v);		       \
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
			if (_byte_order != BYTE_ORDER)			       \
				__tmp.v = bswap_16(__tmp.v);		       \
			__ctf_tmp_uint64 = (uint64_t) __tmp.v;		       \
			break;						       \
		}							       \
		case 4:							       \
		{							       \
			union { _type t; uint32_t v; } __tmp = { (_type) (_src) }; \
			if (_byte_order != BYTE_ORDER)			       \
				__tmp.v = bswap_32(__tmp.v);		       \
			__ctf_tmp_uint64 = (uint64_t) __tmp.v;		       \
			break;						       \
		}							       \
		case 8:							       \
		{							       \
			union { _type t; uint64_t v; } __tmp = { (_type) (_src) }; \
			if (_byte_order != BYTE_ORDER)			       \
				__tmp.v = bswap_64(__tmp.v);		       \
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
#define _ctf_array_encoded(_type, _item, _src, _byte_order, _length,	       \
			_encoding, _nowrite, _elem_type_base)		       \
	{								       \
		unsigned long __ctf_tmp_ulong = (unsigned long) (_length);     \
		const void *__ctf_tmp_ptr = (_src);			       \
		memcpy(__stack_data, &__ctf_tmp_ulong, sizeof(unsigned long)); \
		__stack_data += sizeof(unsigned long);			       \
		memcpy(__stack_data, &__ctf_tmp_ptr, sizeof(void *));	       \
		__stack_data += sizeof(void *);				       \
	}

#undef _ctf_sequence_encoded
#define _ctf_sequence_encoded(_type, _item, _src, _byte_order, _length_type,   \
			_src_length, _encoding, _nowrite, _elem_type_base)     \
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
		const void *__ctf_tmp_ptr =				       \
			((_src) ? (_src) : __LTTNG_UST_NULL_STRING);	       \
		memcpy(__stack_data, &__ctf_tmp_ptr, sizeof(void *));	       \
		__stack_data += sizeof(void *);				       \
	}

#undef _ctf_enum
#define _ctf_enum(_provider, _name, _type, _item, _src, _nowrite)		\
	_ctf_integer_ext(_type, _item, _src, BYTE_ORDER, 10, _nowrite)

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
#define _ctf_array_encoded(_type, _item, _src, _byte_order, _length,	       \
			_encoding, _nowrite, _elem_type_base)		       \
	__event_align = _tp_max_t(size_t, __event_align, lttng_alignof(_type));

#undef _ctf_sequence_encoded
#define _ctf_sequence_encoded(_type, _item, _src, _byte_order, _length_type,   \
			_src_length, _encoding, _nowrite, _elem_type_base)     \
	__event_align = _tp_max_t(size_t, __event_align, lttng_alignof(_length_type));	  \
	__event_align = _tp_max_t(size_t, __event_align, lttng_alignof(_type));

#undef _ctf_string
#define _ctf_string(_item, _src, _nowrite)

#undef _ctf_enum
#define _ctf_enum(_provider, _name, _type, _item, _src, _nowrite)		\
	_ctf_integer_ext(_type, _item, _src, BYTE_ORDER, 10, _nowrite)

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
#define _ctf_array_encoded(_type, _item, _src, _byte_order, _length,	\
			_encoding, _nowrite, _elem_type_base)		\
	lib_ring_buffer_align_ctx(&__ctx, lttng_alignof(_type));	\
	__chan->ops->event_write(&__ctx, _src, sizeof(_type) * (_length));

#undef _ctf_sequence_encoded
#define _ctf_sequence_encoded(_type, _item, _src, _byte_order, _length_type, \
			_src_length, _encoding, _nowrite, _elem_type_base) \
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
	{									\
		const char *__ctf_tmp_string =					\
			((_src) ? (_src) : __LTTNG_UST_NULL_STRING);		\
		lib_ring_buffer_align_ctx(&__ctx,				\
			lttng_alignof(*__ctf_tmp_string));			\
		if (__chan->ops->u.has_strcpy)					\
			__chan->ops->event_strcpy(&__ctx, __ctf_tmp_string,	\
				__get_dynamic_len(dest));			\
		else								\
			__chan->ops->event_write(&__ctx, __ctf_tmp_string,	\
				__get_dynamic_len(dest));			\
	}


#undef _ctf_enum
#define _ctf_enum(_provider, _name, _type, _item, _src, _nowrite)	\
	_ctf_integer_ext(_type, _item, _src, BYTE_ORDER, 10, _nowrite)

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
 * Use of __builtin_return_address(0) sometimes seems to cause stack
 * corruption on 32-bit PowerPC. Disable this feature on that
 * architecture for now by always using the NULL value for the ip
 * context.
 */
#undef _TP_IP_PARAM
#ifdef TP_IP_PARAM
#define _TP_IP_PARAM(x)		(x)
#else /* TP_IP_PARAM */

#if defined(__PPC__) && !defined(__PPC64__)
#define _TP_IP_PARAM(x)		NULL
#else /* #if defined(__PPC__) && !defined(__PPC64__) */
#define _TP_IP_PARAM(x)		__builtin_return_address(0)
#endif /* #else #if defined(__PPC__) && !defined(__PPC64__) */

#endif /* TP_IP_PARAM */

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
	struct lttng_event *__event = (struct lttng_event *) __tp_data;	      \
	struct lttng_channel *__chan = __event->chan;			      \
	struct lttng_ust_lib_ring_buffer_ctx __ctx;			      \
	struct lttng_stack_ctx __lttng_ctx;				      \
	size_t __event_len, __event_align;				      \
	size_t __dynamic_len_idx = 0;					      \
	union {								      \
		size_t __dynamic_len[_TP_ARRAY_SIZE(__event_fields___##_provider##___##_name) - 1]; \
		char __filter_stack_data[2 * sizeof(unsigned long) * (_TP_ARRAY_SIZE(__event_fields___##_provider##___##_name) - 1)]; \
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
	memset(&__lttng_ctx, 0, sizeof(__lttng_ctx));			      \
	__lttng_ctx.event = __event;					      \
	__lttng_ctx.chan_ctx = tp_rcu_dereference_bp(__chan->ctx);	      \
	__lttng_ctx.event_ctx = tp_rcu_dereference_bp(__event->ctx);	      \
	lib_ring_buffer_ctx_init(&__ctx, __chan->chan, __event, __event_len,  \
				 __event_align, -1, __chan->handle, &__lttng_ctx); \
	__ctx.ip = _TP_IP_PARAM(TP_IP_PARAM);				      \
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
static const char __tp_event_signature___##_provider##___##_name[] = 	\
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

/*
 * Declare _loglevel___##__provider##___##__name as non-static, with
 * hidden visibility for c++ handling of weakref. We do a weakref to the
 * symbol in a later stage, which requires that the symbol is not
 * mangled.
 */
#ifdef __cplusplus
#define LTTNG_TP_EXTERN_C extern "C"
#else
#define LTTNG_TP_EXTERN_C
#endif

#undef TRACEPOINT_LOGLEVEL
#define TRACEPOINT_LOGLEVEL(__provider, __name, __loglevel)		   \
static const int _loglevel_value___##__provider##___##__name = __loglevel; \
LTTNG_TP_EXTERN_C const int *_loglevel___##__provider##___##__name	   \
		__attribute__((visibility("hidden"))) =			   \
		&_loglevel_value___##__provider##___##__name;

#include TRACEPOINT_INCLUDE

#undef LTTNG_TP_EXTERN_C

/*
 * Stage 6.1 of tracepoint event generation.
 *
 * Tracepoint UML URI info.
 */

/* Reset all macros within TRACEPOINT_EVENT */
#include <lttng/ust-tracepoint-event-reset.h>

/*
 * Declare _model_emf_uri___##__provider##___##__name as non-static,
 * with hidden visibility for c++ handling of weakref. We do a weakref
 * to the symbol in a later stage, which requires that the symbol is not
 * mangled.
 */
#ifdef __cplusplus
#define LTTNG_TP_EXTERN_C extern "C"
#else
#define LTTNG_TP_EXTERN_C
#endif

#undef TRACEPOINT_MODEL_EMF_URI
#define TRACEPOINT_MODEL_EMF_URI(__provider, __name, __uri)		   \
LTTNG_TP_EXTERN_C const char *_model_emf_uri___##__provider##___##__name   \
		__attribute__((visibility("hidden"))) = __uri;		   \

#include TRACEPOINT_INCLUDE

#undef LTTNG_TP_EXTERN_C

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
static const struct lttng_event_desc __event_desc___##_provider##_##_name = {	       \
	.name = #_provider ":" #_name,					       \
	.probe_callback = (void (*)(void)) &__event_probe__##_provider##___##_template,\
	.ctx = NULL,							       \
	.fields = __event_fields___##_provider##___##_template,		       \
	.nr_fields = _TP_ARRAY_SIZE(__event_fields___##_provider##___##_template) - 1, \
	.loglevel = &__ref_loglevel___##_provider##___##_name,		       \
	.signature = __tp_event_signature___##_provider##___##_template,       \
	.u = {								       \
	    .ext = {							       \
		  .model_emf_uri = &__ref_model_emf_uri___##_provider##___##_name, \
		},							       \
	},								       \
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
	NULL,	/* Dummy, C99 forbids 0-len array. */
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
	.nr_events = _TP_ARRAY_SIZE(_TP_COMBINE_TOKENS(__event_desc___, TRACEPOINT_PROVIDER)) - 1,
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
