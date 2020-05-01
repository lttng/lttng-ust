/*
 * SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2005-2012 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 *
 * This contains the core definitions for the Linux Trace Toolkit.
 */

#ifndef _LTTNG_UST_TRACER_H
#define _LTTNG_UST_TRACER_H

#include <limits.h>

#if defined (__cplusplus)
#include <type_traits>
#endif

#include <lttng/ust-compiler.h>
#include <lttng/ust-config.h>
#include <lttng/ust-version.h>

#ifndef LTTNG_UST_HAVE_EFFICIENT_UNALIGNED_ACCESS
/* Align data on its natural alignment */
#define RING_BUFFER_ALIGN
#endif

#ifndef CHAR_BIT
#define CHAR_BIT 8
#endif

#ifdef RING_BUFFER_ALIGN
#define lttng_alignof(type)	__alignof__(type)
#else
#define lttng_alignof(type)	1
#endif

#define lttng_is_signed_type(type)           ((type) -1 < (type) 0)

/*
 * This macro adds a compilation assertion that CTF arrays and sequences
 * declared by the users are of an integral type.
 */

#if defined(__cplusplus)
#define _lttng_is_integer(type) (std::is_integral<type>::value)
#else
#define _lttng_is_integer(type) (__builtin_types_compatible_p(type, _Bool) || \
		__builtin_types_compatible_p(type, char) || \
		__builtin_types_compatible_p(type, unsigned char) || \
		__builtin_types_compatible_p(type, short) || \
		__builtin_types_compatible_p(type, unsigned short) || \
		__builtin_types_compatible_p(type, int) || \
		__builtin_types_compatible_p(type, unsigned int) || \
		__builtin_types_compatible_p(type, long) || \
		__builtin_types_compatible_p(type, unsigned long) || \
		__builtin_types_compatible_p(type, long long) || \
		__builtin_types_compatible_p(type, unsigned long long))
#endif

#define _lttng_array_element_type_is_supported(_type, _item) \
		lttng_static_assert(_lttng_is_integer(_type), \
			"Non-integer type `" #_item "` not supported as element of CTF_ARRAY or CTF_SEQUENCE", \
			Non_integer_type__##_item##__not_supported_as_element_of_CTF_ARRAY_or_CTF_SEQUENCE);

#endif /* _LTTNG_UST_TRACER_H */
