/*
 * SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2010-2011 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 */

#ifndef _LTTNG_UST_UTILS_H
#define _LTTNG_UST_UTILS_H

#include <stdio.h>
#include <stdlib.h>
#include <urcu/compiler.h>

/* For lttng_ust_is_integer_type */
#if defined (__cplusplus)
#include <type_traits>
#endif


/**
 * lttng_ust_stringify - convert a literal value to a C string
 */
#define __lttng_ust_stringify1(x)	#x
#define lttng_ust_stringify(x)	__lttng_ust_stringify1(x)

/**
 * lttng_ust_is_signed_type - check if type is signed
 *
 * Returns true if the type of @type is signed.
 */
#if defined(__cplusplus)
#define lttng_ust_is_signed_type(type)	(std::is_signed<type>::value)
#else
#define lttng_ust_is_signed_type(type)	((type) -1 < (type) 1)
#endif


/**
 * lttng_ust_is_integer_type - check if type is an integer
 *
 * Returns true if the type of @type is an integer.
 */
#if defined(__cplusplus)
#define lttng_ust_is_integer_type(type) (std::is_integral<type>::value)
#else
#define lttng_ust_is_integer_type(type) \
		(__builtin_types_compatible_p(type, _Bool) || \
		__builtin_types_compatible_p(type, char) || \
		__builtin_types_compatible_p(type, signed char) || \
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

/**
 * lttng_ust_field_array_element_type_is_supported -
 *
 * Adds a compilation assertion that array and sequence fields declared by the
 * user are of an integral type.
 */
#define lttng_ust_field_array_element_type_is_supported(type, item) \
		lttng_ust_static_assert(lttng_ust_is_integer_type(type), \
			"Non-integer type `" #item "` not supported as element of LTTNG_UST_FIELD_ARRAY or LTTNG_UST_FIELD_SEQUENCE", \
			Non_integer_type__##item##__not_supported_as_element_of_LTTNG_UST_FIELD_ARRAY_or_LTTNG_UST_FIELD_SEQUENCE)


/**
 * lttng_ust_runtime_bug_on - check condition at runtime
 * @condition: the condition which should be false.
 *
 * If the condition is true, a BUG will be triggered at runtime.
 */
#define lttng_ust_runtime_bug_on(condition)				\
	do {								\
		if (caa_unlikely(condition)) {				\
			fprintf(stderr,					\
				"LTTng BUG in file %s, line %d.\n",	\
				__FILE__, __LINE__);			\
			exit(EXIT_FAILURE);				\
		}							\
	} while (0)


/**
 * lttng_ust_build_bug_on - check condition at build
 * @condition: the condition which should be false.
 *
 * If the condition is true, the compiler will generate a build error.
 */
#define lttng_ust_build_bug_on(condition)			\
	((void) sizeof(char[-!!(condition)]))


/**
 * lttng_ust_build_runtime_bug_on - check condition at build (if constant) or runtime
 * @condition: the condition which should be false.
 *
 * If the condition is a constant and true, the compiler will generate a build
 * error. If the condition is not constant, a BUG will be triggered at runtime
 * if the condition is ever true. If the condition is constant and false, no
 * code is emitted.
 */
#define lttng_ust_build_runtime_bug_on(condition)		\
	do {							\
		if (__builtin_constant_p(condition))		\
			lttng_ust_build_bug_on(condition);	\
		else						\
			lttng_ust_runtime_bug_on(condition);	\
	} while (0)


/**
 * lttng_ust_offset_align - Calculate the offset needed to align an object on
 *                its natural alignment towards higher addresses.
 * @align_drift:  object offset from an "alignment"-aligned address.
 * @alignment:    natural object alignment. Must be non-zero, power of 2.
 *
 * Returns the offset that must be added to align towards higher
 * addresses.
 */
#define lttng_ust_offset_align(align_drift, alignment)			       \
	({								       \
		lttng_ust_build_runtime_bug_on((alignment) == 0		       \
				   || ((alignment) & ((alignment) - 1)));      \
		(((alignment) - (align_drift)) & ((alignment) - 1));	       \
	})


/**
 * lttng_ust_offset_align_floor - Calculate the offset needed to align an
 *                object on its natural alignment towards lower addresses.
 * @align_drift:  object offset from an "alignment"-aligned address.
 * @alignment:    natural object alignment. Must be non-zero, power of 2.
 *
 * Returns the offset that must be substracted to align towards lower addresses.
 */
#define lttng_ust_offset_align_floor(align_drift, alignment)		       \
	({								       \
		lttng_ust_build_runtime_bug_on((alignment) == 0		       \
				   || ((alignment) & ((alignment) - 1)));      \
		(((align_drift) - (alignment)) & ((alignment) - 1));	       \
	})

#endif /* _LTTNG_UST_UTILS_H */
