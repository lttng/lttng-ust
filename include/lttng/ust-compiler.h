/*
 * SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2011-2012 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 * Copyright (C) 2011-2012 Paul Woegerer <paul_woegerer@mentor.com>
 */

#ifndef _LTTNG_UST_COMPILER_H
#define _LTTNG_UST_COMPILER_H

#include <assert.h>

#define lttng_ust_notrace __attribute__((no_instrument_function))

/*
 * Clang supports the no_sanitize variable attribute on global variables.
 * GCC only supports the no_sanitize_address function attribute, which is
 * not what we need.
 */
#if defined(__clang__)
# if __has_feature(address_sanitizer)
#  define __lttng_ust_variable_attribute_no_sanitize_address \
	__attribute__((no_sanitize("address")))
# else
#  define __lttng_ust_variable_attribute_no_sanitize_address
# endif
#else
#  define __lttng_ust_variable_attribute_no_sanitize_address
#endif

/*
 * g++ 4.8 and prior do not support C99 compound literals. Therefore,
 * force allocating those on the heap with these C++ compilers.
 */
#if defined (__cplusplus) && !defined (__clang__) && defined (__GNUC__) && \
	((__GNUC__ < 4) || ((__GNUC__ == 4) && (__GNUC_MINOR__ <= 8)))
# ifndef LTTNG_UST_ALLOCATE_COMPOUND_LITERAL_ON_HEAP
#  define LTTNG_UST_ALLOCATE_COMPOUND_LITERAL_ON_HEAP
# endif
#endif

/*
 * Compound literals with static storage are needed by LTTng.
 * Compound literals are part of the C99 and C11 standards, but not
 * part of the C++ standards. However, those are supported by both g++ and
 * clang. In order to be strictly C++11 compliant, defining
 * LTTNG_UST_ALLOCATE_COMPOUND_LITERAL_ON_HEAP before including this header
 * allocates those on the heap in C++.
 *
 * Example use:
 * static struct mystruct *var = LTTNG_UST_COMPOUND_LITERAL(struct mystruct, { 1, 2, 3 });
 */
#if defined (__cplusplus) && defined (LTTNG_UST_ALLOCATE_COMPOUND_LITERAL_ON_HEAP)
#define LTTNG_UST_COMPOUND_LITERAL(type, ...)	new (type) __VA_ARGS__
#else
#define LTTNG_UST_COMPOUND_LITERAL(type, ...)	(type[]) { __VA_ARGS__ }
#endif

/*
 * Compile time assertion.
 * - predicate: boolean expression to evaluate,
 * - msg: string to print to the user on failure when `static_assert()` is
 *   supported,
 * - c_identifier_msg: message to be included in the typedef to emulate a
 *   static assertion. This parameter must be a valid C identifier as it will
 *   be used as a typedef name.
 */
#ifdef __cplusplus
#define lttng_ust_static_assert(predicate, msg, c_identifier_msg)  \
	static_assert(predicate, msg)
#elif __STDC_VERSION__ >= 201112L
#define lttng_ust_static_assert(predicate, msg, c_identifier_msg)  \
	_Static_assert(predicate, msg)
#else
/*
 * Evaluates the predicate and emit a compilation error on failure.
 *
 * If the predicate evaluates to true, this macro emits a typedef of an array
 * of size 0.
 *
 * If the predicate evaluates to false, this macro emits a typedef of an array
 * of negative size which is invalid in C and forces a compiler error. The msg
 * parameter is used in the tentative typedef so it is printed to the user.
 */
#define lttng_ust_static_assert(predicate, msg, c_identifier_msg)  \
    typedef char lttng_ust_static_assert_##c_identifier_msg[2*!!(predicate)-1]
#endif

/*
 * Wrap constructor and destructor functions to invoke them as functions with
 * the constructor/destructor GNU C attributes when building as C, or as the
 * constructor/destructor of a variable defined within an anonymous namespace
 * when building as C++.
 */
#ifdef __cplusplus
#define LTTNG_UST_DECLARE_CONSTRUCTOR_DESTRUCTOR(name, constructor_func,        \
						 destructor_func, ...)          \
namespace lttng {                                                               \
namespace ust {                                                                 \
namespace details {                                                             \
class LTTNG_UST__TP_COMBINE_TOKENS(lttng_ust_constructor_destructor_,           \
				   name) {                                      \
public:                                                                         \
	LTTNG_UST__TP_COMBINE_TOKENS(lttng_ust_constructor_destructor_,         \
				     name)() __VA_ARGS__        \
	{                                                                       \
		constructor_func();                                             \
	}                                                                       \
	~LTTNG_UST__TP_COMBINE_TOKENS(lttng_ust_constructor_destructor_,        \
                                      name)() __VA_ARGS__       \
	{                                                                       \
		destructor_func();                                              \
	}                                                                       \
};                                                                              \
}                                                                               \
}                                                                               \
}                                                                               \
                                                                                \
namespace {                                                                     \
const lttng::ust::details::LTTNG_UST__TP_COMBINE_TOKENS(                        \
	lttng_ust_constructor_destructor_, name)                                \
		LTTNG_UST__TP_COMBINE_TOKENS(name, registration_instance);      \
}
#else /* __cplusplus */
#define LTTNG_UST_DECLARE_CONSTRUCTOR_DESTRUCTOR(name, constructor_func,             \
						 destructor_func, ...)               \
	static void LTTNG_UST__TP_COMBINE_TOKENS(lttng_ust_constructor_, name)(void) \
		__attribute__((constructor)) __VA_ARGS__;            \
	static void LTTNG_UST__TP_COMBINE_TOKENS(lttng_ust_constructor_, name)(void) \
	{                                                                            \
		constructor_func();                                                  \
	}                                                                            \
	static void LTTNG_UST__TP_COMBINE_TOKENS(lttng_ust_destructor_, name)(void)  \
		__attribute__((destructor)) __VA_ARGS__;             \
	static void LTTNG_UST__TP_COMBINE_TOKENS(lttng_ust_destructor_, name)(void)  \
	{                                                                            \
		destructor_func();                                                   \
	}
#endif

#endif /* _LTTNG_UST_COMPILER_H */
