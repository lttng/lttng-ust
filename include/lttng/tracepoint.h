// SPDX-FileCopyrightText: 2011-2012 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
//
// SPDX-License-Identifier: MIT

#ifndef _LTTNG_UST_TRACEPOINT_H
#define _LTTNG_UST_TRACEPOINT_H

#include <stdio.h>
#include <stdlib.h>
#include <lttng/tracepoint-types.h>
#include <lttng/tracepoint-rcu.h>
#include <lttng/ust-utils.h>
#include <sys/types.h>
#include <unistd.h>

#include <urcu/compiler.h>
#include <urcu/system.h>
#include <dlfcn.h>	/* for dlopen */
#include <string.h>	/* for memset */
#include <stdbool.h>

#include <lttng/ust-config.h>	/* for sdt */
#include <lttng/ust-compiler.h>
#include <lttng/ust-tracer.h>
#include <lttng/ust-api-compat.h>

#if (defined(__cplusplus) && (__cplusplus <= 199711L))
#error "C++11 support is required to build tracepoints and providers as C++"
#endif

#define LTTNG_UST_TRACEPOINT_NAME_LEN_MAX	256

#ifdef LTTNG_UST_HAVE_SDT_INTEGRATION
/*
 * Instead of using SDT_USE_VARIADIC from 'sys/sdt.h', use our own namespaced
 * macros since the instrumented application might already have included
 * 'sys/sdt.h' without variadic support.
 */
#include <sys/sdt.h>

#define LTTNG_UST__SDT_NARG(...) \
	LTTNG_UST___SDT_NARG(__VA_ARGS__, 12,11,10,9,8,7,6,5,4,3,2,1,0)

#define LTTNG_UST___SDT_NARG(_0,_1,_2,_3,_4,_5,_6,_7,_8,_9,_10,_11,_12, N, ...) N

#define LTTNG_UST__SDT_PROBE_N(provider, name, N, ...) \
	_SDT_PROBE(provider, name, N, (__VA_ARGS__))

#define LTTNG_UST_STAP_PROBEV(provider, name, ...) \
	LTTNG_UST__SDT_PROBE_N(provider, name, LTTNG_UST__SDT_NARG(0, ##__VA_ARGS__), ##__VA_ARGS__)

#else
#define LTTNG_UST_STAP_PROBEV(...)
#endif

#ifdef __cplusplus
extern "C" {
#endif

#define lttng_ust_tracepoint_enabled(provider, name)				\
	caa_unlikely(CMM_LOAD_SHARED(lttng_ust_tracepoint_##provider##___##name.state))

#define lttng_ust_do_tracepoint(provider, name, ...)				\
	lttng_ust_tracepoint_cb_##provider##___##name(__VA_ARGS__)

#define lttng_ust_tracepoint(provider, name, ...)				\
	do {									\
		LTTNG_UST_STAP_PROBEV(provider, name, ## __VA_ARGS__);		\
		if (lttng_ust_tracepoint_enabled(provider, name))		\
			lttng_ust_do_tracepoint(provider, name, __VA_ARGS__);	\
	} while (0)

#define LTTNG_UST_TP_ARGS(...)       __VA_ARGS__

/*
 * LTTNG_UST_TP_ARGS takes tuples of type, argument separated by a comma.
 * It can take up to 10 tuples (which means that less than 10 tuples is
 * fine too).
 * Each tuple is also separated by a comma.
 */
#define LTTNG_UST___TP_COMBINE_TOKENS(_tokena, _tokenb)				\
		_tokena##_tokenb
#define LTTNG_UST__TP_COMBINE_TOKENS(_tokena, _tokenb)				\
		LTTNG_UST___TP_COMBINE_TOKENS(_tokena, _tokenb)
#define LTTNG_UST___TP_COMBINE_TOKENS3(_tokena, _tokenb, _tokenc)			\
		_tokena##_tokenb##_tokenc
#define LTTNG_UST__TP_COMBINE_TOKENS3(_tokena, _tokenb, _tokenc)			\
		LTTNG_UST___TP_COMBINE_TOKENS3(_tokena, _tokenb, _tokenc)
#define LTTNG_UST___TP_COMBINE_TOKENS4(_tokena, _tokenb, _tokenc, _tokend)	\
		_tokena##_tokenb##_tokenc##_tokend
#define LTTNG_UST__TP_COMBINE_TOKENS4(_tokena, _tokenb, _tokenc, _tokend)		\
		LTTNG_UST___TP_COMBINE_TOKENS4(_tokena, _tokenb, _tokenc, _tokend)

/*
 * LTTNG_UST__TP_EXVAR* extract the var names.
 * LTTNG_UST__TP_EXVAR1 and LTTNG_UST__TP_EXDATA_VAR1 are needed for -std=c99.
 */
#define LTTNG_UST__TP_EXVAR0()
#define LTTNG_UST__TP_EXVAR1(a)
#define LTTNG_UST__TP_EXVAR2(a,b)						b
#define LTTNG_UST__TP_EXVAR4(a,b,c,d)					b,d
#define LTTNG_UST__TP_EXVAR6(a,b,c,d,e,f)					b,d,f
#define LTTNG_UST__TP_EXVAR8(a,b,c,d,e,f,g,h)				b,d,f,h
#define LTTNG_UST__TP_EXVAR10(a,b,c,d,e,f,g,h,i,j)			b,d,f,h,j
#define LTTNG_UST__TP_EXVAR12(a,b,c,d,e,f,g,h,i,j,k,l)			b,d,f,h,j,l
#define LTTNG_UST__TP_EXVAR14(a,b,c,d,e,f,g,h,i,j,k,l,m,n)		b,d,f,h,j,l,n
#define LTTNG_UST__TP_EXVAR16(a,b,c,d,e,f,g,h,i,j,k,l,m,n,o,p)		b,d,f,h,j,l,n,p
#define LTTNG_UST__TP_EXVAR18(a,b,c,d,e,f,g,h,i,j,k,l,m,n,o,p,q,r)	b,d,f,h,j,l,n,p,r
#define LTTNG_UST__TP_EXVAR20(a,b,c,d,e,f,g,h,i,j,k,l,m,n,o,p,q,r,s,t)	b,d,f,h,j,l,n,p,r,t

#define LTTNG_UST__TP_EXDATA_VAR0()						__tp_data
#define LTTNG_UST__TP_EXDATA_VAR1(a)						__tp_data
#define LTTNG_UST__TP_EXDATA_VAR2(a,b)						__tp_data,b
#define LTTNG_UST__TP_EXDATA_VAR4(a,b,c,d)					__tp_data,b,d
#define LTTNG_UST__TP_EXDATA_VAR6(a,b,c,d,e,f)					__tp_data,b,d,f
#define LTTNG_UST__TP_EXDATA_VAR8(a,b,c,d,e,f,g,h)				__tp_data,b,d,f,h
#define LTTNG_UST__TP_EXDATA_VAR10(a,b,c,d,e,f,g,h,i,j)				__tp_data,b,d,f,h,j
#define LTTNG_UST__TP_EXDATA_VAR12(a,b,c,d,e,f,g,h,i,j,k,l)			__tp_data,b,d,f,h,j,l
#define LTTNG_UST__TP_EXDATA_VAR14(a,b,c,d,e,f,g,h,i,j,k,l,m,n)			__tp_data,b,d,f,h,j,l,n
#define LTTNG_UST__TP_EXDATA_VAR16(a,b,c,d,e,f,g,h,i,j,k,l,m,n,o,p)		__tp_data,b,d,f,h,j,l,n,p
#define LTTNG_UST__TP_EXDATA_VAR18(a,b,c,d,e,f,g,h,i,j,k,l,m,n,o,p,q,r)		__tp_data,b,d,f,h,j,l,n,p,r
#define LTTNG_UST__TP_EXDATA_VAR20(a,b,c,d,e,f,g,h,i,j,k,l,m,n,o,p,q,r,s,t)	__tp_data,b,d,f,h,j,l,n,p,r,t

/*
 * LTTNG_UST__TP_EXPROTO* extract tuples of type, var.
 * LTTNG_UST__TP_EXPROTO1 and LTTNG_UST__TP_EXDATA_PROTO1 are needed for -std=c99.
 */
#define LTTNG_UST__TP_EXPROTO0()						void
#define LTTNG_UST__TP_EXPROTO1(a)						void
#define LTTNG_UST__TP_EXPROTO2(a,b)					a b
#define LTTNG_UST__TP_EXPROTO4(a,b,c,d)					a b,c d
#define LTTNG_UST__TP_EXPROTO6(a,b,c,d,e,f)				a b,c d,e f
#define LTTNG_UST__TP_EXPROTO8(a,b,c,d,e,f,g,h)				a b,c d,e f,g h
#define LTTNG_UST__TP_EXPROTO10(a,b,c,d,e,f,g,h,i,j)			a b,c d,e f,g h,i j
#define LTTNG_UST__TP_EXPROTO12(a,b,c,d,e,f,g,h,i,j,k,l)			a b,c d,e f,g h,i j,k l
#define LTTNG_UST__TP_EXPROTO14(a,b,c,d,e,f,g,h,i,j,k,l,m,n)		a b,c d,e f,g h,i j,k l,m n
#define LTTNG_UST__TP_EXPROTO16(a,b,c,d,e,f,g,h,i,j,k,l,m,n,o,p)		a b,c d,e f,g h,i j,k l,m n,o p
#define LTTNG_UST__TP_EXPROTO18(a,b,c,d,e,f,g,h,i,j,k,l,m,n,o,p,q,r)	a b,c d,e f,g h,i j,k l,m n,o p,q r
#define LTTNG_UST__TP_EXPROTO20(a,b,c,d,e,f,g,h,i,j,k,l,m,n,o,p,q,r,s,t)	a b,c d,e f,g h,i j,k l,m n,o p,q r,s t

#define LTTNG_UST__TP_EXDATA_PROTO0()						void *__tp_data
#define LTTNG_UST__TP_EXDATA_PROTO1(a)						void *__tp_data
#define LTTNG_UST__TP_EXDATA_PROTO2(a,b)						void *__tp_data,a b
#define LTTNG_UST__TP_EXDATA_PROTO4(a,b,c,d)					void *__tp_data,a b,c d
#define LTTNG_UST__TP_EXDATA_PROTO6(a,b,c,d,e,f)					void *__tp_data,a b,c d,e f
#define LTTNG_UST__TP_EXDATA_PROTO8(a,b,c,d,e,f,g,h)				void *__tp_data,a b,c d,e f,g h
#define LTTNG_UST__TP_EXDATA_PROTO10(a,b,c,d,e,f,g,h,i,j)				void *__tp_data,a b,c d,e f,g h,i j
#define LTTNG_UST__TP_EXDATA_PROTO12(a,b,c,d,e,f,g,h,i,j,k,l)			void *__tp_data,a b,c d,e f,g h,i j,k l
#define LTTNG_UST__TP_EXDATA_PROTO14(a,b,c,d,e,f,g,h,i,j,k,l,m,n)			void *__tp_data,a b,c d,e f,g h,i j,k l,m n
#define LTTNG_UST__TP_EXDATA_PROTO16(a,b,c,d,e,f,g,h,i,j,k,l,m,n,o,p)		void *__tp_data,a b,c d,e f,g h,i j,k l,m n,o p
#define LTTNG_UST__TP_EXDATA_PROTO18(a,b,c,d,e,f,g,h,i,j,k,l,m,n,o,p,q,r)		void *__tp_data,a b,c d,e f,g h,i j,k l,m n,o p,q r
#define LTTNG_UST__TP_EXDATA_PROTO20(a,b,c,d,e,f,g,h,i,j,k,l,m,n,o,p,q,r,s,t)	void *__tp_data,a b,c d,e f,g h,i j,k l,m n,o p,q r,s t

/* Preprocessor trick to count arguments. Inspired from sdt.h. */
#define LTTNG_UST__TP_NARGS(...)		LTTNG_UST___TP_NARGS(__VA_ARGS__, 20,19,18,17,16,15,14,13,12,11,10,9,8,7,6,5,4,3,2,1,0)
#define LTTNG_UST___TP_NARGS(_0,_1,_2,_3,_4,_5,_6,_7,_8,_9,_10,_11,_12,_13,_14,_15,_16,_17,_18,_19,_20, N, ...)	N
#define LTTNG_UST__TP_PROTO_N(N, ...)		LTTNG_UST__TP_PARAMS(LTTNG_UST__TP_COMBINE_TOKENS(LTTNG_UST__TP_EXPROTO, N)(__VA_ARGS__))
#define LTTNG_UST__TP_VAR_N(N, ...)		LTTNG_UST__TP_PARAMS(LTTNG_UST__TP_COMBINE_TOKENS(LTTNG_UST__TP_EXVAR, N)(__VA_ARGS__))
#define LTTNG_UST__TP_DATA_PROTO_N(N, ...)	LTTNG_UST__TP_PARAMS(LTTNG_UST__TP_COMBINE_TOKENS(LTTNG_UST__TP_EXDATA_PROTO, N)(__VA_ARGS__))
#define LTTNG_UST__TP_DATA_VAR_N(N, ...)	LTTNG_UST__TP_PARAMS(LTTNG_UST__TP_COMBINE_TOKENS(LTTNG_UST__TP_EXDATA_VAR, N)(__VA_ARGS__))
#define LTTNG_UST__TP_ARGS_PROTO(...)		LTTNG_UST__TP_PROTO_N(LTTNG_UST__TP_NARGS(0, ##__VA_ARGS__), ##__VA_ARGS__)
#define LTTNG_UST__TP_ARGS_VAR(...)		LTTNG_UST__TP_VAR_N(LTTNG_UST__TP_NARGS(0, ##__VA_ARGS__), ##__VA_ARGS__)
#define LTTNG_UST__TP_ARGS_DATA_PROTO(...)	LTTNG_UST__TP_DATA_PROTO_N(LTTNG_UST__TP_NARGS(0, ##__VA_ARGS__), ##__VA_ARGS__)
#define LTTNG_UST__TP_ARGS_DATA_VAR(...)	LTTNG_UST__TP_DATA_VAR_N(LTTNG_UST__TP_NARGS(0, ##__VA_ARGS__), ##__VA_ARGS__)
#define LTTNG_UST__TP_PARAMS(...)		__VA_ARGS__

/*
 * sizeof(#_provider) - 1 : length of the provider string (excluding \0).
 * sizeof(#_name) - 1     : length of the name string (excluding \0).
 * + 1                    : separator between provider and event name.
 *
 * Upper bound (inclusive) is LTTNG_UST_TRACEPOINT_NAME_LEN_MAX - 1 to
 * account for \0.
 *
 * The comparison is:
 *   left hand side:   sizeof(#_provider) - 1 + sizeof(#_name) - 1 + 1
 *   right hand side:  LTTNG_UST_TRACEPOINT_NAME_LEN_MAX - 1
 *   operator:         <=  (inclusive)
 * Simplified in the code below.
 */
#define lttng_ust_tracepoint_validate_name_len(_provider, _name)						\
	lttng_ust_static_assert(sizeof(#_provider) + sizeof(#_name) <= LTTNG_UST_TRACEPOINT_NAME_LEN_MAX,	\
		"Tracepoint name length is too long",								\
		Tracepoint_name_length_is_too_long)

/*
 * The tracepoint cb is marked always inline so we can distinguish
 * between caller's ip addresses within the probe using the return
 * address.
 */
#define LTTNG_UST__DECLARE_TRACEPOINT(_provider, _name, ...)			 		\
extern struct lttng_ust_tracepoint lttng_ust_tracepoint_##_provider##___##_name		\
		LTTNG_UST__TRACEPOINT_DEFINITION_VISIBILITY;				\
static inline										\
void lttng_ust_tracepoint_cb_##_provider##___##_name(LTTNG_UST__TP_ARGS_PROTO(__VA_ARGS__))		\
	__attribute__((always_inline, unused)) lttng_ust_notrace;			\
static											\
void lttng_ust_tracepoint_cb_##_provider##___##_name(LTTNG_UST__TP_ARGS_PROTO(__VA_ARGS__))		\
{											\
	struct lttng_ust_tracepoint_probe *__tp_probe;					\
											\
	if (caa_unlikely(!LTTNG_UST_TP_RCU_LINK_TEST()))						\
		return;									\
	lttng_ust_tp_rcu_read_lock();								\
	__tp_probe = lttng_ust_tp_rcu_dereference(lttng_ust_tracepoint_##_provider##___##_name.probes);	\
	if (caa_unlikely(!__tp_probe))							\
		goto end;								\
	do {										\
		void (*__tp_cb)(void) = __tp_probe->func;				\
		void *__tp_data = __tp_probe->data;					\
											\
		URCU_FORCE_CAST(void (*)(LTTNG_UST__TP_ARGS_DATA_PROTO(__VA_ARGS__)), __tp_cb)	\
				(LTTNG_UST__TP_ARGS_DATA_VAR(__VA_ARGS__));			\
	} while ((++__tp_probe)->func);							\
end:											\
	lttng_ust_tp_rcu_read_unlock();								\
}											\
static inline										\
void lttng_ust_tracepoint_register_##_provider##___##_name(char *provider_name, char *event_name, \
		void (*func)(void), void *data)						\
	lttng_ust_notrace;								\
static inline										\
void lttng_ust_tracepoint_register_##_provider##___##_name(char *provider_name, char *event_name, \
		void (*func)(void), void *data)						\
{											\
	lttng_ust_tracepoint_provider_register(provider_name, event_name, func, data,		\
		lttng_ust_tracepoint_##_provider##___##_name.signature);			\
}											\
static inline										\
void lttng_ust_tracepoint_unregister_##_provider##___##_name(char *provider_name, char *event_name, \
		void (*func)(void), void *data)						\
	lttng_ust_notrace;								\
static inline										\
void lttng_ust_tracepoint_unregister_##_provider##___##_name(char *provider_name, char *event_name, \
		void (*func)(void), void *data)						\
{											\
	lttng_ust_tracepoint_provider_unregister(provider_name, event_name, func, data);		\
}

/*
 * Registration of tracepoint provider probe functions with
 * lttng_ust_tracepoint_provider_register, unregistration with
 * lttng_ust_tracepoint_provider_unregister.
 */
int lttng_ust_tracepoint_provider_register(const char *provider_name, const char *event_name,
		void (*func)(void), void *data, const char *signature);
int lttng_ust_tracepoint_provider_unregister(const char *provider_name, const char *event_name,
		void (*func)(void), void *data);

/*
 * Registration of tracepoint instrumentation modules with lttng_ust_tracepoint_module_register,
 * unregistration with lttng_ust_tracepoint_module_unregister.
 */
int lttng_ust_tracepoint_module_register(struct lttng_ust_tracepoint * const *tracepoints_start,
                             int tracepoints_count);
int lttng_ust_tracepoint_module_unregister(struct lttng_ust_tracepoint * const *tracepoints_start);

/*
 * tracepoint dynamic linkage handling (callbacks). Hidden visibility:
 * shared across objects in a module/main executable.
 *
 * IMPORTANT: this structure is part of the ABI between instrumented
 * applications and UST. Fields need to be only added at the end, never
 * reordered, never removed.
 *
 * The field @struct_size should be used to determine the size of the
 * structure. It should be queried before using additional fields added
 * at the end of the structure.
 */
struct lttng_ust_tracepoint_dlopen {
	uint32_t struct_size;

	void *liblttngust_handle;

	int (*lttng_ust_tracepoint_module_register)(struct lttng_ust_tracepoint * const *tracepoints_start,
		int tracepoints_count);
	int (*lttng_ust_tracepoint_module_unregister)(struct lttng_ust_tracepoint * const *tracepoints_start);
	void (*rcu_read_lock_sym)(void);
	void (*rcu_read_unlock_sym)(void);
	void *(*rcu_dereference_sym)(void *p);

	/* End of base ABI. Fields below should be used after checking struct_size. */
};

extern struct lttng_ust_tracepoint_dlopen lttng_ust_tracepoint_dlopen;
extern struct lttng_ust_tracepoint_dlopen *lttng_ust_tracepoint_dlopen_ptr;

/*
 * These weak symbols, the constructor, and destructor take care of
 * registering only _one_ instance of the tracepoints per shared-ojbect
 * (or for the whole main program).
 */
int lttng_ust_tracepoint_registered
	__attribute__((weak, visibility("hidden")));
int lttng_ust_tracepoint_ptrs_registered
	__attribute__((weak, visibility("hidden")));
struct lttng_ust_tracepoint_dlopen lttng_ust_tracepoint_dlopen
		__attribute__((weak, visibility("hidden"))) = {
	.struct_size = sizeof(struct lttng_ust_tracepoint_dlopen),
};
/*
 * Deal with gcc O1 optimisation issues with weak hidden symbols. gcc
 * 4.8 and prior does not have the same behavior for symbol scoping on
 * 32-bit powerpc depending on the object size: symbols for objects of 8
 * bytes or less have the same address throughout a module, whereas they
 * have different addresses between compile units for objects larger
 * than 8 bytes. Add this pointer indirection to ensure that the symbol
 * scoping match that of the other weak hidden symbols found in this
 * header.
 */
struct lttng_ust_tracepoint_dlopen *lttng_ust_tracepoint_dlopen_ptr
	__attribute__((weak, visibility("hidden")));

/*
 * Tracepoint dynamic linkage handling (callbacks). Hidden visibility: shared
 * across objects in a module/main executable. The callbacks are used to
 * control and check if the destructors should be executed.
 *
 * IMPORTANT: this structure is part of the ABI between instrumented
 * applications and UST. Fields need to be only added at the end, never
 * reordered, never removed.
 *
 * The field @struct_size should be used to determine the size of the
 * structure. It should be queried before using additional fields added
 * at the end of the structure.
 */
struct lttng_ust_tracepoint_destructors_syms {
	uint32_t struct_size;

	void (*tracepoint_disable_destructors)(void);
	int (*tracepoint_get_destructors_state)(void);

	/* End of base ABI. Fields below should be used after checking struct_size. */
};

extern struct lttng_ust_tracepoint_destructors_syms lttng_ust_tracepoint_destructors_syms;
extern struct lttng_ust_tracepoint_destructors_syms *lttng_ust_tracepoint_destructors_syms_ptr;

struct lttng_ust_tracepoint_destructors_syms lttng_ust_tracepoint_destructors_syms
	__attribute__((weak, visibility("hidden"))) = {
	.struct_size = sizeof(struct lttng_ust_tracepoint_destructors_syms),
};
struct lttng_ust_tracepoint_destructors_syms *lttng_ust_tracepoint_destructors_syms_ptr
	__attribute__((weak, visibility("hidden")));

static inline void tracepoint_disable_destructors(void)
{
	if (!lttng_ust_tracepoint_dlopen_ptr)
		lttng_ust_tracepoint_dlopen_ptr = &lttng_ust_tracepoint_dlopen;
	if (!lttng_ust_tracepoint_destructors_syms_ptr)
		lttng_ust_tracepoint_destructors_syms_ptr = &lttng_ust_tracepoint_destructors_syms;
	if (lttng_ust_tracepoint_dlopen_ptr->liblttngust_handle
			&& lttng_ust_tracepoint_destructors_syms_ptr->tracepoint_disable_destructors)
		lttng_ust_tracepoint_destructors_syms_ptr->tracepoint_disable_destructors();
}

#ifndef _LGPL_SOURCE
static inline void
lttng_ust_tracepoint__init_urcu_sym(void)
	lttng_ust_notrace;
static inline void
lttng_ust_tracepoint__init_urcu_sym(void)
{
	if (!lttng_ust_tracepoint_dlopen_ptr)
		lttng_ust_tracepoint_dlopen_ptr = &lttng_ust_tracepoint_dlopen;
	/*
	 * Symbols below are needed by tracepoint call sites and probe
	 * providers.
	 */
	if (!lttng_ust_tracepoint_dlopen_ptr->rcu_read_lock_sym)
		lttng_ust_tracepoint_dlopen_ptr->rcu_read_lock_sym =
			URCU_FORCE_CAST(void (*)(void),
				dlsym(lttng_ust_tracepoint_dlopen_ptr->liblttngust_handle,
					"lttng_ust_tp_rcu_read_lock"));
	if (!lttng_ust_tracepoint_dlopen_ptr->rcu_read_unlock_sym)
		lttng_ust_tracepoint_dlopen_ptr->rcu_read_unlock_sym =
			URCU_FORCE_CAST(void (*)(void),
				dlsym(lttng_ust_tracepoint_dlopen_ptr->liblttngust_handle,
					"lttng_ust_tp_rcu_read_unlock"));
	if (!lttng_ust_tracepoint_dlopen_ptr->rcu_dereference_sym)
		lttng_ust_tracepoint_dlopen_ptr->rcu_dereference_sym =
			URCU_FORCE_CAST(void *(*)(void *p),
				dlsym(lttng_ust_tracepoint_dlopen_ptr->liblttngust_handle,
					"lttng_ust_tp_rcu_dereference_sym"));
}
#else
static inline void
lttng_ust_tracepoint__init_urcu_sym(void)
	lttng_ust_notrace;
static inline void
lttng_ust_tracepoint__init_urcu_sym(void)
{
}
#endif

/*
 * Use getenv() directly and bypass lttng-ust helper functions
 * because we may not have access to lttng-ust shared libraries.
 */
#ifdef LTTNG_UST_DEBUG
static inline
bool lttng_ust_tracepoint_logging_debug_enabled(void)
{
	return true;
}
#else /* #ifdef LTTNG_UST_DEBUG */
static inline
bool lttng_ust_tracepoint_logging_debug_enabled(void)
{
	return getenv("LTTNG_UST_DEBUG");
}
#endif /* #ifdef LTTNG_UST_DEBUG */

#ifdef LTTNG_UST_ABORT_ON_CRITICAL
static inline
bool lttng_ust_tracepoint_logging_abort_on_critical_enabled(void)
{
	return true;
}
#else /* #ifdef LTTNG_UST_ABORT_ON_CRITICAL */
static inline
bool lttng_ust_tracepoint_logging_abort_on_critical_enabled(void)
{
	return getenv("LTTNG_UST_ABORT_ON_CRITICAL");
}
#endif

#define LTTNG_UST_TRACEPOINT_THIS_IP		\
	({ __label__ here; here: &&here; })

static void
lttng_ust_tracepoints_print_disabled_message(void)
{
	if (lttng_ust_tracepoint_logging_debug_enabled())
		fprintf(stderr, "lttng-ust-tracepoint [%ld]: Critical: dlopen() failed to find '%s', tracepoints in this binary won't be registered. "
			"(at addr=%p in %s() at " __FILE__ ":" lttng_ust_stringify(__LINE__) ")\n",
			(long) getpid(),
			LTTNG_UST_TRACEPOINT_LIB_SONAME,
			LTTNG_UST_TRACEPOINT_THIS_IP,
			__func__);
	if (lttng_ust_tracepoint_logging_abort_on_critical_enabled())
		abort();
}

static void
lttng_ust__tracepoints__init(void)
	lttng_ust_notrace __attribute__((constructor(LTTNG_UST_CONSTRUCTOR_PRIO)));
static void
lttng_ust__tracepoints__init(void)
{
	if (lttng_ust_tracepoint_registered++) {
		if (!lttng_ust_tracepoint_dlopen_ptr->liblttngust_handle)
			return;
		lttng_ust_tracepoint__init_urcu_sym();
		return;
	}

	if (!lttng_ust_tracepoint_dlopen_ptr)
		lttng_ust_tracepoint_dlopen_ptr = &lttng_ust_tracepoint_dlopen;
	if (!lttng_ust_tracepoint_dlopen_ptr->liblttngust_handle)
		lttng_ust_tracepoint_dlopen_ptr->liblttngust_handle =
			dlopen(LTTNG_UST_TRACEPOINT_LIB_SONAME, RTLD_NOW | RTLD_GLOBAL);
	if (!lttng_ust_tracepoint_dlopen_ptr->liblttngust_handle) {
		lttng_ust_tracepoints_print_disabled_message();
		return;
	}
	lttng_ust_tracepoint__init_urcu_sym();
}

static void
lttng_ust__tracepoints__destroy(void)
	lttng_ust_notrace __attribute__((destructor(LTTNG_UST_CONSTRUCTOR_PRIO)));
static void
lttng_ust__tracepoints__destroy(void)
{
	int ret;

	if (--lttng_ust_tracepoint_registered)
		return;
	if (!lttng_ust_tracepoint_dlopen_ptr)
		lttng_ust_tracepoint_dlopen_ptr = &lttng_ust_tracepoint_dlopen;
	if (!lttng_ust_tracepoint_destructors_syms_ptr)
		lttng_ust_tracepoint_destructors_syms_ptr = &lttng_ust_tracepoint_destructors_syms;
	if (!lttng_ust_tracepoint_dlopen_ptr->liblttngust_handle)
		return;
	if (lttng_ust_tracepoint_ptrs_registered)
		return;
	/*
	 * Lookup if destructors must be executed using the new method.
	 */
	if (lttng_ust_tracepoint_destructors_syms_ptr->tracepoint_get_destructors_state
		&& !lttng_ust_tracepoint_destructors_syms_ptr->tracepoint_get_destructors_state()) {
		/*
		 * The tracepoint_get_destructors_state symbol was found with
		 * dlsym but its returned value is 0 meaning that destructors
		 * must not be executed.
		 */
		return;
	}
	ret = dlclose(lttng_ust_tracepoint_dlopen_ptr->liblttngust_handle);
	if (ret) {
		fprintf(stderr, "Error (%d) in dlclose\n", ret);
		abort();
	}
	memset(lttng_ust_tracepoint_dlopen_ptr, 0, sizeof(*lttng_ust_tracepoint_dlopen_ptr));
}

#if LTTNG_UST_COMPAT_API(0)
# if defined(TRACEPOINT_DEFINE) && !defined(LTTNG_UST_TRACEPOINT_DEFINE)
#  define LTTNG_UST_TRACEPOINT_DEFINE
# endif
#endif /* #if LTTNG_UST_COMPAT_API(0) */

#if LTTNG_UST_COMPAT_API(0)
#define tracepoint			lttng_ust_tracepoint
#define do_tracepoint			lttng_ust_do_tracepoint
#define tracepoint_enabled		lttng_ust_tracepoint_enabled
#define TP_ARGS				LTTNG_UST_TP_ARGS
#endif /* #if LTTNG_UST_COMPAT_API(0) */

#ifdef __cplusplus
}
#endif

#endif /* _LTTNG_UST_TRACEPOINT_H */

/* The following declarations must be outside re-inclusion protection. */

#ifdef LTTNG_UST_TRACEPOINT_DEFINE

#ifndef _LTTNG_UST_TRACEPOINT_DEFINE_ONCE
#define _LTTNG_UST_TRACEPOINT_DEFINE_ONCE

#ifdef __cplusplus
extern "C" {
#endif

/*
 * These weak symbols, the constructor, and destructor take care of
 * registering only _one_ instance of the tracepoints per shared-ojbect
 * (or for the whole main program).
 */
extern struct lttng_ust_tracepoint * const __start_lttng_ust_tracepoints_ptrs[]
	__attribute__((weak, visibility("hidden")));
extern struct lttng_ust_tracepoint * const __stop_lttng_ust_tracepoints_ptrs[]
	__attribute__((weak, visibility("hidden")));

/*
 * When LTTNG_UST_TRACEPOINT_PROBE_DYNAMIC_LINKAGE is defined, we do not emit a
 * unresolved symbol that requires the provider to be linked in. When
 * LTTNG_UST_TRACEPOINT_PROBE_DYNAMIC_LINKAGE is not defined, we emit an
 * unresolved symbol that depends on having the provider linked in,
 * otherwise the linker complains. This deals with use of static
 * libraries, ensuring that the linker does not remove the provider
 * object from the executable.
 */

#if LTTNG_UST_COMPAT_API(0)
# if defined(TRACEPOINT_PROBE_DYNAMIC_LINKAGE) && !defined(LTTNG_UST_TRACEPOINT_PROBE_DYNAMIC_LINKAGE)
#  define LTTNG_UST_TRACEPOINT_PROBE_DYNAMIC_LINKAGE
# endif
#endif /* #if LTTNG_UST_COMPAT_API(0) */

#ifdef LTTNG_UST_TRACEPOINT_PROBE_DYNAMIC_LINKAGE
#define LTTNG_UST__TRACEPOINT_UNDEFINED_REF(provider)	NULL
#else	/* LTTNG_UST_TRACEPOINT_PROBE_DYNAMIC_LINKAGE */
#define LTTNG_UST__TRACEPOINT_UNDEFINED_REF(provider)	&lttng_ust_tracepoint_provider_##provider
#endif /* LTTNG_UST_TRACEPOINT_PROBE_DYNAMIC_LINKAGE */

/*
 * Note: to allow PIC code, we need to allow the linker to update the pointers
 * in the lttng_ust_tracepoints_ptrs section.
 * Therefore, this section is _not_ const (read-only).
 */
#define LTTNG_UST__TP_EXTRACT_STRING(...)	#__VA_ARGS__

#undef LTTNG_UST__DEFINE_TRACEPOINT
#define LTTNG_UST__DEFINE_TRACEPOINT(_provider, _name, _args)				\
	lttng_ust_tracepoint_validate_name_len(_provider, _name);		\
	extern int lttng_ust_tracepoint_provider_##_provider			\
		LTTNG_UST__TRACEPOINT_PROVIDER_DEFINITION_VISIBILITY;		\
	static const char lttng_ust_tp_provider_strtab_##_provider##___##_name[]	\
		__attribute__((section("lttng_ust_tracepoints_strings"))) =		\
			#_provider;						\
	static const char lttng_ust_tp_name_strtab_##_provider##___##_name[]		\
		__attribute__((section("lttng_ust_tracepoints_strings"))) =		\
			#_name;							\
	struct lttng_ust_tracepoint lttng_ust_tracepoint_##_provider##___##_name	\
		__attribute__((section("lttng_ust_tracepoints")))		\
		LTTNG_UST__TRACEPOINT_DEFINITION_VISIBILITY = {			\
			sizeof(struct lttng_ust_tracepoint),			\
			lttng_ust_tp_provider_strtab_##_provider##___##_name,		\
			lttng_ust_tp_name_strtab_##_provider##___##_name,		\
			0,							\
			NULL,							\
			LTTNG_UST__TRACEPOINT_UNDEFINED_REF(_provider), 	\
			LTTNG_UST__TP_EXTRACT_STRING(_args),			\
		};								\
	static struct lttng_ust_tracepoint *					\
		lttng_ust_tracepoint_ptr_##_provider##___##_name			\
		__attribute__((section("lttng_ust_tracepoints_ptrs"), used))		\
		__lttng_ust_variable_attribute_no_sanitize_address =		\
			&lttng_ust_tracepoint_##_provider##___##_name;

static void
lttng_ust__tracepoints__ptrs_init(void)
	lttng_ust_notrace __attribute__((constructor(LTTNG_UST_CONSTRUCTOR_PRIO)));
static void
lttng_ust__tracepoints__ptrs_init(void)
{
	if (lttng_ust_tracepoint_ptrs_registered++)
		return;
	if (!lttng_ust_tracepoint_dlopen_ptr)
		lttng_ust_tracepoint_dlopen_ptr = &lttng_ust_tracepoint_dlopen;
	if (!lttng_ust_tracepoint_dlopen_ptr->liblttngust_handle)
		lttng_ust_tracepoint_dlopen_ptr->liblttngust_handle =
			dlopen(LTTNG_UST_TRACEPOINT_LIB_SONAME, RTLD_NOW | RTLD_GLOBAL);
	if (!lttng_ust_tracepoint_dlopen_ptr->liblttngust_handle) {
		lttng_ust_tracepoints_print_disabled_message();
		return;
	}
	if (!lttng_ust_tracepoint_destructors_syms_ptr)
		lttng_ust_tracepoint_destructors_syms_ptr = &lttng_ust_tracepoint_destructors_syms;
	lttng_ust_tracepoint_dlopen_ptr->lttng_ust_tracepoint_module_register =
		URCU_FORCE_CAST(int (*)(struct lttng_ust_tracepoint * const *, int),
				dlsym(lttng_ust_tracepoint_dlopen_ptr->liblttngust_handle,
					"lttng_ust_tracepoint_module_register"));
	lttng_ust_tracepoint_dlopen_ptr->lttng_ust_tracepoint_module_unregister =
		URCU_FORCE_CAST(int (*)(struct lttng_ust_tracepoint * const *),
				dlsym(lttng_ust_tracepoint_dlopen_ptr->liblttngust_handle,
					"lttng_ust_tracepoint_module_unregister"));
	lttng_ust_tracepoint_destructors_syms_ptr->tracepoint_disable_destructors =
		URCU_FORCE_CAST(void (*)(void),
				dlsym(lttng_ust_tracepoint_dlopen_ptr->liblttngust_handle,
					"lttng_ust_tp_disable_destructors"));
	lttng_ust_tracepoint_destructors_syms_ptr->tracepoint_get_destructors_state =
		URCU_FORCE_CAST(int (*)(void),
				dlsym(lttng_ust_tracepoint_dlopen_ptr->liblttngust_handle,
					"lttng_ust_tp_get_destructors_state"));
	lttng_ust_tracepoint__init_urcu_sym();
	if (lttng_ust_tracepoint_dlopen_ptr->lttng_ust_tracepoint_module_register) {
		lttng_ust_tracepoint_dlopen_ptr->lttng_ust_tracepoint_module_register(__start_lttng_ust_tracepoints_ptrs,
				__stop_lttng_ust_tracepoints_ptrs -
				__start_lttng_ust_tracepoints_ptrs);
	}
}

static void
lttng_ust__tracepoints__ptrs_destroy(void)
	lttng_ust_notrace __attribute__((destructor(LTTNG_UST_CONSTRUCTOR_PRIO)));
static void
lttng_ust__tracepoints__ptrs_destroy(void)
{
	int ret;

	if (--lttng_ust_tracepoint_ptrs_registered)
		return;
	if (!lttng_ust_tracepoint_dlopen_ptr)
		lttng_ust_tracepoint_dlopen_ptr = &lttng_ust_tracepoint_dlopen;
	if (!lttng_ust_tracepoint_destructors_syms_ptr)
		lttng_ust_tracepoint_destructors_syms_ptr = &lttng_ust_tracepoint_destructors_syms;
	if (lttng_ust_tracepoint_dlopen_ptr->lttng_ust_tracepoint_module_unregister)
		lttng_ust_tracepoint_dlopen_ptr->lttng_ust_tracepoint_module_unregister(__start_lttng_ust_tracepoints_ptrs);
	if (lttng_ust_tracepoint_dlopen_ptr->liblttngust_handle
			&& lttng_ust_tracepoint_destructors_syms_ptr->tracepoint_get_destructors_state
			&& lttng_ust_tracepoint_destructors_syms_ptr->tracepoint_get_destructors_state()
			&& !lttng_ust_tracepoint_ptrs_registered) {
		ret = dlclose(lttng_ust_tracepoint_dlopen_ptr->liblttngust_handle);
		if (ret) {
			fprintf(stderr, "Error (%d) in dlclose\n", ret);
			abort();
		}
		memset(lttng_ust_tracepoint_dlopen_ptr, 0, sizeof(*lttng_ust_tracepoint_dlopen_ptr));
	}
}

#ifdef __cplusplus
}
#endif

#endif /* _LTTNG_UST_TRACEPOINT_DEFINE_ONCE */

#else /* LTTNG_UST_TRACEPOINT_DEFINE */

#undef LTTNG_UST__DEFINE_TRACEPOINT
#define LTTNG_UST__DEFINE_TRACEPOINT(_provider, _name, _args)

#endif /* #else LTTNG_UST_TRACEPOINT_DEFINE */

/*
 * LTTNG_UST_TRACEPOINT_HIDDEN_DEFINITION: Define this before including
 * a tracepoint instrumentation header to hide symbols associated with
 * tracepoint module instrumentation. This is useful if all compile
 * units using the lttng_ust_tracepoint(),
 * lttng_ust_tracepoint_enabled() and lttng_ust_do_tracepoint() macros
 * is within the same module as the compile unit including the
 * tracepoint header after defining LTTNG_UST_TRACEPOINT_DEFINE.
 */

#undef LTTNG_UST__TRACEPOINT_DEFINITION_VISIBILITY
#ifdef LTTNG_UST_TRACEPOINT_HIDDEN_DEFINITION
#define LTTNG_UST__TRACEPOINT_DEFINITION_VISIBILITY		__attribute__((visibility("hidden")))
#else
#define LTTNG_UST__TRACEPOINT_DEFINITION_VISIBILITY		__attribute__((visibility("default")))
#endif

/*
 * LTTNG_UST_TRACEPOINT_PROVIDER_HIDDEN_DEFINITION: Define this before
 * including a tracepoint instrumentation header to hide symbols
 * associated with the tracepoint provider. This is useful if the
 * tracepoint definition (including the header after defining
 * LTTNG_UST_TRACEPOINT_DEFINE) is in the same module as the provider
 * (including the header after defining
 * LTTNG_UST_TRACEPOINT_CREATE_PROBES).
 */
#undef LTTNG_UST__TRACEPOINT_PROVIDER_DEFINITION_VISIBILITY
#ifdef LTTNG_UST_TRACEPOINT_PROVIDER_HIDDEN_DEFINITION
#define LTTNG_UST__TRACEPOINT_PROVIDER_DEFINITION_VISIBILITY	__attribute__((visibility("hidden")))
#else
#define LTTNG_UST__TRACEPOINT_PROVIDER_DEFINITION_VISIBILITY	__attribute__((visibility("default")))
#endif

#ifndef LTTNG_UST_TRACEPOINT_ENUM

/*
 * Tracepoint Enumerations
 *
 * The enumeration is a mapping between an integer, or range of integers, and
 * a string. It can be used to have a more compact trace in cases where the
 * possible values for a field are limited:
 *
 * An example:
 *
 * LTTNG_UST_TRACEPOINT_ENUM(someproject_component, enumname,
 *	LTTNG_UST_TP_ENUM_VALUES(
 *		lttng_ust_field_enum_value("even", 0)
 *		lttng_ust_field_enum_value("uneven", 1)
 *		lttng_ust_field_enum_range("twoto4", 2, 4)
 *		lttng_ust_field_enum_value("five", 5)
 *	)
 * )
 *
 * Where "someproject_component" is the name of the component this enumeration
 * belongs to and "enumname" identifies this enumeration. Inside the
 * LTTNG_UST_TP_ENUM_VALUES macro is the actual mapping. Each string value can map
 * to either a single value with lttng_ust_field_enum_value or a range of values
 * with lttng_ust_field_enum_range.
 *
 * Enumeration ranges may overlap, but the behavior is implementation-defined,
 * each trace reader will handle overlapping as it wishes.
 *
 * That enumeration can then be used in a field inside the TP_FIELD macro using
 * the following line:
 *
 * lttng_ust_field_enum(someproject_component, enumname, enumtype, enumfield, enumval)
 *
 * Where "someproject_component" and "enumname" match those in the
 * LTTNG_UST_TRACEPOINT_ENUM, "enumtype" is a signed or unsigned integer type
 * backing the enumeration, "enumfield" is the name of the field and
 * "enumval" is the value.
 */

#define LTTNG_UST_TRACEPOINT_ENUM(provider, name, values)

#if LTTNG_UST_COMPAT_API(0)
#define TRACEPOINT_ENUM		LTTNG_UST_TRACEPOINT_ENUM
#endif /* #if LTTNG_UST_COMPAT_API(0) */

#endif /* #ifndef LTTNG_UST_TRACEPOINT_ENUM */

#ifndef LTTNG_UST_TRACEPOINT_EVENT

/*
 * How to use the LTTNG_UST_TRACEPOINT_EVENT macro:
 *
 * An example:
 *
 * LTTNG_UST_TRACEPOINT_EVENT(someproject_component, event_name,
 *
 *     * LTTNG_UST_TP_ARGS takes from 0 to 10 "type, field_name" pairs *
 *
 *     LTTNG_UST_TP_ARGS(int, arg0, void *, arg1, char *, string, size_t, strlen,
 *             long *, arg4, size_t, arg4_len),
 *
 *	* LTTNG_UST_TP_FIELDS describes the event payload layout in the trace *
 *
 *     LTTNG_UST_TP_FIELDS(
 *         * Integer, printed in base 10 *
 *         lttng_ust_field_integer(int, field_a, arg0)
 *
 *         * Integer, printed with 0x base 16 *
 *         lttng_ust_field_integer_hex(unsigned long, field_d, arg1)
 *
 *         * Enumeration *
 *         lttng_ust_field_enum(someproject_component, enum_name, int, field_e, arg0)
 *
 *         * Array Sequence, printed as UTF8-encoded array of bytes *
 *         lttng_ust_field_array_text(char, field_b, string, FIXED_LEN)
 *         lttng_ust_field_sequence_text(char, field_c, string, size_t, strlen)
 *
 *         * String, printed as UTF8-encoded string *
 *         lttng_ust_field_string(field_e, string)
 *
 *         * Array sequence of signed integer values *
 *         lttng_ust_field_array(long, field_f, arg4, FIXED_LEN4)
 *         lttng_ust_field_sequence(long, field_g, arg4, size_t, arg4_len)
 *     )
 * )
 *
 * More detailed explanation:
 *
 * The name of the tracepoint is expressed as a tuple with the provider
 * and name arguments.
 *
 * The provider and name should be a proper C99 identifier.
 * The "provider" and "name" MUST follow these rules to ensure no
 * namespace clash occurs:
 *
 * For projects (applications and libraries) for which an entity
 * specific to the project controls the source code and thus its
 * tracepoints (typically with a scope larger than a single company):
 *
 * either:
 *   project_component, event
 * or:
 *   project, event
 *
 * Where "project" is the name of the project,
 *       "component" is the name of the project component (which may
 *       include several levels of sub-components, e.g.
 *       ...component_subcomponent_...) where the tracepoint is located
 *       (optional),
 *       "event" is the name of the tracepoint event.
 *
 * For projects issued from a single company wishing to advertise that
 * the company controls the source code and thus the tracepoints, the
 * "com_" prefix should be used:
 *
 * either:
 *   com_company_project_component, event
 * or:
 *   com_company_project, event
 *
 * Where "company" is the name of the company,
 *       "project" is the name of the project,
 *       "component" is the name of the project component (which may
 *       include several levels of sub-components, e.g.
 *       ...component_subcomponent_...) where the tracepoint is located
 *       (optional),
 *       "event" is the name of the tracepoint event.
 *
 * the provider:event identifier is limited to 127 characters.
 */

#define LTTNG_UST_TRACEPOINT_EVENT(provider, name, args, fields)			\
	LTTNG_UST__DECLARE_TRACEPOINT(provider, name, LTTNG_UST__TP_PARAMS(args))		\
	LTTNG_UST__DEFINE_TRACEPOINT(provider, name, LTTNG_UST__TP_PARAMS(args))

#define LTTNG_UST_TRACEPOINT_EVENT_CLASS(provider, name, args, fields)

#define LTTNG_UST_TRACEPOINT_EVENT_INSTANCE(template_provider, template_name, provider, name, args)	\
	LTTNG_UST__DECLARE_TRACEPOINT(provider, name, LTTNG_UST__TP_PARAMS(args))		\
	LTTNG_UST__DEFINE_TRACEPOINT(provider, name, LTTNG_UST__TP_PARAMS(args))

#if LTTNG_UST_COMPAT_API(0)
#define TRACEPOINT_EVENT		LTTNG_UST_TRACEPOINT_EVENT
#define TRACEPOINT_EVENT_CLASS		LTTNG_UST_TRACEPOINT_EVENT_CLASS
#define TRACEPOINT_EVENT_INSTANCE(_provider, _template, _name, args)	\
	LTTNG_UST_TRACEPOINT_EVENT_INSTANCE(_provider, _template,	\
		_provider, _name, LTTNG_UST__TP_PARAMS(args))

#endif /* #if LTTNG_UST_COMPAT_API(0) */

#endif /* #ifndef LTTNG_UST_TRACEPOINT_EVENT */

#ifndef LTTNG_UST_TRACEPOINT_LOGLEVEL

/*
 * Tracepoint Loglevels
 *
 * Typical use of these loglevels:
 *
 * The loglevels go from 0 to 14. Higher numbers imply the most
 * verbosity (higher event throughput expected.
 *
 * Loglevels 0 through 6, and loglevel 14, match syslog(3) loglevels
 * semantic. Loglevels 7 through 13 offer more fine-grained selection of
 * debug information.
 *
 * LTTNG_UST_TRACEPOINT_LOGLEVEL_EMERG           0
 * system is unusable
 *
 * LTTNG_UST_TRACEPOINT_LOGLEVEL_ALERT           1
 * action must be taken immediately
 *
 * LTTNG_UST_TRACEPOINT_LOGLEVEL_CRIT            2
 * critical conditions
 *
 * LTTNG_UST_TRACEPOINT_LOGLEVEL_ERR             3
 * error conditions
 *
 * LTTNG_UST_TRACEPOINT_LOGLEVEL_WARNING         4
 * warning conditions
 *
 * LTTNG_UST_TRACEPOINT_LOGLEVEL_NOTICE          5
 * normal, but significant, condition
 *
 * LTTNG_UST_TRACEPOINT_LOGLEVEL_INFO            6
 * informational message
 *
 * LTTNG_UST_TRACEPOINT_LOGLEVEL_DEBUG_SYSTEM    7
 * debug information with system-level scope (set of programs)
 *
 * LTTNG_UST_TRACEPOINT_LOGLEVEL_DEBUG_PROGRAM   8
 * debug information with program-level scope (set of processes)
 *
 * LTTNG_UST_TRACEPOINT_LOGLEVEL_DEBUG_PROCESS   9
 * debug information with process-level scope (set of modules)
 *
 * LTTNG_UST_TRACEPOINT_LOGLEVEL_DEBUG_MODULE    10
 * debug information with module (executable/library) scope (set of units)
 *
 * LTTNG_UST_TRACEPOINT_LOGLEVEL_DEBUG_UNIT      11
 * debug information with compilation unit scope (set of functions)
 *
 * LTTNG_UST_TRACEPOINT_LOGLEVEL_DEBUG_FUNCTION  12
 * debug information with function-level scope
 *
 * LTTNG_UST_TRACEPOINT_LOGLEVEL_DEBUG_LINE      13
 * debug information with line-level scope (LTTNG_UST_TRACEPOINT_EVENT default)
 *
 * LTTNG_UST_TRACEPOINT_LOGLEVEL_DEBUG           14
 * debug-level message
 *
 * Declare tracepoint loglevels for tracepoints. A LTTNG_UST_TRACEPOINT_EVENT
 * should be declared prior to the the LTTNG_UST_TRACEPOINT_LOGLEVEL for a given
 * tracepoint name. The first field is the provider name, the second
 * field is the name of the tracepoint, the third field is the loglevel
 * name.
 *
 *      LTTNG_UST_TRACEPOINT_LOGLEVEL(< [com_company_]project[_component] >, < event >,
 *              < loglevel_name >)
 *
 * The LTTNG_UST_TRACEPOINT_PROVIDER must be already declared before declaring a
 * LTTNG_UST_TRACEPOINT_LOGLEVEL.
 */

enum {
	LTTNG_UST_TRACEPOINT_LOGLEVEL_EMERG		= 0,
	LTTNG_UST_TRACEPOINT_LOGLEVEL_ALERT		= 1,
	LTTNG_UST_TRACEPOINT_LOGLEVEL_CRIT		= 2,
	LTTNG_UST_TRACEPOINT_LOGLEVEL_ERR		= 3,
	LTTNG_UST_TRACEPOINT_LOGLEVEL_WARNING		= 4,
	LTTNG_UST_TRACEPOINT_LOGLEVEL_NOTICE		= 5,
	LTTNG_UST_TRACEPOINT_LOGLEVEL_INFO		= 6,
	LTTNG_UST_TRACEPOINT_LOGLEVEL_DEBUG_SYSTEM	= 7,
	LTTNG_UST_TRACEPOINT_LOGLEVEL_DEBUG_PROGRAM	= 8,
	LTTNG_UST_TRACEPOINT_LOGLEVEL_DEBUG_PROCESS	= 9,
	LTTNG_UST_TRACEPOINT_LOGLEVEL_DEBUG_MODULE	= 10,
	LTTNG_UST_TRACEPOINT_LOGLEVEL_DEBUG_UNIT	= 11,
	LTTNG_UST_TRACEPOINT_LOGLEVEL_DEBUG_FUNCTION	= 12,
	LTTNG_UST_TRACEPOINT_LOGLEVEL_DEBUG_LINE	= 13,
	LTTNG_UST_TRACEPOINT_LOGLEVEL_DEBUG		= 14,
};

#define LTTNG_UST_TRACEPOINT_LOGLEVEL(provider, name, loglevel)

#if LTTNG_UST_COMPAT_API(0)
#define TRACEPOINT_LOGLEVEL	LTTNG_UST_TRACEPOINT_LOGLEVEL

#define TRACE_EMERG		LTTNG_UST_TRACEPOINT_LOGLEVEL_EMERG
#define TRACE_ALERT		LTTNG_UST_TRACEPOINT_LOGLEVEL_ALERT
#define TRACE_CRIT		LTTNG_UST_TRACEPOINT_LOGLEVEL_CRIT
#define TRACE_ERR		LTTNG_UST_TRACEPOINT_LOGLEVEL_ERR
#define TRACE_WARNING		LTTNG_UST_TRACEPOINT_LOGLEVEL_WARNING
#define TRACE_NOTICE		LTTNG_UST_TRACEPOINT_LOGLEVEL_NOTICE
#define TRACE_INFO		LTTNG_UST_TRACEPOINT_LOGLEVEL_INFO
#define TRACE_DEBUG_SYSTEM	LTTNG_UST_TRACEPOINT_LOGLEVEL_DEBUG_SYSTEM
#define TRACE_DEBUG_PROGRAM	LTTNG_UST_TRACEPOINT_LOGLEVEL_DEBUG_PROGRAM
#define TRACE_DEBUG_PROCESS	LTTNG_UST_TRACEPOINT_LOGLEVEL_DEBUG_PROCESS
#define TRACE_DEBUG_MODULE	LTTNG_UST_TRACEPOINT_LOGLEVEL_DEBUG_MODULE
#define TRACE_DEBUG_UNIT	LTTNG_UST_TRACEPOINT_LOGLEVEL_DEBUG_UNIT
#define TRACE_DEBUG_FUNCTION	LTTNG_UST_TRACEPOINT_LOGLEVEL_DEBUG_FUNCTION
#define TRACE_DEBUG_LINE	LTTNG_UST_TRACEPOINT_LOGLEVEL_DEBUG_LINE
#define TRACE_DEBUG		LTTNG_UST_TRACEPOINT_LOGLEVEL_DEBUG
#endif

#endif /* #ifndef LTTNG_UST_TRACEPOINT_LOGLEVEL */

#ifndef LTTNG_UST_TRACEPOINT_MODEL_EMF_URI

#define LTTNG_UST_TRACEPOINT_MODEL_EMF_URI(provider, name, uri)

#if LTTNG_UST_COMPAT_API(0)
#define TRACEPOINT_MODEL_EMF_URI LTTNG_UST_TRACEPOINT_MODEL_EMF_URI
#endif

#endif /* #ifndef LTTNG_UST_TRACEPOINT_MODEL_EMF_URI */
