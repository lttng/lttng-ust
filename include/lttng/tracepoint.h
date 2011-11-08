#ifndef _UST_TRACEPOINT_H
#define _UST_TRACEPOINT_H

/*
 * Copyright (C) 2008-2011 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 * Copyright (C) 2009 Pierre-Marc Fournier
 * Copyright (C) 2009 Steven Rostedt <rostedt@goodmis.org>
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
 *
 * Heavily inspired from the Linux Kernel Markers.
 *
 * Ported to userspace by Pierre-Marc Fournier.
 */

#include <urcu-bp.h>
#include <urcu/list.h>

#ifdef __cplusplus
extern "C" {
#endif

struct tracepoint_probe {
	void *func;
	void *data;
};

struct tracepoint {
	const char *name;		/* Tracepoint name */
	char state;			/* State. */
	struct tracepoint_probe *probes;
};

/*
 * Tracepoints should be added to the instrumented code using the
 * "tracepoint()" macro.
 */
#define tracepoint(provider, name, args...)	\
		__trace_##provider##___##name(args)

/*
 * it_func[0] is never NULL because there is at least one element in the array
 * when the array itself is non NULL.
 */
#define __DO_TRACE(tp, proto, args)					\
	do {								\
		struct tracepoint_probe *__tp_it_probe_ptr;		\
		void *__tp_it_func;					\
		void *__tp_cb_data;					\
									\
		rcu_read_lock();					\
		__tp_it_probe_ptr = rcu_dereference((tp)->probes);	\
		if (__tp_it_probe_ptr) {				\
			do {						\
				__tp_it_func = __tp_it_probe_ptr->func;	\
				__tp_cb_data = __tp_it_probe_ptr->data;	\
				URCU_FORCE_CAST(void(*)(proto), __tp_it_func)(args); \
			} while ((++__tp_it_probe_ptr)->func);		\
		}							\
		rcu_read_unlock();					\
	} while (0)

#define TP_PARAMS(args...)	args
#define TP_PROTO(args...)	args
#define TP_ARGS(args...)	args

#define __CHECK_TRACE(provider, name, proto, args)			\
	do {								\
		if (caa_unlikely(__tracepoint_##provider##___##name.state))	\
			__DO_TRACE(&__tracepoint_##provider##___##name,	\
				TP_PROTO(proto), TP_ARGS(args));	\
	} while (0)

/*
 * Make sure the alignment of the structure in the __tracepoints section will
 * not add unwanted padding between the beginning of the section and the
 * structure. Force alignment to the same alignment as the section start.
 */
#define __DECLARE_TRACEPOINT(provider, name, proto, args, data_proto, data_args)	\
	extern struct tracepoint __tracepoint_##provider##___##name;	\
	static inline void __trace_##provider##___##name(proto)		\
	{								\
		__CHECK_TRACE(provider, name, TP_PROTO(data_proto),	\
			      TP_ARGS(data_args));			\
	}								\
	static inline int						\
	__register_trace_##provider##___##name(void (*probe)(data_proto), void *data)	\
	{								\
		return __tracepoint_probe_register(#provider ":" #name, (void *) probe,	\
						 data);			\
	}								\
	static inline int						\
	__unregister_trace_##provider##___##name(void (*probe)(data_proto), void *data)	\
	{								\
		return __tracepoint_probe_unregister(#provider ":" #name, (void *) probe, \
						   data);		\
	}

/*
 * The need for the _DECLARE_TRACEPOINT_NOARGS() is to handle the prototype
 * (void). "void" is a special value in a function prototype and can
 * not be combined with other arguments. Since the DECLARE_TRACEPOINT()
 * macro adds a data element at the beginning of the prototype,
 * we need a way to differentiate "(void *data, proto)" from
 * "(void *data, void)". The second prototype is invalid.
 *
 * DECLARE_TRACEPOINT_NOARGS() passes "void" as the tracepoint prototype
 * and "void *__tp_cb_data" as the callback prototype.
 *
 * DECLARE_TRACEPOINT() passes "proto" as the tracepoint protoype and
 * "void *__tp_cb_data, proto" as the callback prototype.
 */
#define _DECLARE_TRACEPOINT_NOARGS(provider, name)			\
	__DECLARE_TRACEPOINT(provider, name, void, , void *__tp_cb_data, __tp_cb_data)

#define _DECLARE_TRACEPOINT(provider, name, proto, args)		\
	__DECLARE_TRACEPOINT(provider, name, TP_PARAMS(proto), TP_PARAMS(args),	\
			TP_PARAMS(void *__tp_cb_data, proto),		\
			TP_PARAMS(__tp_cb_data, args))

/*
 * __tracepoints_ptrs section is not const (read-only) to let the linker update
 * the pointer, allowing PIC code.
 */
#define _DEFINE_TRACEPOINT(provider, name)				\
	static const char __tpstrtab_##provider##___##name[]		\
	__attribute__((section("__tracepoints_strings"))) =		\
		#provider ":" #name;					\
	struct tracepoint __tracepoint_##provider##___##name		\
	__attribute__((section("__tracepoints"))) =			\
		{ __tpstrtab_##provider##___##name, 0, NULL };		\
	static struct tracepoint * __tracepoint_ptr_##provider##___##name	\
	__attribute__((used, section("__tracepoints_ptrs"))) =		\
		&__tracepoint_##provider##___##name;


#define __register_tracepoint(provider, name, probe, data)		\
		__register_trace_##provider##___##name(probe, data)
#define __unregister_tracepoint(provider, name, probe, data)		\
		__unregister_trace_##provider##___##name(probe, data)

/*
 * Connect a probe to a tracepoint.
 * Internal API.
 */
extern
int __tracepoint_probe_register(const char *name, void *probe, void *data);

/*
 * Disconnect a probe from a tracepoint.
 * Internal API.
 */
extern
int __tracepoint_probe_unregister(const char *name, void *probe, void *data);

extern
int tracepoint_register_lib(struct tracepoint * const *tracepoints_start,
			    int tracepoints_count);
extern
int tracepoint_unregister_lib(struct tracepoint * const *tracepoints_start);

/*
 * These weak symbols, the constructor, and destructor take care of
 * registering only _one_ instance of the tracepoints per shared-ojbect
 * (or for the whole main program).
 */
extern struct tracepoint * const __start___tracepoints_ptrs[]
	__attribute__((weak, visibility("hidden")));
extern struct tracepoint * const __stop___tracepoints_ptrs[]
	__attribute__((weak, visibility("hidden")));
int __tracepoint_registered
	__attribute__((weak, visibility("hidden")));

static void __attribute__((constructor)) __tracepoints__init(void)
{
	if (__tracepoint_registered++)
		return;
	tracepoint_register_lib(__start___tracepoints_ptrs,
				__stop___tracepoints_ptrs -
				__start___tracepoints_ptrs);
}

static void __attribute__((destructor)) __tracepoints__destroy(void)
{
	if (--__tracepoint_registered)
		return;
	tracepoint_unregister_lib(__start___tracepoints_ptrs);
}

#ifndef TRACEPOINT_EVENT
/*
 * Usage of the TRACEPOINT_EVENT macro:
 *
 * In short, an example:
 *
 * TRACEPOINT_EVENT(< [com_company_]project[_component] >, < event >,
 *     TP_PROTO(int arg0, void *arg1, char *string, size_t strlen,
 *              long *arg4, size_t arg4_len),
 *     TP_ARGS(arg0, arg1, string, strlen, arg4, arg4_len),
 *     TP_FIELDS(
 *
 *         * Integer, printed in base 10 * 
 *         ctf_integer(int, field_a, arg0)
 *
 *         * Integer, printed with 0x base 16 * 
 *         ctf_integer_hex(unsigned long, field_d, arg1)
 *
 *         * Array Sequence, printed as UTF8-encoded array of bytes * 
 *         ctf_array_text(char, field_b, string, FIXED_LEN)
 *         ctf_sequence_text(char, field_c, string, size_t, strlen)
 *
 *         * String, printed as UTF8-encoded string * 
 *         ctf_string(field_e, string)
 *
 *         * Array sequence of signed integer values * 
 *         ctf_array(long, field_f, arg4, FIXED_LEN4)
 *         ctf_sequence(long, field_g, arg4, size_t, arg4_len)
 *     )
 * )
 *
 * In more detail:
 *
 * We define a tracepoint, its arguments, and its 'fast binary record'
 * layout.
 *
 * Firstly, name your tracepoint via TRACEPOINT_EVENT(provider, name,
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
 *
 * As an example, let's consider a user-space application "someproject"
 * that would have an internal thread scheduler:
 *
 *  TRACEPOINT_EVENT(someproject_sched, switch,
 *
 *	*
 *	* A function has a regular function arguments
 *	* prototype, declare it via TP_PROTO():
 *	*
 *
 *	TP_PROTO(struct rq *rq, struct task_struct *prev,
 *		 struct task_struct *next),
 *
 *	*
 *	* Define the call signature of the 'function'.
 *	* (Design sidenote: we use this instead of a
 *	*  TP_PROTO1/TP_PROTO2/TP_PROTO3 ugliness.)
 *	*
 *
 *	TP_ARGS(rq, prev, next),
 *
 *	*
 *	* Fast binary tracing: define the trace record via
 *	* TP_FIELDS(). You can think about it like a
 *	* regular C structure local variable definition.
 *	*
 *	* This is how the trace record is structured and will
 *	* be saved into the ring buffer. These are the fields
 *	* that will be exposed to readers.
 *	*
 *	* ctf_integer(pid_t, prev_pid, prev->pid) is equivalent
 *	* to a standard declaraton:
 *	*
 *	*	pid_t prev_pid;
 *	*
 *	* followed by an assignment:
 *	*
 *	*	prev_pid = prev->pid;
 *	*
 *	* ctf_array(char, prev_comm, prev->comm, TASK_COMM_LEN) is
 *	* equivalent to:
 *	*
 *	*	char prev_comm[TASK_COMM_LEN];
 *	*
 *	* followed by an assignment:
 *	*
 *	*	memcpy(prev_comm, prev->comm, TASK_COMM_LEN);
 *	*
 *
 *	TP_FIELDS(
 *		ctf_array(char, prev_comm, prev->comm, TASK_COMM_LEN)
 *		ctf_integer(pid_t, prev_pid,  prev->pid)
 *		ctf_integer(int, prev_prio, prev->prio)
 *		ctf_array(char, next_comm, next->comm, TASK_COMM_LEN)
 *		ctf_integer(pid_t, next_pid,  next->pid)
 *		ctf_integer(int, next_prio, next->prio)
 *	)
 * )
 *
 * Do _NOT_ add comma (,) nor semicolon (;) after the TRACEPOINT_EVENT
 * declaration.
 *
 * The TRACEPOINT_SYSTEM must be defined when declaring a
 * TRACEPOINT_EVENT. See ust/tracepoint-event.h for information about
 * usage of other macros controlling TRACEPOINT_EVENT.
 */

#define TRACEPOINT_EVENT(provider, name, proto, args, fields)		\
	_DECLARE_TRACEPOINT(provider, name, TP_PARAMS(proto), TP_PARAMS(args))

#define TRACEPOINT_EVENT_CLASS(provider, name, proto, args, fields)
#define TRACEPOINT_EVENT_INSTANCE(provider, template, name, proto, args)\
	_DECLARE_TRACEPOINT(provider, name, TP_PARAMS(proto), TP_PARAMS(args))

/*
 * Declaration of tracepoints that take 0 argument.
 */
#define TRACEPOINT_EVENT_NOARGS(provider, name, fields)			\
	_DECLARE_TRACEPOINT_NOARGS(provider, name)

#define TRACEPOINT_EVENT_CLASS_NOARGS(provider, name, fields)
#define TRACEPOINT_EVENT_INSTANCE_NOARGS(provider, template, name)	\
	_DECLARE_TRACEPOINT_NOARGS(provider, name)

#endif /* #ifndef TRACEPOINT_EVENT */

#ifndef TRACEPOINT_LOGLEVEL

/*
 * Tracepoint Loglevel Declaration Facility
 *
 * This is a place-holder the tracepoint loglevel declaration,
 * overridden by the tracer implementation.
 *
 * Typical use of these loglevels:
 *
 * 1) Declare the mapping between loglevel names and an integer values
 *    within TRACEPOINT_LOGLEVEL_ENUM, using TP_LOGLEVEL for each tuple.
 *    Do _NOT_ add comma (,) nor semicolon (;) between the
 *    TRACEPOINT_LOGLEVEL_ENUM entries. Do _NOT_ add comma (,) nor
 *    semicolon (;) after the TRACEPOINT_LOGLEVEL_ENUM declaration.  The
 *    name should be a proper C99 identifier.
 *
 *      TRACEPOINT_LOGLEVEL_ENUM(
 *              TP_LOGLEVEL( < loglevel_name >, < value > )
 *              TP_LOGLEVEL( < loglevel_name >, < value > )
 *              ...
 *      )
 *
 *    e.g.:
 *
 *      TRACEPOINT_LOGLEVEL_ENUM(
 *              TP_LOGLEVEL(LOG_EMERG,   0)
 *              TP_LOGLEVEL(LOG_ALERT,   1)
 *              TP_LOGLEVEL(LOG_CRIT,    2)
 *              TP_LOGLEVEL(LOG_ERR,     3)
 *              TP_LOGLEVEL(LOG_WARNING, 4)
 *              TP_LOGLEVEL(LOG_NOTICE,  5)
 *              TP_LOGLEVEL(LOG_INFO,    6)
 *              TP_LOGLEVEL(LOG_DEBUG,   7)
 *      )
 *
 * 2) Then, declare tracepoint loglevels for tracepoints. A
 *    TRACEPOINT_EVENT should be declared prior to the the
 *    TRACEPOINT_LOGLEVEL for a given tracepoint name. The first field
 *    is the name of the tracepoint, the second field is the loglevel
 *    name.
 *
 *      TRACEPOINT_LOGLEVEL(< [com_company_]project[_component] >, < event >,
 *              < loglevel_name >)
 *
 * The TRACEPOINT_SYSTEM must be defined when declaring a
 * TRACEPOINT_LOGLEVEL_ENUM and TRACEPOINT_LOGLEVEL. The tracepoint
 * loglevel enumeration apply to the entire TRACEPOINT_SYSTEM. Only one
 * tracepoint loglevel enumeration should be declared per tracepoint
 * system.
 */

#define TRACEPOINT_LOGLEVEL_ENUM()
#define TRACEPOINT_LOGLEVEL(name, loglevel)

#endif /* #ifndef TRACEPOINT_LOGLEVEL */

#ifdef __cplusplus 
}
#endif

#endif /* _UST_TRACEPOINT_H */
