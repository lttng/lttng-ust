#ifndef _UST_TRACEPOINT_H
#define _UST_TRACEPOINT_H

/*
 * Copyright (C) 2008 Mathieu Desnoyers <mathieu.desnoyers@polymtl.ca>
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
#include <ust/core.h>
#include <urcu/list.h>

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
#define tracepoint(name, args...)	__trace_##name(args)

/*
 * Library should be made known to libust by declaring TRACEPOINT_LIB in
 * the source file. (Usually at the end of the file, in the outermost
 * scope).
 */
#define TRACEPOINT_LIB							\
	extern struct tracepoint * const __start___tracepoints_ptrs[] __attribute__((weak, visibility("hidden"))); \
	extern struct tracepoint * const __stop___tracepoints_ptrs[] __attribute__((weak, visibility("hidden"))); \
	static struct tracepoint * __tracepoint_ptr_dummy		\
	__attribute__((used, section("__tracepoints_ptrs")));		\
	static void __attribute__((constructor)) __tracepoints__init(void) \
	{								\
		tracepoint_register_lib(__start___tracepoints_ptrs,	\
					__stop___tracepoints_ptrs -	\
					__start___tracepoints_ptrs);	\
	}								\
									\
	static void __attribute__((destructor)) __tracepoints__destroy(void) \
	{								\
		tracepoint_unregister_lib(__start___tracepoints_ptrs);	\
	}

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
				((void(*)(proto))__tp_it_func)(args);	\
			} while ((++__tp_it_probe_ptr)->func);		\
		}							\
		rcu_read_unlock();					\
	} while (0)

#define TP_PARAMS(args...)	args
#define TP_PROTO(args...)	args
#define TP_ARGS(args...)	args

#define __CHECK_TRACE(name, proto, args)				\
	do {								\
		if (unlikely(__tracepoint_##name.state))		\
			__DO_TRACE(&__tracepoint_##name,		\
				TP_PROTO(proto), TP_ARGS(args));	\
	} while (0)

/*
 * Make sure the alignment of the structure in the __tracepoints section will
 * not add unwanted padding between the beginning of the section and the
 * structure. Force alignment to the same alignment as the section start.
 */
#define __DECLARE_TRACEPOINT(name, proto, args, data_proto, data_args)	\
	extern struct tracepoint __tracepoint_##name;			\
	static inline void __trace_##name(proto)			\
	{								\
		__CHECK_TRACE(name, TP_PROTO(data_proto),		\
			      TP_ARGS(data_args));			\
	}								\
	static inline int						\
	__register_trace_##name(void (*probe)(data_proto), void *data)	\
	{								\
		return __tracepoint_probe_register(#name, (void *)probe,\
						 data);			\
									\
	}								\
	static inline int						\
	__unregister_trace_##name(void (*probe)(data_proto), void *data)\
	{								\
		return __tracepoint_probe_unregister(#name, (void *)probe, \
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
#define _DECLARE_TRACEPOINT_NOARGS(name)				\
	__DECLARE_TRACEPOINT(name, void, , void *__tp_cb_data, __tp_cb_data)

#define _DECLARE_TRACEPOINT(name, proto, args)				\
	__DECLARE_TRACEPOINT(name, TP_PARAMS(proto), TP_PARAMS(args),	\
			TP_PARAMS(void *__tp_cb_data, proto),		\
			TP_PARAMS(__tp_cb_data, args))

/*
 * __tracepoints_ptrs section is not const (read-only) to let the linker update
 * the pointer, allowing PIC code.
 */
#define _DEFINE_TRACEPOINT(name)					\
	static const char __tpstrtab_##name[]				\
	__attribute__((section("__tracepoints_strings"))) = #name;	\
	struct tracepoint __tracepoint_##name				\
	__attribute__((section("__tracepoints"))) =			\
		{ __tpstrtab_##name, 0, NULL };				\
	static struct tracepoint * __tracepoint_ptr_##name		\
	__attribute__((used, section("__tracepoints_ptrs"))) =		\
		&__tracepoint_##name;


#define __register_tracepoint(name, probe, data)			\
		__register_trace_##name(probe, data)
#define __unregister_tracepoint(name, probe, data)			\
		__unregister_trace_##name(probe, data)

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

struct tracepoint_lib {
	struct tracepoint * const *tracepoints_start;
	int tracepoints_count;
	struct cds_list_head list;
};

extern
int tracepoint_register_lib(struct tracepoint * const *tracepoints_start,
			    int tracepoints_count);
extern
int tracepoint_unregister_lib(struct tracepoint * const *tracepoints_start);


#ifndef TRACEPOINT_EVENT
/*
 * For use with the TRACEPOINT_EVENT macro:
 *
 * We define a tracepoint, its arguments, its printf format
 * and its 'fast binary record' layout.
 *
 * Firstly, name your tracepoint via TRACEPOINT_EVENT(name : the
 * 'subsystem_event' notation is fine.
 *
 * Think about this whole construct as the
 * 'trace_sched_switch() function' from now on.
 *
 *
 *  TRACEPOINT_EVENT(sched_switch,
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
 *	* tp_field(pid_t, prev_pid, prev->pid) is equivalent
 *	* to a standard declaraton:
 *	*
 *	*	pid_t prev_pid;
 *	*
 *	* followed by an assignment:
 *	*
 *	*	prev_pid = prev->pid;
 *	*
 *	* tp_array(char, prev_comm, TASK_COMM_LEN, prev->comm) is
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
 *		tp_array(char,	prev_comm, TASK_COMM_LEN, prev->comm)
 *		tp_field(pid_t,	prev_pid,  prev->pid)
 *		tp_field(int,	prev_prio, prev->prio)
 *		tp_array(char,	next_comm, TASK_COMM_LEN, next->comm)
 *		tp_field(pid_t,	next_pid,  next->pid)
 *		tp_field(int,	next_prio, next->prio)
 *	)
 * );
 */

#define TRACEPOINT_EVENT(name, proto, args, fields)			\
	_DECLARE_TRACEPOINT(name, TP_PARAMS(proto), TP_PARAMS(args))

#define TRACEPOINT_EVENT_CLASS(name, proto, args, fields)
#define TRACEPOINT_EVENT_INSTANCE(template, name, proto, args)		\
	_DECLARE_TRACEPOINT(name, TP_PARAMS(proto), TP_PARAMS(args))

/*
 * Declaration of tracepoints that take 0 argument.
 */
#define TRACEPOINT_EVENT_NOARGS(name, fields)				\
	_DECLARE_TRACEPOINT_NOARGS(name)

#define TRACEPOINT_EVENT_CLASS_NOARGS(name, fields)
#define TRACEPOINT_EVENT_INSTANCE_NOARGS(template, name)		\
	_DECLARE_TRACEPOINT_NOARGS(name)



#define TRACEPOINT_EVENT_LIB						\
	extern struct trace_event * const __start___trace_events_ptrs[]	\
	__attribute__((weak, visibility("hidden")));			\
	extern struct trace_event * const __stop___trace_events_ptrs[]	\
	__attribute__((weak, visibility("hidden")));			\
	static struct trace_event * __event_ptrs_dummy			\
	__attribute__((used, section("__trace_events_ptrs")));		\
	static void __attribute__((constructor))			\
	__trace_events__init(void)					\
	{								\
		trace_event_register_lib(__start___trace_events_ptrs,	\
					 __stop___trace_events_ptrs -	\
					 __start___trace_events_ptrs);	\
	}								\
									\
	static void __attribute__((destructor))				\
	__trace_event__destroy(void)					\
	{								\
		trace_event_unregister_lib(__start___trace_events_ptrs);\
	}

struct trace_event {
	const char *name;
};

struct trace_event_lib {
	struct trace_event * const *trace_events_start;
	int trace_events_count;
	struct cds_list_head list;
};

extern
int trace_event_register_lib(struct trace_event * const *start_trace_events,
			     int trace_event_count);
extern
int trace_event_unregister_lib(struct trace_event * const *start_trace_events);

#endif /* #ifndef TRACEPOINT_EVENT */

#endif /* _UST_TRACEPOINT_H */
