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

struct tracepoint;

struct tracepoint_probe {
	void *func;
	void *data;
};

struct tracepoint {
	const char *name;		/* Tracepoint name */
	char state;			/* State. */
	struct tracepoint_probe *probes;
};

#define TP_PARAMS(args...)	args
#define TP_PROTO(args...)	args
#define TP_ARGS(args...)	args

/*
 * Tracepoints should be added to the instrumented code using the
 * "tracepoint()" macro.
 */
#define tracepoint(name, args...)	__trace_##name(args)

#define register_tracepoint(name, probe, data)			\
		__register_trace_##name(probe, data)

#define unregister_tracepoint(name, probe, data)		\
		__unregister_trace_##name(probe, data)

#define CONFIG_TRACEPOINTS
#ifdef CONFIG_TRACEPOINTS

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
#define __DECLARE_TRACE(name, proto, args, data_proto, data_args)	\
	extern struct tracepoint __tracepoint_##name;			\
	static inline void __trace_##name(proto)			\
	{								\
		__CHECK_TRACE(name, TP_PROTO(data_proto),		\
			      TP_ARGS(data_args));			\
	}								\
	static inline int						\
	__register_trace_##name(void (*probe)(data_proto), void *data)	\
	{								\
		return tracepoint_probe_register(#name, (void *)probe,	\
						 data);			\
									\
	}								\
	static inline int						\
	__unregister_trace_##name(void (*probe)(data_proto), void *data)\
	{								\
		return tracepoint_probe_unregister(#name, (void *)probe, \
						   data);		\
	}

#define DEFINE_TRACE_FN(name, reg, unreg)				\
	static const char __tpstrtab_##name[]				\
	__attribute__((section("__tracepoints_strings"))) = #name;	\
	struct tracepoint __tracepoint_##name				\
	__attribute__((section("__tracepoints"))) =			\
		{ __tpstrtab_##name, 0, NULL };				\
	static struct tracepoint * const __tracepoint_ptr_##name	\
	__attribute__((used, section("__tracepoints_ptrs"))) =		\
		&__tracepoint_##name;

#define DEFINE_TRACE(name)						\
	DEFINE_TRACE_FN(name, NULL, NULL)

extern void tracepoint_update_probe_range(struct tracepoint * const *begin,
	struct tracepoint * const *end);

#else /* !CONFIG_TRACEPOINTS */
#define __DECLARE_TRACE(name, proto, args)				\
	static inline void trace_##name(proto)				\
	{ }								\
	static inline void _trace_##name(proto)				\
	{ }								\
	static inline int __register_trace_##name(void (*probe)(proto), void *data)	\
	{								\
		return -ENOSYS;						\
	}								\
	static inline int __unregister_trace_##name(void (*probe)(proto), void *data)	\
	{								\
		return -ENOSYS;						\
	}

#define DEFINE_TRACE(name)
#define EXPORT_TRACEPOINT_SYMBOL_GPL(name)
#define EXPORT_TRACEPOINT_SYMBOL(name)

static inline void tracepoint_update_probe_range(struct tracepoint *begin,
	struct tracepoint *end)
{ }
#endif /* CONFIG_TRACEPOINTS */

/*
 * The need for the DECLARE_TRACE_NOARGS() is to handle the prototype
 * (void). "void" is a special value in a function prototype and can
 * not be combined with other arguments. Since the DECLARE_TRACE()
 * macro adds a data element at the beginning of the prototype,
 * we need a way to differentiate "(void *data, proto)" from
 * "(void *data, void)". The second prototype is invalid.
 *
 * DECLARE_TRACE_NOARGS() passes "void" as the tracepoint prototype
 * and "void *__tp_cb_data" as the callback prototype.
 *
 * DECLARE_TRACE() passes "proto" as the tracepoint protoype and
 * "void *__tp_cb_data, proto" as the callback prototype.
 */
#define DECLARE_TRACE_NOARGS(name)					\
		__DECLARE_TRACE(name, void, , void *__tp_cb_data, __tp_cb_data)

#define DECLARE_TRACE(name, proto, args)				\
		__DECLARE_TRACE(name, TP_PARAMS(proto), TP_PARAMS(args),\
				TP_PARAMS(void *__tp_cb_data, proto),	\
				TP_PARAMS(__tp_cb_data, args))

/*
 * Connect a probe to a tracepoint.
 * Internal API, should not be used directly.
 */
extern int tracepoint_probe_register(const char *name, void *probe, void *data);

/*
 * Disconnect a probe from a tracepoint.
 * Internal API, should not be used directly.
 */
extern int tracepoint_probe_unregister(const char *name, void *probe, void *data);

extern int tracepoint_probe_register_noupdate(const char *name, void *probe,
					      void *data);
extern int tracepoint_probe_unregister_noupdate(const char *name, void *probe,
						void *data);
extern void tracepoint_probe_update_all(void);

struct tracepoint_iter {
	struct tracepoint_lib *lib;
	struct tracepoint * const *tracepoint;
};

extern void tracepoint_iter_start(struct tracepoint_iter *iter);
extern void tracepoint_iter_next(struct tracepoint_iter *iter);
extern void tracepoint_iter_stop(struct tracepoint_iter *iter);
extern void tracepoint_iter_reset(struct tracepoint_iter *iter);
extern int tracepoint_get_iter_range(struct tracepoint * const **tracepoint,
	struct tracepoint * const *begin, struct tracepoint * const *end);

/*
 * tracepoint_synchronize_unregister must be called between the last tracepoint
 * probe unregistration and the end of module exit to make sure there is no
 * caller executing a probe when it is freed.
 */
static inline void tracepoint_synchronize_unregister(void)
{
//ust//	synchronize_sched();
}

struct tracepoint_lib {
	struct tracepoint * const *tracepoints_start;
	int tracepoints_count;
	struct cds_list_head list;
};

extern int tracepoint_register_lib(struct tracepoint * const *tracepoints_start,
				   int tracepoints_count);
extern int tracepoint_unregister_lib(struct tracepoint * const *tracepoints_start);

#define TRACEPOINT_LIB							\
	extern struct tracepoint * const __start___tracepoints_ptrs[] __attribute__((weak, visibility("hidden"))); \
	extern struct tracepoint * const __stop___tracepoints_ptrs[] __attribute__((weak, visibility("hidden"))); \
	static struct tracepoint * const __tracepoint_ptr_dummy		\
	__attribute__((used, section("__tracepoints_ptrs"))) = NULL;	\
	static void __attribute__((constructor)) __tracepoints__init(void)	\
	{									\
		tracepoint_register_lib(__start___tracepoints_ptrs,			\
					__stop___tracepoints_ptrs -			\
					__start___tracepoints_ptrs);			\
	}									\
										\
	static void __attribute__((destructor)) __tracepoints__destroy(void)	\
	{									\
		tracepoint_unregister_lib(__start___tracepoints_ptrs);		\
	}


#ifndef TRACE_EVENT
/*
 * For use with the TRACE_EVENT macro:
 *
 * We define a tracepoint, its arguments, its printf format
 * and its 'fast binary record' layout.
 *
 * Firstly, name your tracepoint via TRACE_EVENT(name : the
 * 'subsystem_event' notation is fine.
 *
 * Think about this whole construct as the
 * 'trace_sched_switch() function' from now on.
 *
 *
 *  TRACE_EVENT(sched_switch,
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
 *	* TP_STRUCT__entry(). You can think about it like a
 *	* regular C structure local variable definition.
 *	*
 *	* This is how the trace record is structured and will
 *	* be saved into the ring buffer. These are the fields
 *	* that will be exposed to readers.
 *	*
 *	* The declared 'local variable' is called '__entry'
 *	*
 *	* __field(pid_t, prev_prid) is equivalent to a standard declariton:
 *	*
 *	*	pid_t	prev_pid;
 *	*
 *	* __array(char, prev_comm, TASK_COMM_LEN) is equivalent to:
 *	*
 *	*	char	prev_comm[TASK_COMM_LEN];
 *	*
 *
 *	TP_STRUCT__entry(
 *		__array(	char,	prev_comm,	TASK_COMM_LEN	)
 *		__field(	pid_t,	prev_pid			)
 *		__field(	int,	prev_prio			)
 *		__array(	char,	next_comm,	TASK_COMM_LEN	)
 *		__field(	pid_t,	next_pid			)
 *		__field(	int,	next_prio			)
 *	),
 *
 *	*
 *	* Assign the entry into the trace record, by embedding
 *	* a full C statement block into TP_fast_assign(). You
 *	* can refer to the trace record as '__entry' -
 *	* otherwise you can put arbitrary C code in here.
 *	*
 *	* Note: this C code will execute every time a trace event
 *	* happens, on an active tracepoint.
 *	*
 *
 *	TP_fast_assign(
 *		memcpy(__entry->next_comm, next->comm, TASK_COMM_LEN);
 *		__entry->prev_pid	= prev->pid;
 *		__entry->prev_prio	= prev->prio;
 *		memcpy(__entry->prev_comm, prev->comm, TASK_COMM_LEN);
 *		__entry->next_pid	= next->pid;
 *		__entry->next_prio	= next->prio;
 *	)
 *
 *	*
 *	* Formatted output of a trace record via TP_printf().
 *	* This is how the tracepoint will appear under debugging
 *	* of tracepoints.
 *	*
 *	* (raw-binary tracing wont actually perform this step.)
 *	*
 *
 *	TP_printf("task %s:%d [%d] ==> %s:%d [%d]",
 *		__entry->prev_comm, __entry->prev_pid, __entry->prev_prio,
 *		__entry->next_comm, __entry->next_pid, __entry->next_prio),
 *
 * );
 *
 * This macro construct is thus used for the regular printf format
 * tracing setup.
 *
 * A set of (un)registration functions can be passed to the variant
 * TRACE_EVENT_FN to perform any (un)registration work.
 */

struct trace_event {
	const char *name;
	int (*regfunc)(void *data);
	int (*unregfunc)(void *data);
};

struct trace_event_lib {
	struct trace_event * const *trace_events_start;
	int trace_events_count;
	struct cds_list_head list;
};

struct trace_event_iter {
	struct trace_event_lib *lib;
	struct trace_event * const *trace_event;
};

extern void lock_trace_events(void);
extern void unlock_trace_events(void);

extern void trace_event_iter_start(struct trace_event_iter *iter);
extern void trace_event_iter_next(struct trace_event_iter *iter);
extern void trace_event_iter_reset(struct trace_event_iter *iter);

extern int trace_event_get_iter_range(struct trace_event * const **trace_event,
				      struct trace_event * const *begin,
				      struct trace_event * const *end);

extern void trace_event_update_process(void);
extern int is_trace_event_enabled(const char *channel, const char *name);

extern int trace_event_register_lib(struct trace_event * const *start_trace_events,
				    int trace_event_count);

extern int trace_event_unregister_lib(struct trace_event * const *start_trace_events);

#define TRACE_EVENT_LIB							\
	extern struct trace_event * const __start___trace_events_ptrs[]	\
	__attribute__((weak, visibility("hidden")));			\
	extern struct trace_event * const __stop___trace_events_ptrs[]	\
	__attribute__((weak, visibility("hidden")));			\
	static struct trace_event * const __event_ptrs_dummy		\
	__attribute__((used, section("__trace_events_ptrs"))) =	NULL;	\
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

#define DECLARE_TRACE_EVENT_CLASS(name, proto, args, tstruct, assign, print)
#define DEFINE_TRACE_EVENT(template, name, proto, args)		\
	DECLARE_TRACE(name, TP_PARAMS(proto), TP_PARAMS(args))
#define DEFINE_TRACE_EVENT_PRINT(template, name, proto, args, print)	\
	DECLARE_TRACE(name, TP_PARAMS(proto), TP_PARAMS(args))

#define TRACE_EVENT(name, proto, args, struct, assign, print)	\
	DECLARE_TRACE(name, TP_PARAMS(proto), TP_PARAMS(args))
#define TRACE_EVENT_FN(name, proto, args, struct,		\
		assign, print, reg, unreg)			\
	DECLARE_TRACE(name, TP_PARAMS(proto), TP_PARAMS(args))

#endif /* ifdef TRACE_EVENT (see note above) */


#endif /* _UST_TRACEPOINT_H */
