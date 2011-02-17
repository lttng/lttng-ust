/*
 * Code markup for dynamic and static tracing.
 *
 * See Documentation/marker.txt.
 *
 * (C) Copyright 2006 Mathieu Desnoyers <mathieu.desnoyers@polymtl.ca>
 * (C) Copyright 2009 Pierre-Marc Fournier <pierre-marc dot fournier at polymtl dot ca>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
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

#ifndef _UST_MARKER_H
#define _UST_MARKER_H

#include <stdarg.h>
#include <ust/immediate.h>
#include <ust/core.h>
#include <urcu/list.h>
#include <ust/processor.h>
#include <ust/kcompat/kcompat.h>
#include <ust/kcompat/stringify.h>

#include <bits/wordsize.h>

struct marker;

/**
 * marker_probe_func - Type of a marker probe function
 * @mdata: marker data
 * @probe_private: probe private data
 * @call_private: call site private data
 * @fmt: format string
 * @args: variable argument list pointer. Use a pointer to overcome C's
 *        inability to pass this around as a pointer in a portable manner in
 *        the callee otherwise.
 *
 * Type of marker probe functions. They receive the mdata and need to parse the
 * format string to recover the variable argument list.
 */
typedef void marker_probe_func(const struct marker *mdata,
		void *probe_private, struct registers *regs, void *call_private,
		const char *fmt, va_list *args);

struct marker_probe_closure {
	marker_probe_func *func;	/* Callback */
	void *probe_private;		/* Private probe data */
};

struct marker {
	const char *channel;	/* Name of channel where to send data */
	const char *name;	/* Marker name */
	const char *format;	/* Marker format string, describing the
				 * variable argument list.
				 */
	DEFINE_IMV(char, state);/* Immediate value state. */
	char ptype;		/* probe type : 0 : single, 1 : multi */
				/* Probe wrapper */
	u16 channel_id;		/* Numeric channel identifier, dynamic */
	u16 event_id;		/* Numeric event identifier, dynamic */
	void (*call)(const struct marker *mdata, void *call_private, struct registers *regs, ...);
	struct marker_probe_closure single;
	struct marker_probe_closure *multi;
	const char *tp_name;	/* Optional tracepoint name */
	void *tp_cb;		/* Optional tracepoint callback */
	void *location;		/* Address of marker in code */
};

#define GET_MARKER(channel, name)	(__mark_##channel##_##name)

#define _DEFINE_MARKER(channel, name, tp_name_str, tp_cb, format, unique, m)			\
		struct registers regs;								\
												\
		/* This next asm has to be a basic inline asm (no input/output/clobber), 	\
		 * because it must not require %-sign escaping, as we most certainly		\
		 * have some %-signs in the format string.					\
		 */										\
		asm volatile (									\
			/* We only define these symbols if they have not yet been defined. Indeed, \
			 * if two markers with the same channel/name are on the same line, they	\
			 * will try to create the same symbols, resulting in a conflict. This	\
			 * is not unusual as it can be the result of function inlining.		\
			 */									\
			".ifndef __mstrtab_" __stringify(channel) "_" __stringify(name) "_channel_" __stringify(unique) "\n\t"	\
			/*".section __markers_strings\n\t"*/					\
			".section __markers_strings,\"aw\",@progbits\n\t"				\
			"__mstrtab_" __stringify(channel) "_" __stringify(name) "_channel_" __stringify(unique) ":\n\t"	\
			".string \"" __stringify(channel) "\"\n\t"					\
			"__mstrtab_" __stringify(channel) "_" __stringify(name) "_name_" __stringify(unique) ":\n\t"	\
			".string \"" __stringify(name) "\"\n\t"						\
			"__mstrtab_" __stringify(channel) "_" __stringify(name) "_format_" __stringify(unique) ":\n\t"	\
			".string " "\"" format "\"" "\n\t"						\
			".previous\n\t"								\
			".endif\n\t"								\
		);										\
		asm volatile (									\
			/*".section __markers\n\t"*/ \
			".section __markers,\"aw\",@progbits\n\t"					\
			"2:\n\t" \
			_ASM_PTR "(__mstrtab_" __stringify(channel) "_" __stringify(name) "_channel_" __stringify(unique) ")\n\t" /* channel string */ \
			_ASM_PTR "(__mstrtab_" __stringify(channel) "_" __stringify(name) "_name_" __stringify(unique) ")\n\t" /* name string */ \
			_ASM_PTR "(__mstrtab_" __stringify(channel) "_" __stringify(name) "_format_" __stringify(unique) ")\n\t" /* format string */ \
			".byte 0\n\t" /* state imv */						\
			".byte 0\n\t" /* ptype */							\
			".word 0\n\t" /* channel_id */						\
			".word 0\n\t" /* event_id */						\
			".balign " __stringify(__WORDSIZE) " / 8\n\t" /* alignment */			\
			_ASM_PTR "(marker_probe_cb)\n\t" /* call */				\
			_ASM_PTR "(__mark_empty_function)\n\t" /* marker_probe_closure single.field1 */ \
			_ASM_PTR "0\n\t" /* marker_probe_closure single.field2 */			\
			_ASM_PTR "0\n\t" /* marker_probe_closure *multi */				\
			_ASM_PTR "0\n\t" /* tp_name */						\
			_ASM_PTR "0\n\t" /* tp_cb */						\
			_ASM_PTR "(1f)\n\t" /* location */						\
			".previous\n\t"								\
			/*".section __markers_ptrs\n\t"*/ \
			".section __markers_ptrs,\"a\",@progbits\n\t"				\
			".balign 8\n\t"								\
			_ASM_PTR "(2b)\n\t"							\
			".previous\n\t"								\
			"1:\n\t"								\
			ARCH_COPY_ADDR("%[outptr]")						\
		: [outptr] "=r" (m) );								\
												\
		save_registers(&regs)


#define DEFINE_MARKER(channel, name, format, unique, m)				\
		_DEFINE_MARKER(channel, name, NULL, NULL, format, unique, m)

#define DEFINE_MARKER_TP(channel, name, tp_name, tp_cb, format)		\
		_DEFINE_MARKER_TP(channel, name, #tp_name, tp_cb, format)

#define _DEFINE_MARKER_TP(channel, name, tp_name_str, tp_cb, format) \
		static const char __mstrtab_##channel##_##name[]	\
		__attribute__((section("__markers_strings")))		\
		= #channel "\0" #name "\0" format;			\
		static struct marker GET_MARKER(channel, name)		\
		__attribute__((section("__markers"))) =			\
		{ __mstrtab_##channel##_##name,				\
			&__mstrtab_##channel##_##name[sizeof(#channel)],	\
			&__mstrtab_##channel##_##name[sizeof(#channel) + sizeof(#name)],		\
			0, 0, 0, 0, marker_probe_cb,				\
			{ __mark_empty_function, NULL},			\
			NULL, tp_name_str, tp_cb };			\
		static struct marker * const __mark_ptr_##channel##_##name	\
			__attribute__((used, section("__markers_ptrs"))) =	\
			&GET_MARKER(channel, name);

/*
 * Make sure the alignment of the structure in the __markers section will
 * not add unwanted padding between the beginning of the section and the
 * structure. Force alignment to the same alignment as the section start.
 *
 * The "generic" argument controls which marker enabling mechanism must be used.
 * If generic is true, a variable read is used.
 * If generic is false, immediate values are used.
 */

#define __trace_mark(generic, channel, name, call_private, format, args...) \
	__trace_mark_counter(generic, channel, name, __LINE__, call_private, format, ## args)

#define __trace_mark_counter(generic, channel, name, unique, call_private, format, args...) \
	do {								\
		struct marker *m;					\
		DEFINE_MARKER(channel, name, format, unique, m);			\
		__mark_check_format(format, ## args);			\
		if (!generic) {						\
			if (unlikely(imv_read(m->state))) \
				(m->call)(m, call_private, &regs, ## args);		\
		} else {						\
			if (unlikely(_imv_read(m->state))) \
				(m->call)(m, call_private, &regs, ## args);		\
		}							\
	} while (0)

#define __trace_mark_tp(channel, name, call_private, tp_name, tp_cb, format, args...) \
	__trace_mark_tp_counter(channel, name, __LINE__, call_private, tp_name, tp_cb, format, ## args)

#define __trace_mark_tp_counter(channel, name, unique, call_private, tp_name, tp_cb, format, args...) \
	do {								\
		struct registers regs;								\
		void __check_tp_type(void)				\
		{							\
			register_trace_##tp_name(tp_cb, call_private);		\
		}							\
		DEFINE_MARKER_TP(channel, name, tp_name, tp_cb, format);\
		__mark_check_format(format, ## args);			\
		(*GET_MARKER(channel, name).call)(&GET_MARKER(channel, name), \
			call_private, &regs, ## args);				\
	} while (0)

extern void marker_update_probe_range(struct marker * const *begin,
	struct marker * const *end);

/**
 * trace_mark - Marker using code patching
 * @channel: marker channel (where to send the data), not quoted.
 * @name: marker name, not quoted.
 * @format: format string
 * @args...: variable argument list
 *
 * Places a marker using optimized code patching technique (imv_read())
 * to be enabled when immediate values are present.
 */
#define trace_mark(channel, name, format, args...) \
	__trace_mark(0, channel, name, NULL, format, ## args)

/**
 * _trace_mark - Marker using variable read
 * @channel: marker channel (where to send the data), not quoted.
 * @name: marker name, not quoted.
 * @format: format string
 * @args...: variable argument list
 *
 * Places a marker using a standard memory read (_imv_read()) to be
 * enabled. Should be used for markers in code paths where instruction
 * modification based enabling is not welcome.
 */
#define _trace_mark(channel, name, format, args...) \
	__trace_mark(1, channel, name, NULL, format, ## args)

/**
 * trace_mark_tp - Marker in a tracepoint callback
 * @channel: marker channel (where to send the data), not quoted.
 * @name: marker name, not quoted.
 * @tp_name: tracepoint name, not quoted.
 * @tp_cb: tracepoint callback. Should have an associated global symbol so it
 *         is not optimized away by the compiler (should not be static).
 * @format: format string
 * @args...: variable argument list
 *
 * Places a marker in a tracepoint callback.
 */
#define trace_mark_tp(channel, name, tp_name, tp_cb, format, args...)	\
	__trace_mark_tp(channel, name, NULL, tp_name, tp_cb, format, ## args)

/**
 * MARK_NOARGS - Format string for a marker with no argument.
 */
#define MARK_NOARGS " "

extern void lock_markers(void);
extern void unlock_markers(void);

extern void markers_compact_event_ids(void);

/* To be used for string format validity checking with gcc */
static inline void __printf(1, 2) ___mark_check_format(const char *fmt, ...)
{
}

#define __mark_check_format(format, args...)				\
	do {								\
		if (0)							\
			___mark_check_format(format, ## args);		\
	} while (0)

extern marker_probe_func __mark_empty_function;

extern void marker_probe_cb(const struct marker *mdata,
	void *call_private, struct registers *regs, ...);

/*
 * Connect a probe to a marker.
 * private data pointer must be a valid allocated memory address, or NULL.
 */
extern int marker_probe_register(const char *channel, const char *name,
	const char *format, marker_probe_func *probe, void *probe_private);

/*
 * Returns the private data given to marker_probe_register.
 */
extern int marker_probe_unregister(const char *channel, const char *name,
	marker_probe_func *probe, void *probe_private);
/*
 * Unregister a marker by providing the registered private data.
 */
extern int marker_probe_unregister_private_data(marker_probe_func *probe,
	void *probe_private);

extern void *marker_get_private_data(const char *channel, const char *name,
	marker_probe_func *probe, int num);

/*
 * marker_synchronize_unregister must be called between the last marker probe
 * unregistration and the first one of
 * - the end of module exit function
 * - the free of any resource used by the probes
 * to ensure the code and data are valid for any possibly running probes.
 */
#define marker_synchronize_unregister() synchronize_sched()

struct marker_iter {
//ust//	struct module *module;
	struct lib *lib;
	struct marker * const *marker;
};

extern void marker_iter_start(struct marker_iter *iter);
extern void marker_iter_next(struct marker_iter *iter);
extern void marker_iter_stop(struct marker_iter *iter);
extern void marker_iter_reset(struct marker_iter *iter);
extern int marker_get_iter_range(struct marker * const **marker, struct marker * const *begin,
	struct marker * const *end);

extern void marker_update_process(void);
extern int is_marker_enabled(const char *channel, const char *name);

//ust// #ifdef CONFIG_MARKERS_USERSPACE
//ust// extern void exit_user_markers(struct task_struct *p);
//ust// #else
//ust// static inline void exit_user_markers(struct task_struct *p)
//ust// {
//ust// }
//ust// #endif

struct marker_addr {
	struct marker *marker;
	void *addr;
};

struct lib {
	struct marker * const *markers_start;
#ifdef CONFIG_UST_GDB_INTEGRATION
	struct marker_addr *markers_addr_start;
#endif
	int markers_count;
	struct cds_list_head list;
};

extern int marker_register_lib(struct marker * const *markers_start, int markers_count);
extern int marker_unregister_lib(struct marker * const *markers_start);

#define MARKER_LIB							\
	extern struct marker * const __start___markers[] __attribute__((weak, visibility("hidden"))); \
	extern struct marker * const __stop___markers[] __attribute__((weak, visibility("hidden"))); \
									\
	static void __attribute__((constructor)) __markers__init(void)	\
	{								\
		marker_register_lib(__start___markers,			\
			(((long)__stop___markers) - ((long)__start___markers))	\
				/ sizeof(*__start___markers));		\
	} \
	\
	static void __attribute__((destructor)) __markers__destroy(void)	\
	{								\
		marker_unregister_lib(__start___markers); \
	}

extern void marker_set_new_marker_cb(void (*cb)(struct marker *));
extern void init_markers(void);

#endif /* _UST_MARKER_H */
