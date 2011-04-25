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
 */

#ifndef _UST_MARKER_H
#define _UST_MARKER_H

#include <stdarg.h>
#include <ust/core.h>
#include <urcu/list.h>
#include <ust/processor.h>
#include <ust/kcompat/kcompat.h>
#include <ust/kcompat/stringify.h>

#include <bits/wordsize.h>

struct ust_marker;

/**
 * ust_marker_probe_func - Type of a marker probe function
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
typedef void ust_marker_probe_func(const struct ust_marker *mdata,
		void *probe_private, struct registers *regs, void *call_private,
		const char *fmt, va_list *args);

struct ust_marker_probe_closure {
	ust_marker_probe_func *func;	/* Callback */
	void *probe_private;		/* Private probe data */
};

struct ust_marker {
	const char *channel;	/* Name of channel where to send data */
	const char *name;	/* Marker name */
	const char *format;	/* Marker format string, describing the
				 * variable argument list.
				 */
	char state;		/* State. */
	char ptype;		/* probe type : 0 : single, 1 : multi */
				/* Probe wrapper */
	u16 channel_id;		/* Numeric channel identifier, dynamic */
	u16 event_id;		/* Numeric event identifier, dynamic */
	void (*call)(const struct ust_marker *mdata, void *call_private, struct registers *regs, ...);
	struct ust_marker_probe_closure single;
	struct ust_marker_probe_closure *multi;
	const char *tp_name;	/* Optional tracepoint name */
	void *tp_cb;		/* Optional tracepoint callback */
	void *location;		/* Address of marker in code */
};

#define GET_UST_MARKER(name)		(__ust_marker_ust_##name)

#define _DEFINE_UST_MARKER(channel, name, tp_name_str, tp_cb, format, unique, m)			\
		struct registers __ust_marker_regs;							\
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
			/*".section __ust_marker_strings\n\t"*/					\
			".section __ust_marker_strings,\"aw\"\n\t"					\
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
			/*".section __ust_marker\n\t"*/ \
			".section __ust_marker,\"aw\"\n\t"						\
			"2:\n\t" \
			_ASM_PTR "(__mstrtab_" __stringify(channel) "_" __stringify(name) "_channel_" __stringify(unique) ")\n\t" /* channel string */ \
			_ASM_PTR "(__mstrtab_" __stringify(channel) "_" __stringify(name) "_name_" __stringify(unique) ")\n\t" /* name string */ \
			_ASM_PTR "(__mstrtab_" __stringify(channel) "_" __stringify(name) "_format_" __stringify(unique) ")\n\t" /* format string */ \
			".byte 0\n\t" /* state imv */						\
			".byte 0\n\t" /* ptype */							\
			".hword 0\n\t" /* channel_id */						\
			".hword 0\n\t" /* event_id */						\
			".balign " __stringify(__WORDSIZE) " / 8\n\t" /* alignment */			\
			_ASM_PTR "(ust_marker_probe_cb)\n\t" /* call */				\
			_ASM_PTR "(__ust_marker_empty_function)\n\t" /* ust_marker_probe_closure single.field1 */ \
			_ASM_PTR "0\n\t" /* ust_marker_probe_closure single.field2 */			\
			_ASM_PTR "0\n\t" /* ust_marker_probe_closure *multi */				\
			_ASM_PTR "0\n\t" /* tp_name */						\
			_ASM_PTR "0\n\t" /* tp_cb */						\
			_ASM_PTR "(1f)\n\t" /* location */						\
			".previous\n\t"								\
			/*".section __ust_marker_ptrs\n\t"*/ \
			".section __ust_marker_ptrs,\"aw\"\n\t"					\
			_ASM_PTR "(2b)\n\t"							\
			".previous\n\t"								\
			"1:\n\t"								\
			ARCH_COPY_ADDR("%[outptr]")						\
		: [outptr] "=r" (m) );								\
												\
		save_registers(&__ust_marker_regs)


#define DEFINE_UST_MARKER(name, format, unique, m)			\
		_DEFINE_UST_MARKER(ust, name, NULL, NULL, format, unique, m)

#define DEFINE_UST_MARKER_TP(name, tp_name, tp_cb, format)		\
		_DEFINE_UST_MARKER_TP(ust, name, #tp_name, tp_cb, format)

#define _DEFINE_UST_MARKER_TP(channel, name, tp_name_str, tp_cb, format)\
		static const char __mstrtab_##channel##_##name[]	\
		__attribute__((section("__ust_marker_strings")))	\
		= #channel "\0" #name "\0" format;			\
		static struct ust_marker __ust_marker_##channel##_##name\
		__attribute__((section("__ust_marker"))) =		\
		{ __mstrtab_##channel##_##name,				\
			&__mstrtab_##channel##_##name[sizeof(#channel)],\
			&__mstrtab_##channel##_##name[sizeof(#channel) + sizeof(#name)],		\
			0, 0, 0, 0, ust_marker_probe_cb,		\
			{ __ust_marker_empty_function, NULL},		\
			NULL, tp_name_str, tp_cb };			\
		static struct ust_marker * const __ust_marker_ptr_##channel##_##name	\
			__attribute__((used, section("__ust_marker_ptrs"))) =	\
			&__ust_marker_##channel##_##name;

/*
 * Make sure the alignment of the structure in the __ust_marker section will
 * not add unwanted padding between the beginning of the section and the
 * structure. Force alignment to the same alignment as the section start.
 */

#define __ust_marker(channel, name, call_private, format, args...) \
	__ust_marker_counter(channel, name, __LINE__, call_private, format, ## args)

#define __ust_marker_counter(channel, name, unique, call_private, format, args...) \
	do {								\
		struct ust_marker *__ust_marker_counter_ptr;			\
		_DEFINE_UST_MARKER(channel, name, NULL, NULL, format, unique, __ust_marker_counter_ptr);	\
		__ust_marker_check_format(format, ## args);		\
		if (unlikely(__ust_marker_counter_ptr->state)) \
			(__ust_marker_counter_ptr->call)(__ust_marker_counter_ptr, call_private, &__ust_marker_regs, ## args);		\
	} while (0)

#define __ust_marker_tp(channel, name, call_private, tp_name, tp_cb, format, args...) \
	__ust_marker_tp_counter(channel, name, __LINE__, call_private, tp_name, tp_cb, format, ## args)

#define __ust_marker_tp_counter(channel, name, unique, call_private, tp_name, tp_cb, format, args...) \
	do {								\
		struct registers __ust_marker_regs;				\
		void __check_tp_type(void)				\
		{							\
			register_trace_##tp_name(tp_cb, call_private);		\
		}							\
		_DEFINE_UST_MARKER_TP(channel, name, #tp_name, tp_cb, format);	\
		__ust_marker_check_format(format, ## args);		\
		(*__ust_marker_##channel##_##name.call)(&__ust_marker_##channel##_##name,	\
			call_private, &__ust_marker_regs, ## args);				\
	} while (0)

extern void ust_marker_update_probe_range(struct ust_marker * const *begin,
	struct ust_marker * const *end);

/**
 * ust_marker - Marker using code patching
 * @name: marker name, not quoted.
 * @format: format string
 * @args...: variable argument list
 *
 * Places a marker at caller site.
 */
#define ust_marker(name, format, args...) \
	__ust_marker(ust, name, NULL, format, ## args)


/*
 * trace_mark() -- TO BE DEPRECATED
 * @channel: name prefix, not quoted. Ignored.
 * @name: marker name, not quoted.
 * @format: format string
 * @args...: variable argument list
 *
 * Kept as a compatibility API and will be *DEPRECATED* in favor of
 * ust_marker().
 */
#define trace_mark(channel, name, format, args...)	\
	ust_marker(name, format, ## args)

/**
 * ust_marker_tp - Marker in a tracepoint callback
 * @name: marker name, not quoted.
 * @tp_name: tracepoint name, not quoted.
 * @tp_cb: tracepoint callback. Should have an associated global symbol so it
 *         is not optimized away by the compiler (should not be static).
 * @format: format string
 * @args...: variable argument list
 *
 * Places a marker in a tracepoint callback.
 */
#define ust_marker_tp(name, tp_name, tp_cb, format, args...)	\
	__ust_marker_tp(ust, name, NULL, tp_name, tp_cb, format, ## args)

/**
 * UST_MARKER_NOARGS - Format string for a marker with no argument.
 */
#define UST_MARKER_NOARGS " "

/**
 * MARKER_NOARGS - Compatibility API. Will be *DEPRECATED*. Use
 * UST_MARKER_NOARGS instead.
 */
#define MARK_NOARGS	UST_MARKER_NOARGS

extern void lock_ust_marker(void);
extern void unlock_ust_marker(void);

extern void ust_marker_compact_event_ids(void);

/* To be used for string format validity checking with gcc */
static inline void __printf(1, 2) ___ust_marker_check_format(const char *fmt, ...)
{
}

#define __ust_marker_check_format(format, args...)			\
	do {								\
		if (0)							\
			___ust_marker_check_format(format, ## args);	\
	} while (0)

extern ust_marker_probe_func __ust_marker_empty_function;

extern void ust_marker_probe_cb(const struct ust_marker *mdata,
	void *call_private, struct registers *regs, ...);

/*
 * Connect a probe to a marker.
 * private data pointer must be a valid allocated memory address, or NULL.
 */
extern int ust_marker_probe_register(const char *channel, const char *name,
	const char *format, ust_marker_probe_func *probe, void *probe_private);

/*
 * Returns the private data given to ust_marker_probe_register.
 */
extern int ust_marker_probe_unregister(const char *channel, const char *name,
	ust_marker_probe_func *probe, void *probe_private);
/*
 * Unregister a marker by providing the registered private data.
 */
extern int ust_marker_probe_unregister_private_data(ust_marker_probe_func *probe,
	void *probe_private);

extern void *ust_marker_get_private_data(const char *channel, const char *name,
	ust_marker_probe_func *probe, int num);

/*
 * ust_marker_synchronize_unregister must be called between the last marker probe
 * unregistration and the first one of
 * - the end of module exit function
 * - the free of any resource used by the probes
 * to ensure the code and data are valid for any possibly running probes.
 */
#define ust_marker_synchronize_unregister() synchronize_sched()

struct ust_marker_iter {
//ust//	struct module *module;
	struct ust_marker_lib *lib;
	struct ust_marker * const *ust_marker;
};

extern void ust_marker_iter_start(struct ust_marker_iter *iter);
extern void ust_marker_iter_next(struct ust_marker_iter *iter);
extern void ust_marker_iter_stop(struct ust_marker_iter *iter);
extern void ust_marker_iter_reset(struct ust_marker_iter *iter);
extern int ust_marker_get_iter_range(struct ust_marker * const **marker, struct ust_marker * const *begin,
	struct ust_marker * const *end);

extern void ust_marker_update_process(void);
extern int is_ust_marker_enabled(const char *channel, const char *name);

//ust// #ifdef CONFIG_UST_MARKER_USERSPACE
//ust// extern void exit_user_ust_marker(struct task_struct *p);
//ust// #else
//ust// static inline void exit_user_ust_marker(struct task_struct *p)
//ust// {
//ust// }
//ust// #endif

struct ust_marker_addr {
	struct ust_marker *marker;
	void *addr;
};

struct ust_marker_lib {
	struct ust_marker * const *ust_marker_start;
#ifdef CONFIG_UST_GDB_INTEGRATION
	struct ust_marker_addr *ust_marker_addr_start;
#endif
	int ust_marker_count;
	struct cds_list_head list;
};

extern int ust_marker_register_lib(struct ust_marker * const *ust_marker_start, int ust_marker_count);
extern int ust_marker_unregister_lib(struct ust_marker * const *ust_marker_start);

#define UST_MARKER_LIB							\
	extern struct ust_marker * const __start___ust_marker_ptrs[] __attribute__((weak, visibility("hidden"))); \
	extern struct ust_marker * const __stop___ust_marker_ptrs[] __attribute__((weak, visibility("hidden"))); \
	static struct ust_marker * const __ust_marker_ptr_dummy			\
		__attribute__((used, section("__ust_marker_ptrs"))) = NULL;\
									\
	static void __attribute__((constructor)) __ust_marker__init(void)	\
	{								\
		ust_marker_register_lib(__start___ust_marker_ptrs,	\
				    __stop___ust_marker_ptrs		\
				    - __start___ust_marker_ptrs);		\
	}								\
									\
	static void __attribute__((destructor)) __ust_marker__destroy(void)\
	{								\
		ust_marker_unregister_lib(__start___ust_marker_ptrs);	\
	}

extern void ust_marker_set_new_ust_marker_cb(void (*cb)(struct ust_marker *));
extern void init_ust_marker(void);

#endif /* _UST_MARKER_H */
