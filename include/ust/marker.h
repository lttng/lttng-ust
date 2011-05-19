#ifndef _UST_MARKER_H
#define _UST_MARKER_H

/*
 * Code markup for dynamic and static tracing.
 *
 * See Documentation/marker.txt.
 *
 * (C) Copyright 2006 Mathieu Desnoyers <mathieu.desnoyers@polymtl.ca>
 * (C) Copyright 2009 Pierre-Marc Fournier <pierre-marc dot fournier at polymtl dot ca>
 * (C) Copyright 2011 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
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

#include <stdarg.h>
#include <bits/wordsize.h>
#include <urcu/list.h>
#include <ust/core.h>
#include <ust/kcompat/kcompat.h>

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
		void *probe_private, void *call_private,
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
	void (*call)(const struct ust_marker *mdata, void *call_private, ...);
	struct ust_marker_probe_closure single;
	struct ust_marker_probe_closure *multi;
	const char *tp_name;	/* Optional tracepoint name */
	void *tp_cb;		/* Optional tracepoint callback */
};

/*
 * We keep the "channel" as internal field for marker.c *only*. It will be
 * removed soon.
 */

/*
 * __ust_marker_ptrs section is not const (read-only) because it needs to be
 * read-write to let the linker apply relocations and keep the object PIC.
 */
#define _DEFINE_UST_MARKER(channel, name, tp_name_str, tp_cb, format)	\
		static const char __mstrtab_##channel##_##name[]	\
		__attribute__((section("__ust_markers_strings")))	\
		= #channel "\0" #name "\0" format;			\
		static struct ust_marker __ust_marker_def_##name	\
		__attribute__((section("__ust_markers"))) =		\
		{ __mstrtab_##channel##_##name,				\
		  &__mstrtab_##channel##_##name[sizeof(#channel)],	\
		  &__mstrtab_##channel##_##name[sizeof(#channel) +	\
						sizeof(#name)],		\
		  0, 0, 0, 0, ust_marker_probe_cb,			\
		  { __ust_marker_empty_function, NULL},			\
		  NULL, tp_name_str, tp_cb };				\
		static struct ust_marker * __ust_marker_ptr_##name	\
			__attribute__((used, section("__ust_marker_ptrs"))) = \
			&__ust_marker_def_##name

/*
 * Make sure the alignment of the structure in the __ust_marker section will
 * not add unwanted padding between the beginning of the section and the
 * structure. Force alignment to the same alignment as the section start.
 */

#define __ust_marker(channel, name, call_private, format, args...)	\
	do {								\
		_DEFINE_UST_MARKER(channel, name, NULL, NULL, format);	\
		__ust_marker_check_format(format, ## args);		\
		if (unlikely(__ust_marker_def_##name.state))		\
			(__ust_marker_def_##name.call)			\
				(&__ust_marker_def_##name, call_private,\
				## args);				\
	} while (0)

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

static inline __attribute__((deprecated))
void __trace_mark_is_deprecated()
{
}

/**
 * UST_MARKER_NOARGS - Format string for a marker with no argument.
 */
#define UST_MARKER_NOARGS " "

/* To be used for string format validity checking with gcc */
static inline
void __printf(1, 2) ___ust_marker_check_format(const char *fmt, ...)
{
}

#define __ust_marker_check_format(format, args...)			\
	do {								\
		if (0)							\
			___ust_marker_check_format(format, ## args);	\
	} while (0)

extern ust_marker_probe_func __ust_marker_empty_function;

extern void ust_marker_probe_cb(const struct ust_marker *mdata,
	void *call_private, ...);

struct ust_marker_lib {
	struct ust_marker * const *ust_marker_start;
	int ust_marker_count;
	struct cds_list_head list;
};

#define UST_MARKER_LIB							\
	extern struct ust_marker * const __start___ust_marker_ptrs[] __attribute__((weak, visibility("hidden"))); \
	extern struct ust_marker * const __stop___ust_marker_ptrs[] __attribute__((weak, visibility("hidden"))); \
	static struct ust_marker * __ust_marker_ptr_dummy		\
		__attribute__((used, section("__ust_marker_ptrs")));	\
									\
	static void __attribute__((constructor)) __ust_marker__init(void) \
	{								\
		ust_marker_register_lib(__start___ust_marker_ptrs,	\
				    __stop___ust_marker_ptrs		\
				    - __start___ust_marker_ptrs);	\
	}								\
									\
	static void __attribute__((destructor)) __ust_marker__destroy(void) \
	{								\
		ust_marker_unregister_lib(__start___ust_marker_ptrs);	\
	}

extern
int ust_marker_register_lib(struct ust_marker * const *ust_marker_start,
			    int ust_marker_count);
extern
int ust_marker_unregister_lib(struct ust_marker * const *ust_marker_start);

/*
 * trace_mark() -- DEPRECATED
 * @channel: name prefix, not quoted. Ignored.
 * @name: marker name, not quoted.
 * @format: format string
 * @args...: variable argument list
 *
 * Kept as a compatibility API and is *DEPRECATED* in favor of
 * ust_marker().
 */
#define trace_mark(channel, name, format, args...)	\
	__trace_mark_is_deprecated();			\
	ust_marker(name, format, ## args)

static inline __attribute__((deprecated))
void __MARKER_LIB_IS_DEPRECATED()
{
}

/*
 * MARKER_LIB is kept for backward compatibility and is *DEPRECATED*.
 * Use UST_MARKER_LIB instead.
 */
#define MARKER_LIB			\
	__MARKER_LIB_IS_DEPRECATED();	\
	UST_MARKER_LIB

/**
 * MARKER_NOARGS - Compatibility API. *DEPRECATED*. Use
 * UST_MARKER_NOARGS instead.
 */
#define MARK_NOARGS	UST_MARKER_NOARGS

#endif /* _UST_MARKER_H */
