#ifndef _UST_MARKER_INTERNAL_H
#define _UST_MARKER_INTERNAL_H

/*
 * Code markup for dynamic and static tracing. (internal header)
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
#include <urcu-bp.h>
#include <urcu/list.h>
#include <ust/core.h>
#include <ust/kcompat/kcompat.h>
#include <ust/marker.h>

#define GET_UST_MARKER(name)		(__ust_marker_def_##name)

#define DEFINE_UST_MARKER(name, format)					\
		_DEFINE_UST_MARKER(ust, name, NULL, NULL, format)

#define DEFINE_UST_MARKER_TP(name, tp_name, tp_cb, format)		\
		_DEFINE_UST_MARKER(ust, name, #tp_name, tp_cb, format)

#define __ust_marker_tp(name, call_private, tp_name, tp_cb,		\
			format, args...)				\
	do {								\
		void __check_tp_type(void)				\
		{							\
			register_trace_##tp_name(tp_cb, call_private);	\
		}							\
		DEFINE_UST_MARKER_TP(name, #tp_name, tp_cb, format);	\
		__ust_marker_check_format(format, ## args);		\
		(*__ust_marker_def_##name.call)				\
			(&__ust_marker_def_##name, call_private, ## args); \
	} while (0)

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

extern void ust_marker_update_probe_range(struct ust_marker * const *begin,
	struct ust_marker * const *end);

extern void lock_ust_marker(void);
extern void unlock_ust_marker(void);

extern void ust_marker_compact_event_ids(void);

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
 * ust_marker_synchronize_unregister must be called between the last
 * marker probe unregistration and the first one of
 * - the end of library exit function
 * - the free of any resource used by the probes
 * to ensure the code and data are valid for any possibly running probes.
 */
#define ust_marker_synchronize_unregister() synchronize_rcu()

struct ust_marker_iter {
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

extern void ust_marker_set_new_ust_marker_cb(void (*cb)(struct ust_marker *));
extern void init_ust_marker(void);

#endif /* _UST_MARKER_INTERNAL_H */
