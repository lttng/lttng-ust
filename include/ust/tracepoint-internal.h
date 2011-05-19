#ifndef _UST_TRACEPOINT_INTERNAL_H
#define _UST_TRACEPOINT_INTERNAL_H

/*
 * tracepoint-internal.h
 *
 * Tracepoint internal header.
 *
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

extern void tracepoint_update_probe_range(struct tracepoint * const *begin,
	struct tracepoint * const *end);

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
	synchronize_rcu();
}

extern void lock_trace_events(void);
extern void unlock_trace_events(void);

struct trace_event_iter {
	struct trace_event_lib *lib;
	struct trace_event * const *trace_event;
};

extern void trace_event_iter_start(struct trace_event_iter *iter);
extern void trace_event_iter_next(struct trace_event_iter *iter);
extern void trace_event_iter_reset(struct trace_event_iter *iter);

extern int trace_event_get_iter_range(struct trace_event * const **trace_event,
				      struct trace_event * const *begin,
				      struct trace_event * const *end);

extern void trace_event_update_process(void);
extern int is_trace_event_enabled(const char *channel, const char *name);

#endif /* _UST_TRACEPOINT_INTERNAL_H */
