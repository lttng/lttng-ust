#ifndef _LTTNG_TRACEPOINT_INTERNAL_H
#define _LTTNG_TRACEPOINT_INTERNAL_H

/*
 * Copyright (c) 2011 - Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
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

#include <urcu/list.h>
#include <lttng/tracepoint-types.h>

struct tracepoint_lib {
	struct cds_list_head list;
	struct tracepoint tracepoints_start;
	int tracepoints_count;
};

struct tracepoint_iter {
	struct tracepoint_lib *lib;
	struct tracepoint * const *tracepoint;

extern int tracepoint_probe_register_noupdate(const char *name, void *callback, void *priv);
extern int tracepoint_probe_unregister_noupdate(const char *name, void *callback, void *priv);
extern int tracepoint_probe_update_all(void);

extern void tracepoint_iter_start(struct tracepoint_iter *iter);
extern void tracepoint_iter_next(struct tracepoint_iter *iter);
extern void tracepoint_iter_stop(struct tracepoint_iter *iter);
extern void tracepoint_iter_reset(struct tracepoint_iter *iter);
extern int tracepoint_get_iter_range(struct tracepoint * const **tracepoint,
	struct tracepoint * const *begin, struct tracepoint * const *end);

/*
 * call after disconnection of last probe implemented within a
 * shared object before unmapping the library that contains the probe.
 */
static inline void tracepoint_synchronize_unregister(void)
{
	synchronize_rcu();
}

extern void init_tracepoint(void);
extern void exit_tracepoint(void);

#endif /* _LTTNG_TRACEPOINT_INTERNAL_H */
