#ifndef _LTTNG_TRACEPOINT_TYPES_H
#define _LTTNG_TRACEPOINT_TYPES_H

/*
 * Copyright (c) 2011 - Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 *
 * THIS MATERIAL IS PROVIDED AS IS, WITH ABSOLUTELY NO WARRANTY EXPRESSED
 * OR IMPLIED.  ANY USE IS AT YOUR OWN RISK.
 *
 * Permission is hereby granted to use or copy this program
 * for any purpose,  provided the above notices are retained on all copies.
 * Permission to modify the code and to distribute modified code is granted,
 * provided the above notices are retained, and a notice that the code was
 * modified is included with the above copyright notice.
 */

struct tracepoint_probe {
	void *callback;
	void *priv;
};

struct tracepoint {
	const char *name;
	int state;
	struct tracepoint_probe *probes;
};

struct tracepoint_lib {
	struct cds_list_head list;
	struct tracepoint tracepoints_start;
	int tracepoints_count;
};

#endif /* _LTTNG_TRACEPOINT_TYPES_H */
