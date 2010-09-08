/*
 * Copyright (C) 2010 Nils Carlson
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
 *
 */

#include <errno.h>
#include <ust/tracepoint.h>
#include <ust/core.h>
#include <ust/kcompat/kcompat.h>
#include "usterr.h"

#define _LGPL_SOURCE
#include <urcu-bp.h>

/* libraries that contain trace_events (struct trace_event_lib) */
static LIST_HEAD(libs);

static DEFINE_MUTEX(trace_events_mutex);

void lock_trace_events(void)
{
	pthread_mutex_lock(&trace_events_mutex);
}

void unlock_trace_events(void)
{
	pthread_mutex_unlock(&trace_events_mutex);
}


int lib_get_iter_trace_events(struct trace_event_iter *iter)
{
	struct trace_event_lib *iter_lib;
	int found = 0;

	list_for_each_entry(iter_lib, &libs, list) {
		if (iter_lib < iter->lib)
			continue;
		else if (iter_lib > iter->lib)
			iter->trace_event = NULL;
		found = trace_event_get_iter_range(&iter->trace_event,
			iter_lib->trace_events_start,
			iter_lib->trace_events_start + iter_lib->trace_events_count);
		if (found) {
			iter->lib = iter_lib;
			break;
		}
	}
	return found;
}

/**
 * trace_event_get_iter_range - Get a next trace_event iterator given a range.
 * @trace_event: current trace_events (in), next trace_event (out)
 * @begin: beginning of the range
 * @end: end of the range
 *
 * Returns whether a next trace_event has been found (1) or not (0).
 * Will return the first trace_event in the range if the input trace_event is NULL.
 */
int trace_event_get_iter_range(struct trace_event **trace_event, struct trace_event *begin,
	struct trace_event *end)
{
	if (!*trace_event && begin != end) {
		*trace_event = begin;
		return 1;
	}
	if (*trace_event >= begin && *trace_event < end)
		return 1;
	return 0;
}

static void trace_event_get_iter(struct trace_event_iter *iter)
{
	int found = 0;

	found = lib_get_iter_trace_events(iter);
end:
	if (!found)
		trace_event_iter_reset(iter);
}

void trace_event_iter_start(struct trace_event_iter *iter)
{
	trace_event_get_iter(iter);
}

void trace_event_iter_next(struct trace_event_iter *iter)
{
	iter->trace_event++;
	/*
	 * iter->trace_event may be invalid because we blindly incremented it.
	 * Make sure it is valid by marshalling on the trace_events, getting the
	 * trace_events from following modules if necessary.
	 */
	trace_event_get_iter(iter);
}

void trace_event_iter_reset(struct trace_event_iter *iter)
{
	iter->lib = NULL;
	iter->trace_event = NULL;
}

int trace_event_register_lib(struct trace_event *trace_events_start,
			     int trace_events_count)
{
	struct trace_event_lib *pl;

	pl = (struct trace_event_lib *) malloc(sizeof(struct trace_event_lib));

	pl->trace_events_start = trace_events_start;
	pl->trace_events_count = trace_events_count;

	/* FIXME: maybe protect this with its own mutex? */
	pthread_mutex_lock(&trace_events_mutex);
	list_add(&pl->list, &libs);
	pthread_mutex_unlock(&trace_events_mutex);

	DBG("just registered a trace_events section from %p and having %d trace_events", trace_events_start, trace_events_count);

	return 0;
}

int trace_event_unregister_lib(struct trace_event *trace_events_start)
{
	struct trace_event_lib *lib;

	pthread_mutex_lock(&trace_events_mutex);

	list_for_each_entry(lib, &libs, list) {
		if(lib->trace_events_start == trace_events_start) {
			struct trace_event_lib *lib2free = lib;
			list_del(&lib->list);
			free(lib2free);
			break;
		}
	}

	pthread_mutex_unlock(&trace_events_mutex);

	return 0;
}
