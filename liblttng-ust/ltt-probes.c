/*
 * ltt-probes.c
 *
 * Copyright 2010 (c) - Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 *
 * Holds LTTng probes registry.
 *
 * Dual LGPL v2.1/GPL v2 license.
 */

#include <string.h>
#include <errno.h>
#include <urcu/list.h>
#include <lttng/ust-events.h>
#include <assert.h>

#include "ltt-tracer-core.h"

/*
 * probe list is protected by ust_lock()/ust_unlock().
 */
static CDS_LIST_HEAD(probe_list);

static
const struct lttng_probe_desc *find_provider(const char *provider)
{
	struct lttng_probe_desc *iter;

	cds_list_for_each_entry(iter, &probe_list, head) {
		if (!strcmp(iter->provider, provider))
			return iter;
	}
	return NULL;
}

static
const struct lttng_event_desc *find_event(const char *name)
{
	struct lttng_probe_desc *probe_desc;
	int i;

	cds_list_for_each_entry(probe_desc, &probe_list, head) {
		for (i = 0; i < probe_desc->nr_events; i++) {
			if (!strcmp(probe_desc->event_desc[i]->name, name))
				return probe_desc->event_desc[i];
		}
	}
	return NULL;
}

int ltt_probe_register(struct lttng_probe_desc *desc)
{
	struct lttng_probe_desc *iter;
	int ret = 0;
	int i;

	ust_lock();
	if (find_provider(desc->provider)) {
		ret = -EEXIST;
		goto end;
	}
	/*
	 * TODO: This is O(N^2). Turn into a hash table when probe registration
	 * overhead becomes an issue.
	 */
	for (i = 0; i < desc->nr_events; i++) {
		if (find_event(desc->event_desc[i]->name)) {
			ret = -EEXIST;
			goto end;
		}
	}

	/*
	 * We sort the providers by struct lttng_probe_desc pointer
	 * address.
	 */
	cds_list_for_each_entry_reverse(iter, &probe_list, head) {
		BUG_ON(iter == desc); /* Should never be in the list twice */
		if (iter < desc) {
			/* We belong to the location right after iter. */
			cds_list_add(&desc->head, &iter->head);
			goto desc_added;
		}
	}
	/* We should be added at the head of the list */
	cds_list_add(&desc->head, &probe_list);
desc_added:

	/*
	 * fix the events awaiting probe load.
	 */
	for (i = 0; i < desc->nr_events; i++) {
		ret = pending_probe_fix_events(desc->event_desc[i]);
		assert(!ret);
	}
end:
	ust_unlock();
	return ret;
}

void ltt_probe_unregister(struct lttng_probe_desc *desc)
{
	ust_lock();
	cds_list_del(&desc->head);
	ust_unlock();
}

/*
 * called with UST lock held.
 */
const struct lttng_event_desc *ltt_event_get(const char *name)
{
	const struct lttng_event_desc *event;

	event = find_event(name);
	if (!event)
		return NULL;
	return event;
}

void ltt_event_put(const struct lttng_event_desc *event)
{
}
