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
#include <urcu/hlist.h>
#include <lttng/ust-events.h>
#include <assert.h>
#include <helper.h>
#include <ctype.h>

#include "tracepoint-internal.h"
#include "ltt-tracer-core.h"
#include "jhash.h"
#include "error.h"

/*
 * probe list is protected by ust_lock()/ust_unlock().
 */
static CDS_LIST_HEAD(probe_list);

/*
 * Wildcard list, containing the active wildcards.
 * Protected by ust lock.
 */
static CDS_LIST_HEAD(wildcard_list);

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
			if (!strncmp(probe_desc->event_desc[i]->name, name,
					LTTNG_UST_SYM_NAME_LEN - 1))
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
	DBG("just registered probe %s containing %u events",
		desc->provider, desc->nr_events);
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
	DBG("just unregistered probe %s", desc->provider);
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

void ltt_probes_prune_event_list(struct lttng_ust_tracepoint_list *list)
{
	struct tp_list_entry *list_entry, *tmp;

	cds_list_for_each_entry_safe(list_entry, tmp, &list->head, head) {
		cds_list_del(&list_entry->head);
		free(list_entry);
	}
}

/*
 * called with UST lock held.
 */
int ltt_probes_get_event_list(struct lttng_ust_tracepoint_list *list)
{
	struct lttng_probe_desc *probe_desc;
	int i;

	CDS_INIT_LIST_HEAD(&list->head);
	cds_list_for_each_entry(probe_desc, &probe_list, head) {
		for (i = 0; i < probe_desc->nr_events; i++) {
			struct tp_list_entry *list_entry;

			list_entry = zmalloc(sizeof(*list_entry));
			if (!list_entry)
				goto err_nomem;
			cds_list_add(&list_entry->head, &list->head);
			strncpy(list_entry->tp.name,
				probe_desc->event_desc[i]->name,
				LTTNG_UST_SYM_NAME_LEN);
			list_entry->tp.name[LTTNG_UST_SYM_NAME_LEN - 1] = '\0';
			if (!probe_desc->event_desc[i]->loglevel) {
				list_entry->tp.loglevel = TRACE_DEFAULT;
			} else {
				list_entry->tp.loglevel = *(*probe_desc->event_desc[i]->loglevel);
			}
		}
	}
	if (cds_list_empty(&list->head))
		list->iter = NULL;
	else
		list->iter =
			cds_list_first_entry(&list->head, struct tp_list_entry, head);
	return 0;

err_nomem:
	ltt_probes_prune_event_list(list);
	return -ENOMEM;
}

/*
 * Return current iteration position, advance internal iterator to next.
 * Return NULL if end of list.
 */
struct lttng_ust_tracepoint_iter *
	lttng_ust_tracepoint_list_get_iter_next(struct lttng_ust_tracepoint_list *list)
{
	struct tp_list_entry *entry;

	if (!list->iter)
		return NULL;
	entry = list->iter;
	if (entry->head.next == &list->head)
		list->iter = NULL;
	else
		list->iter = cds_list_entry(entry->head.next,
				struct tp_list_entry, head);
	return &entry->tp;
}

/* WILDCARDS */

/*
 * Return wildcard for a given event name if the event name match the
 * one of the wildcards.
 * Must be called with ust lock held.
 * Returns NULL if not present.
 */
struct wildcard_entry *match_wildcard(const char *name)
{
	struct wildcard_entry *e;

	cds_list_for_each_entry(e, &wildcard_list, list) {
		/* If only contain '*' */
		if (strlen(e->name) == 1)
			return e;
		/* Compare excluding final '*' */
		if (!strncmp(name, e->name, strlen(e->name) - 1))
			return e;
	}
	return NULL;
}

/*
 * marshall all probes/all events and create those that fit the
 * wildcard. Add them to the events list as created.
 */
static
void _probes_create_wildcard_events(struct wildcard_entry *entry,
				struct session_wildcard *wildcard)
{
	struct lttng_probe_desc *probe_desc;
	struct lttng_ust_event event_param;
	int i;

	cds_list_for_each_entry(probe_desc, &probe_list, head) {
		for (i = 0; i < probe_desc->nr_events; i++) {
			const struct lttng_event_desc *event_desc;
			int match = 0;

			event_desc = probe_desc->event_desc[i];
			/* compare excluding final '*' */
			assert(strlen(entry->name) > 0);
			if (strcmp(event_desc->name, "lttng_ust:metadata")
					&& (strlen(entry->name) == 1
						|| !strncmp(event_desc->name, entry->name,
							strlen(entry->name) - 1))) {
				/* TODO: check if loglevel match */
				//if (event_desc->loglevel
				//	&& (*event_desc->loglevel) ...)
				match = 1;
			}
			if (match) {
				struct ltt_event *ev;
				int ret;

				memcpy(&event_param, &wildcard->event_param,
						sizeof(event_param));
				memcpy(event_param.name,
					event_desc->name,
					sizeof(event_param.name));
				/* create event */
				ret = ltt_event_create(wildcard->chan,
					&event_param, NULL,
					&ev);
				if (ret) {
					DBG("Error creating event");
					continue;
				}
				cds_list_add(&ev->wildcard_list,
					&wildcard->events);
			}
		}
	}
}

/*
 * Add the wildcard to the wildcard list. Must be called with
 * ust lock held.
 */
struct session_wildcard *add_wildcard(const char *name,
	struct ltt_channel *chan,
	struct lttng_ust_event *event_param)
{
	struct wildcard_entry *e;
	struct session_wildcard *sw;
	size_t name_len = strlen(name) + 1;
	int found = 0;

	/* try to find global wildcard entry */
	cds_list_for_each_entry(e, &wildcard_list, list) {
		if (!strncmp(name, e->name, LTTNG_UST_SYM_NAME_LEN - 1)) {
			found = 1;
			break;
		}
	}

	if (!found) {
		/*
		 * Create global wildcard entry if not found. Using
		 * zmalloc here to allocate a variable length element.
		 * Could cause some memory fragmentation if overused.
		 */
		e = zmalloc(sizeof(struct wildcard_entry) + name_len);
		if (!e)
			return ERR_PTR(-ENOMEM);
		memcpy(&e->name[0], name, name_len);
		cds_list_add(&e->list, &wildcard_list);
		CDS_INIT_LIST_HEAD(&e->session_list);
	}

	/* session wildcard */
	cds_list_for_each_entry(sw, &e->session_list, session_list) {
		if (chan == sw->chan) {
			DBG("wildcard %s busy for this channel", name);
			return ERR_PTR(-EEXIST);	/* Already there */
		}
	}
	sw = zmalloc(sizeof(struct session_wildcard));
	if (!sw)
		return ERR_PTR(-ENOMEM);
	sw->chan = chan;
	sw->enabled = 1;
	memcpy(&sw->event_param, event_param, sizeof(sw->event_param));
	sw->event_param.instrumentation = LTTNG_UST_TRACEPOINT;
	CDS_INIT_LIST_HEAD(&sw->events);
	cds_list_add(&sw->list, &chan->session->wildcards);
	cds_list_add(&sw->session_list, &e->session_list);
	sw->entry = e;
	_probes_create_wildcard_events(e, sw);
	return sw;
}

/*
 * Remove the wildcard from the wildcard list. Must be called with
 * ust_lock held. Only called at session teardown.
 */
void _remove_wildcard(struct session_wildcard *wildcard)
{
	struct ltt_event *ev, *tmp;

	/*
	 * Just remove the events owned (for enable/disable) by this
	 * wildcard from the list. The session teardown will take care
	 * of freeing the event memory.
	 */
	cds_list_for_each_entry_safe(ev, tmp, &wildcard->events,
			wildcard_list) {
		cds_list_del(&ev->wildcard_list);
	}
	cds_list_del(&wildcard->session_list);
	cds_list_del(&wildcard->list);
	if (cds_list_empty(&wildcard->entry->session_list)) {
		cds_list_del(&wildcard->entry->list);
		free(wildcard->entry);
	}
	free(wildcard);
}

int ltt_wildcard_enable(struct session_wildcard *wildcard)
{
	struct ltt_event *ev;
	int ret;

	if (wildcard->enabled)
		return -EEXIST;
	cds_list_for_each_entry(ev, &wildcard->events, wildcard_list) {
		ret = ltt_event_enable(ev);
		if (ret) {
			DBG("Error: enable error.\n");
			return ret;
		}
	}
	wildcard->enabled = 1;
	return 0;
}

int ltt_wildcard_disable(struct session_wildcard *wildcard)
{
	struct ltt_event *ev;
	int ret;

	if (!wildcard->enabled)
		return -EEXIST;
	cds_list_for_each_entry(ev, &wildcard->events, wildcard_list) {
		ret = ltt_event_disable(ev);
		if (ret) {
			DBG("Error: disable error.\n");
			return ret;
		}
	}
	wildcard->enabled = 0;
	return 0;
}
