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

#include "ltt-tracer-core.h"
#include "jhash.h"
#include "error.h"

/*
 * probe list is protected by ust_lock()/ust_unlock().
 */
static CDS_LIST_HEAD(probe_list);

/*
 * Loglevel hash table, containing the active loglevels.
 * Protected by ust lock.
 */
#define LOGLEVEL_HASH_BITS 6
#define LOGLEVEL_TABLE_SIZE (1 << LOGLEVEL_HASH_BITS)
static struct cds_hlist_head loglevel_table[LOGLEVEL_TABLE_SIZE];

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
				list_entry->tp.loglevel[0] = '\0';
				list_entry->tp.loglevel_value = 0;
			} else {
				strncpy(list_entry->tp.loglevel,
					(*probe_desc->event_desc[i]->loglevel)->identifier,
					LTTNG_UST_SYM_NAME_LEN);
				list_entry->tp.loglevel[LTTNG_UST_SYM_NAME_LEN - 1] = '\0';
				list_entry->tp.loglevel_value =
					(*probe_desc->event_desc[i]->loglevel)->value;
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

/*
 * Get loglevel if the loglevel is present in the loglevel hash table.
 * Must be called with ust lock held.
 * Returns NULL if not present.
 */
struct loglevel_entry *get_loglevel(const char *name)
{
	struct cds_hlist_head *head;
	struct cds_hlist_node *node;
	struct loglevel_entry *e;
	uint32_t hash = jhash(name, strlen(name), 0);

	head = &loglevel_table[hash & (LOGLEVEL_TABLE_SIZE - 1)];
	cds_hlist_for_each_entry(e, node, head, hlist) {
		if (!strcmp(name, e->name))
			return e;
	}
	return NULL;
}

struct loglevel_entry *get_loglevel_value(int64_t value)
{
	char name[LTTNG_UST_SYM_NAME_LEN];
	int ret;

	ret = snprintf(name, LTTNG_UST_SYM_NAME_LEN, "%lld", (long long) value);
	if (ret < 0)
		return NULL;
	return get_loglevel(name);
}

/*
 * marshall all probes/all events and create those that fit the
 * loglevel. Add them to the events list as created.
 */
static
void _probes_create_loglevel_events(struct loglevel_entry *entry,
				struct session_loglevel *loglevel)
{
	struct lttng_probe_desc *probe_desc;
	struct lttng_ust_event event_param;
	int i;

	cds_list_for_each_entry(probe_desc, &probe_list, head) {
		for (i = 0; i < probe_desc->nr_events; i++) {
			const struct tracepoint_loglevel_entry *ev_ll;
			const struct lttng_event_desc *event_desc;
			int match = 0;

			event_desc = probe_desc->event_desc[i];
			if (!(event_desc->loglevel))
				continue;
			ev_ll = *event_desc->loglevel;
			if (isalpha(entry->name[0])) {
				if (atoll(entry->name) == ev_ll->value) {
					match = 1;
				}
			} else if (!strcmp(ev_ll->identifier, entry->name)) {
				match = 1;
			}

			if (match) {
				struct ltt_event *ev;
				int ret;

				memcpy(&event_param, &loglevel->event_param,
						sizeof(event_param));
				memcpy(event_param.name,
					event_desc->name,
					sizeof(event_param.name));
				/* create event */
				ret = ltt_event_create(loglevel->chan,
					&event_param, NULL,
					&ev);
				if (ret) {
					DBG("Error creating event");
					continue;
				}
				cds_list_add(&ev->loglevel_list,
					&loglevel->events);
			}
		}
	}
}

/*
 * Add the loglevel to the loglevel hash table. Must be called with
 * ust lock held.
 */
struct session_loglevel *add_loglevel(const char *name,
	struct ltt_channel *chan,
	struct lttng_ust_event *event_param)
{
	struct cds_hlist_head *head;
	struct cds_hlist_node *node;
	struct loglevel_entry *e;
	struct session_loglevel *sl;
	size_t name_len = strlen(name) + 1;
	uint32_t hash = jhash(name, name_len-1, 0);
	int found = 0;

	/* loglevel entry */
	head = &loglevel_table[hash & (LOGLEVEL_TABLE_SIZE - 1)];
	cds_hlist_for_each_entry(e, node, head, hlist) {
		if (!strcmp(name, e->name)) {
			found = 1;
			break;
		}
	}

	if (!found) {
		/*
		 * Using zmalloc here to allocate a variable length element. Could
		 * cause some memory fragmentation if overused.
		 */
		e = zmalloc(sizeof(struct loglevel_entry) + name_len);
		if (!e)
			return ERR_PTR(-ENOMEM);
		memcpy(&e->name[0], name, name_len);
		cds_hlist_add_head(&e->hlist, head);
		CDS_INIT_LIST_HEAD(&e->session_list);
	}

	/* session loglevel */
	cds_list_for_each_entry(sl, &e->session_list, session_list) {
		if (chan == sl->chan) {
			DBG("loglevel %s busy for this channel", name);
			return ERR_PTR(-EEXIST);	/* Already there */
		}
	}
	sl = zmalloc(sizeof(struct session_loglevel));
	if (!sl)
		return ERR_PTR(-ENOMEM);
	sl->chan = chan;
	sl->enabled = 1;
	memcpy(&sl->event_param, event_param, sizeof(sl->event_param));
	sl->event_param.instrumentation = LTTNG_UST_TRACEPOINT;
	CDS_INIT_LIST_HEAD(&sl->events);
	cds_list_add(&sl->list, &chan->session->loglevels);
	cds_list_add(&sl->session_list, &e->session_list);
	sl->entry = e;
	_probes_create_loglevel_events(e, sl);
	return sl;
}

/*
 * Remove the loglevel from the loglevel hash table. Must be called with
 * ust_lock held. Only called at session teardown.
 */
void _remove_loglevel(struct session_loglevel *loglevel)
{
	struct ltt_event *ev, *tmp;

	/*
	 * Just remove the events owned (for enable/disable) by this
	 * loglevel from the list. The session teardown will take care
	 * of freeing the event memory.
	 */
	cds_list_for_each_entry_safe(ev, tmp, &loglevel->events, list) {
		cds_list_del(&ev->list);
	}
	cds_list_del(&loglevel->session_list);
	cds_list_del(&loglevel->list);
	if (cds_list_empty(&loglevel->entry->session_list)) {
		cds_hlist_del(&loglevel->entry->hlist);
		free(loglevel->entry);
	}
	free(loglevel);
}

int ltt_loglevel_enable(struct session_loglevel *loglevel)
{
	struct ltt_event *ev;
	int ret;

	if (loglevel->enabled)
		return -EEXIST;
	cds_list_for_each_entry(ev, &loglevel->events, list) {
		ret = ltt_event_enable(ev);
		if (ret) {
			DBG("Error: enable error.\n");
			return ret;
		}
	}
	loglevel->enabled = 1;
	return 0;
}

int ltt_loglevel_disable(struct session_loglevel *loglevel)
{
	struct ltt_event *ev;
	int ret;

	if (!loglevel->enabled)
		return -EEXIST;
	cds_list_for_each_entry(ev, &loglevel->events, list) {
		ret = ltt_event_disable(ev);
		if (ret) {
			DBG("Error: disable error.\n");
			return ret;
		}
	}
	loglevel->enabled = 0;
	return 0;
}
