/*
 * ltt-probes.c
 *
 * Holds LTTng probes registry.
 *
 * Copyright 2010-2012 (c) - Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; only
 * version 2.1 of the License.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */

#include <string.h>
#include <errno.h>
#include <urcu/list.h>
#include <urcu/hlist.h>
#include <lttng/ust-events.h>
#include <lttng/tracepoint.h>
#include "tracepoint-internal.h"
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
		const struct lttng_event_desc *ed;

		ed = desc->event_desc[i];
		DBG("Registered event probe \"%s\" with signature \"%s\"",
			ed->name, ed->signature);
		ret = pending_probe_fix_events(ed);
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

void ltt_probes_prune_field_list(struct lttng_ust_field_list *list)
{
	struct tp_field_list_entry *list_entry, *tmp;

	cds_list_for_each_entry_safe(list_entry, tmp, &list->head, head) {
		cds_list_del(&list_entry->head);
		free(list_entry);
	}
}

/*
 * called with UST lock held.
 */
int ltt_probes_get_field_list(struct lttng_ust_field_list *list)
{
	struct lttng_probe_desc *probe_desc;
	int i;

	CDS_INIT_LIST_HEAD(&list->head);
	cds_list_for_each_entry(probe_desc, &probe_list, head) {
		for (i = 0; i < probe_desc->nr_events; i++) {
			const struct lttng_event_desc *event_desc =
				probe_desc->event_desc[i];
			int j;

			if (event_desc->nr_fields == 0) {
				/* Events without fields. */
				struct tp_field_list_entry *list_entry;

				list_entry = zmalloc(sizeof(*list_entry));
				if (!list_entry)
					goto err_nomem;
				cds_list_add(&list_entry->head, &list->head);
				strncpy(list_entry->field.event_name,
					event_desc->name,
					LTTNG_UST_SYM_NAME_LEN);
				list_entry->field.event_name[LTTNG_UST_SYM_NAME_LEN - 1] = '\0';
				list_entry->field.field_name[0] = '\0';
				list_entry->field.type = LTTNG_UST_FIELD_OTHER;
				if (!event_desc->loglevel) {
					list_entry->field.loglevel = TRACE_DEFAULT;
				} else {
					list_entry->field.loglevel = *(*event_desc->loglevel);
				}
				list_entry->field.nowrite = 1;
			}

			for (j = 0; j < event_desc->nr_fields; j++) {
				const struct lttng_event_field *event_field =
					&event_desc->fields[j];
				struct tp_field_list_entry *list_entry;

				list_entry = zmalloc(sizeof(*list_entry));
				if (!list_entry)
					goto err_nomem;
				cds_list_add(&list_entry->head, &list->head);
				strncpy(list_entry->field.event_name,
					event_desc->name,
					LTTNG_UST_SYM_NAME_LEN);
				list_entry->field.event_name[LTTNG_UST_SYM_NAME_LEN - 1] = '\0';
				strncpy(list_entry->field.field_name,
					event_field->name,
					LTTNG_UST_SYM_NAME_LEN);
				list_entry->field.field_name[LTTNG_UST_SYM_NAME_LEN - 1] = '\0';
				switch (event_field->type.atype) {
				case atype_integer:
					list_entry->field.type = LTTNG_UST_FIELD_INTEGER;
					break;
				case atype_string:
					list_entry->field.type = LTTNG_UST_FIELD_STRING;
					break;
				case atype_array:
					if (event_field->type.u.array.elem_type.atype != atype_integer
						|| event_field->type.u.array.elem_type.u.basic.integer.encoding == lttng_encode_none)
						list_entry->field.type = LTTNG_UST_FIELD_OTHER;
					else
						list_entry->field.type = LTTNG_UST_FIELD_STRING;
					break;
				case atype_sequence:
					if (event_field->type.u.sequence.elem_type.atype != atype_integer
						|| event_field->type.u.sequence.elem_type.u.basic.integer.encoding == lttng_encode_none)
						list_entry->field.type = LTTNG_UST_FIELD_OTHER;
					else
						list_entry->field.type = LTTNG_UST_FIELD_STRING;
					break;
				case atype_float:
					list_entry->field.type = LTTNG_UST_FIELD_FLOAT;
					break;
				case atype_enum:
					list_entry->field.type = LTTNG_UST_FIELD_ENUM;
					break;
				default:
					list_entry->field.type = LTTNG_UST_FIELD_OTHER;
				}
				if (!event_desc->loglevel) {
					list_entry->field.loglevel = TRACE_DEFAULT;
				} else {
					list_entry->field.loglevel = *(*event_desc->loglevel);
				}
				list_entry->field.nowrite = event_field->nowrite;
			}
		}
	}
	if (cds_list_empty(&list->head))
		list->iter = NULL;
	else
		list->iter =
			cds_list_first_entry(&list->head,
				struct tp_field_list_entry, head);
	return 0;

err_nomem:
	ltt_probes_prune_field_list(list);
	return -ENOMEM;
}

/*
 * Return current iteration position, advance internal iterator to next.
 * Return NULL if end of list.
 */
struct lttng_ust_field_iter *
	lttng_ust_field_list_get_iter_next(struct lttng_ust_field_list *list)
{
	struct tp_field_list_entry *entry;

	if (!list->iter)
		return NULL;
	entry = list->iter;
	if (entry->head.next == &list->head)
		list->iter = NULL;
	else
		list->iter = cds_list_entry(entry->head.next,
				struct tp_field_list_entry, head);
	return &entry->field;
}

/*
 * marshall all probes/all events and create those that fit the
 * wildcard. Add them to the events list as created.
 */
void ltt_probes_create_wildcard_events(struct wildcard_entry *entry,
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
				if (ltt_loglevel_match(event_desc,
					entry->loglevel_type,
						entry->loglevel)) {
					match = 1;
				}
			}
			if (match) {
				struct ltt_event *ev;
				int ret;

				memcpy(&event_param, &wildcard->event_param,
						sizeof(event_param));
				strncpy(event_param.name,
					event_desc->name,
					sizeof(event_param.name));
				event_param.name[sizeof(event_param.name) - 1] = '\0';
				/* create event */
				ret = ltt_event_create(wildcard->chan,
					&event_param, &ev);
				if (ret) {
					DBG("Error creating event");
					continue;
				}
				cds_list_add(&ev->wildcard_list,
					&wildcard->events);
			}
		}
	}
	lttng_filter_wildcard_link_bytecode(wildcard);
}

