/*
 * lttng-probes.c
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

#define _LGPL_SOURCE
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

#include "lttng-tracer-core.h"
#include "jhash.h"
#include "error.h"

/*
 * probe list is protected by ust_lock()/ust_unlock().
 */
static CDS_LIST_HEAD(_probe_list);

/*
 * List of probes registered by not yet processed.
 */
static CDS_LIST_HEAD(lazy_probe_init);

/*
 * lazy_nesting counter ensures we don't trigger lazy probe registration
 * fixup while we are performing the fixup. It is protected by the ust
 * mutex.
 */
static int lazy_nesting;

/*
 * Called under ust lock.
 */
static
int check_event_provider(struct lttng_probe_desc *desc)
{
	int i;
	size_t provider_name_len;

	provider_name_len = strnlen(desc->provider,
				LTTNG_UST_SYM_NAME_LEN - 1);
	for (i = 0; i < desc->nr_events; i++) {
		if (strncmp(desc->event_desc[i]->name,
				desc->provider,
				provider_name_len))
			return 0;	/* provider mismatch */
	}
	return 1;
}

/*
 * Called under ust lock.
 */
static
void lttng_lazy_probe_register(struct lttng_probe_desc *desc)
{
	struct lttng_probe_desc *iter;
	struct cds_list_head *probe_list;

	/*
	 * Each provider enforce that every event name begins with the
	 * provider name. Check this in an assertion for extra
	 * carefulness. This ensures we cannot have duplicate event
	 * names across providers.
	 */
	assert(check_event_provider(desc));

	/*
	 * The provider ensures there are no duplicate event names.
	 * Duplicated TRACEPOINT_EVENT event names would generate a
	 * compile-time error due to duplicated symbol names.
	 */

	/*
	 * We sort the providers by struct lttng_probe_desc pointer
	 * address.
	 */
	probe_list = &_probe_list;
	cds_list_for_each_entry_reverse(iter, probe_list, head) {
		BUG_ON(iter == desc); /* Should never be in the list twice */
		if (iter < desc) {
			/* We belong to the location right after iter. */
			cds_list_add(&desc->head, &iter->head);
			goto desc_added;
		}
	}
	/* We should be added at the head of the list */
	cds_list_add(&desc->head, probe_list);
desc_added:
	DBG("just registered probe %s containing %u events",
		desc->provider, desc->nr_events);
}

/*
 * Called under ust lock.
 */
static
void fixup_lazy_probes(void)
{
	struct lttng_probe_desc *iter, *tmp;
	int ret;

	lazy_nesting++;
	cds_list_for_each_entry_safe(iter, tmp,
			&lazy_probe_init, lazy_init_head) {
		lttng_lazy_probe_register(iter);
		iter->lazy = 0;
		cds_list_del(&iter->lazy_init_head);
	}
	ret = lttng_fix_pending_events();
	assert(!ret);
	lazy_nesting--;
}

/*
 * Called under ust lock.
 */
struct cds_list_head *lttng_get_probe_list_head(void)
{
	if (!lazy_nesting && !cds_list_empty(&lazy_probe_init))
		fixup_lazy_probes();
	return &_probe_list;
}

static
const struct lttng_probe_desc *find_provider(const char *provider)
{
	struct lttng_probe_desc *iter;
	struct cds_list_head *probe_list;

	probe_list = lttng_get_probe_list_head();
	cds_list_for_each_entry(iter, probe_list, head) {
		if (!strcmp(iter->provider, provider))
			return iter;
	}
	return NULL;
}

static
int check_provider_version(struct lttng_probe_desc *desc)
{
	/*
	 * Check tracepoint provider version compatibility.
	 */
	if (desc->major <= LTTNG_UST_PROVIDER_MAJOR) {
		DBG("Provider \"%s\" accepted, version %u.%u is compatible "
			"with LTTng UST provider version %u.%u.",
			desc->provider, desc->major, desc->minor,
			LTTNG_UST_PROVIDER_MAJOR,
			LTTNG_UST_PROVIDER_MINOR);
		if (desc->major < LTTNG_UST_PROVIDER_MAJOR) {
			DBG("However, some LTTng UST features might not be "
				"available for this provider unless it is "
				"recompiled against a more recent LTTng UST.");
		}
		return 1;		/* accept */
	} else {
		ERR("Provider \"%s\" rejected, version %u.%u is incompatible "
			"with LTTng UST provider version %u.%u. Please upgrade "
			"LTTng UST.",
			desc->provider, desc->major, desc->minor,
			LTTNG_UST_PROVIDER_MAJOR,
			LTTNG_UST_PROVIDER_MINOR);
		return 0;		/* reject */
	}
}


int lttng_probe_register(struct lttng_probe_desc *desc)
{
	int ret = 0;

	lttng_ust_fixup_tls();

	/*
	 * If version mismatch, don't register, but don't trigger assert
	 * on caller. The version check just prints an error.
	 */
	if (!check_provider_version(desc))
		return 0;

	ust_lock_nocheck();

	/*
	 * Check if the provider has already been registered.
	 */
	if (find_provider(desc->provider)) {
		ret = -EEXIST;
		goto end;
	}
	cds_list_add(&desc->lazy_init_head, &lazy_probe_init);
	desc->lazy = 1;
	DBG("adding probe %s containing %u events to lazy registration list",
		desc->provider, desc->nr_events);
	/*
	 * If there is at least one active session, we need to register
	 * the probe immediately, since we cannot delay event
	 * registration because they are needed ASAP.
	 */
	if (lttng_session_active())
		fixup_lazy_probes();
end:
	ust_unlock();
	return ret;
}

/* Backward compatibility with UST 2.0 */
int ltt_probe_register(struct lttng_probe_desc *desc)
{
	return lttng_probe_register(desc);
}

void lttng_probe_unregister(struct lttng_probe_desc *desc)
{
	lttng_ust_fixup_tls();

	if (!check_provider_version(desc))
		return;

	ust_lock_nocheck();
	if (!desc->lazy)
		cds_list_del(&desc->head);
	else
		cds_list_del(&desc->lazy_init_head);
	DBG("just unregistered probe %s", desc->provider);
	ust_unlock();
}

/* Backward compatibility with UST 2.0 */
void ltt_probe_unregister(struct lttng_probe_desc *desc)
{
	lttng_probe_unregister(desc);
}

void lttng_probes_prune_event_list(struct lttng_ust_tracepoint_list *list)
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
int lttng_probes_get_event_list(struct lttng_ust_tracepoint_list *list)
{
	struct lttng_probe_desc *probe_desc;
	int i;
	struct cds_list_head *probe_list;

	probe_list = lttng_get_probe_list_head();
	CDS_INIT_LIST_HEAD(&list->head);
	cds_list_for_each_entry(probe_desc, probe_list, head) {
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
	lttng_probes_prune_event_list(list);
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

void lttng_probes_prune_field_list(struct lttng_ust_field_list *list)
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
int lttng_probes_get_field_list(struct lttng_ust_field_list *list)
{
	struct lttng_probe_desc *probe_desc;
	int i;
	struct cds_list_head *probe_list;

	probe_list = lttng_get_probe_list_head();
	CDS_INIT_LIST_HEAD(&list->head);
	cds_list_for_each_entry(probe_desc, probe_list, head) {
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
	lttng_probes_prune_field_list(list);
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
