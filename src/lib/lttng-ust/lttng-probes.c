/*
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 * Copyright 2010-2012 (C) Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 *
 * Holds LTTng probes registry.
 */

#define _LGPL_SOURCE
#include <string.h>
#include <errno.h>
#include <urcu/list.h>
#include <urcu/hlist.h>
#include <lttng/ust-events.h>
#include <lttng/tracepoint.h>
#include "common/tracepoint.h"
#include <assert.h>
#include "common/macros.h"
#include <ctype.h>

#include "lttng-tracer-core.h"
#include "common/jhash.h"
#include "lib/lttng-ust/events.h"

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
 * Validate that each event within the probe provider refers to the
 * right probe, and that the resulting name is not too long.
 */
static
bool check_event_provider(const struct lttng_ust_probe_desc *probe_desc)
{
	int i;

	for (i = 0; i < probe_desc->nr_events; i++) {
		const struct lttng_ust_event_desc *event_desc = probe_desc->event_desc[i];

		if (event_desc->probe_desc != probe_desc) {
			ERR("Error registering probe provider '%s'. Event '%s:%s' refers to the wrong provider descriptor.",
				probe_desc->provider_name, probe_desc->provider_name, event_desc->event_name);
			return false;	/* provider mismatch */
		}
		if (!lttng_ust_validate_event_name(event_desc)) {
			ERR("Error registering probe provider '%s'. Event '%s:%s' name is too long.",
				probe_desc->provider_name, probe_desc->provider_name, event_desc->event_name);
			return false;	/* provider mismatch */
		}
	}
	return true;
}

/*
 * Called under ust lock.
 */
static
void lttng_lazy_probe_register(struct lttng_ust_registered_probe *reg_probe)
{
	struct lttng_ust_registered_probe *iter;
	struct cds_list_head *probe_list;

	/*
	 * The provider ensures there are no duplicate event names.
	 * Duplicated LTTNG_UST_TRACEPOINT_EVENT event names would generate a
	 * compile-time error due to duplicated symbol names.
	 */

	/*
	 * We sort the providers by struct lttng_ust_probe_desc pointer
	 * address.
	 */
	probe_list = &_probe_list;
	cds_list_for_each_entry_reverse(iter, probe_list, head) {
		BUG_ON(iter == reg_probe); /* Should never be in the list twice */
		if (iter < reg_probe) {
			/* We belong to the location right after iter. */
			cds_list_add(&reg_probe->head, &iter->head);
			goto probe_added;
		}
	}
	/* We should be added at the head of the list */
	cds_list_add(&reg_probe->head, probe_list);
probe_added:
	DBG("just registered probe %s containing %u events",
		reg_probe->desc->provider_name, reg_probe->desc->nr_events);
}

/*
 * Called under ust lock.
 */
static
void fixup_lazy_probes(void)
{
	struct lttng_ust_registered_probe *iter, *tmp;
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
int check_provider_version(const struct lttng_ust_probe_desc *desc)
{
	/*
	 * Check tracepoint provider version compatibility.
	 */
	if (desc->major <= LTTNG_UST_PROVIDER_MAJOR) {
		DBG("Provider \"%s\" accepted, version %u.%u is compatible "
			"with LTTng UST provider version %u.%u.",
			desc->provider_name, desc->major, desc->minor,
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
			desc->provider_name, desc->major, desc->minor,
			LTTNG_UST_PROVIDER_MAJOR,
			LTTNG_UST_PROVIDER_MINOR);
		return 0;		/* reject */
	}
}

struct lttng_ust_registered_probe *lttng_ust_probe_register(const struct lttng_ust_probe_desc *desc)
{
	struct lttng_ust_registered_probe *reg_probe = NULL;

	lttng_ust_fixup_tls();

	/*
	 * If version mismatch, don't register, but don't trigger assert
	 * on caller. The version check just prints an error.
	 */
	if (!check_provider_version(desc))
		return NULL;
	if (!check_event_provider(desc))
		return NULL;

	ust_lock_nocheck();

	reg_probe = zmalloc(sizeof(struct lttng_ust_registered_probe));
	if (!reg_probe)
		goto end;
	reg_probe->desc = desc;
	cds_list_add(&reg_probe->lazy_init_head, &lazy_probe_init);
	reg_probe->lazy = 1;

	DBG("adding probe %s containing %u events to lazy registration list",
		desc->provider_name, desc->nr_events);
	/*
	 * If there is at least one active session, we need to register
	 * the probe immediately, since we cannot delay event
	 * registration because they are needed ASAP.
	 */
	if (lttng_session_active())
		fixup_lazy_probes();

	lttng_fix_pending_event_notifiers();
end:
	ust_unlock();
	return reg_probe;
}

void lttng_ust_probe_unregister(struct lttng_ust_registered_probe *reg_probe)
{
	lttng_ust_fixup_tls();

	if (!reg_probe)
		return;
	if (!check_provider_version(reg_probe->desc))
		return;

	ust_lock_nocheck();
	if (!reg_probe->lazy)
		cds_list_del(&reg_probe->head);
	else
		cds_list_del(&reg_probe->lazy_init_head);

	lttng_probe_provider_unregister_events(reg_probe->desc);
	DBG("just unregistered probes of provider %s", reg_probe->desc->provider_name);
	ust_unlock();
	free(reg_probe);
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
	struct lttng_ust_registered_probe *reg_probe;
	struct cds_list_head *probe_list;
	int i;

	probe_list = lttng_get_probe_list_head();
	CDS_INIT_LIST_HEAD(&list->head);
	cds_list_for_each_entry(reg_probe, probe_list, head) {
		const struct lttng_ust_probe_desc *probe_desc = reg_probe->desc;

		for (i = 0; i < probe_desc->nr_events; i++) {
			const struct lttng_ust_event_desc *event_desc =
				probe_desc->event_desc[i];
			struct tp_list_entry *list_entry;

			/* Skip event if name is too long. */
			if (!lttng_ust_validate_event_name(event_desc))
				continue;
			list_entry = zmalloc(sizeof(*list_entry));
			if (!list_entry)
				goto err_nomem;
			cds_list_add(&list_entry->head, &list->head);
			lttng_ust_format_event_name(event_desc, list_entry->tp.name);
			if (!event_desc->loglevel) {
				list_entry->tp.loglevel = LTTNG_UST_TRACEPOINT_LOGLEVEL_DEFAULT;
			} else {
				list_entry->tp.loglevel = *(*event_desc->loglevel);
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
struct lttng_ust_abi_tracepoint_iter *
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
	struct lttng_ust_registered_probe *reg_probe;
	struct cds_list_head *probe_list;
	int i;

	probe_list = lttng_get_probe_list_head();
	CDS_INIT_LIST_HEAD(&list->head);
	cds_list_for_each_entry(reg_probe, probe_list, head) {
		const struct lttng_ust_probe_desc *probe_desc = reg_probe->desc;

		for (i = 0; i < probe_desc->nr_events; i++) {
			const struct lttng_ust_event_desc *event_desc =
				probe_desc->event_desc[i];
			int j;

			if (event_desc->nr_fields == 0) {
				/* Events without fields. */
				struct tp_field_list_entry *list_entry;

				/* Skip event if name is too long. */
				if (!lttng_ust_validate_event_name(event_desc))
					continue;
				list_entry = zmalloc(sizeof(*list_entry));
				if (!list_entry)
					goto err_nomem;
				cds_list_add(&list_entry->head, &list->head);
				lttng_ust_format_event_name(event_desc, list_entry->field.event_name);
				list_entry->field.field_name[0] = '\0';
				list_entry->field.type = LTTNG_UST_ABI_FIELD_OTHER;
				if (!event_desc->loglevel) {
					list_entry->field.loglevel = LTTNG_UST_TRACEPOINT_LOGLEVEL_DEFAULT;
				} else {
					list_entry->field.loglevel = *(*event_desc->loglevel);
				}
				list_entry->field.nowrite = 1;
			}

			for (j = 0; j < event_desc->nr_fields; j++) {
				const struct lttng_ust_event_field *event_field =
					event_desc->fields[j];
				struct tp_field_list_entry *list_entry;

				/* Skip event if name is too long. */
				if (!lttng_ust_validate_event_name(event_desc))
					continue;
				list_entry = zmalloc(sizeof(*list_entry));
				if (!list_entry)
					goto err_nomem;
				cds_list_add(&list_entry->head, &list->head);
				lttng_ust_format_event_name(event_desc, list_entry->field.event_name);
				strncpy(list_entry->field.field_name,
					event_field->name,
					LTTNG_UST_ABI_SYM_NAME_LEN);
				list_entry->field.field_name[LTTNG_UST_ABI_SYM_NAME_LEN - 1] = '\0';
				switch (event_field->type->type) {
				case lttng_ust_type_integer:
					list_entry->field.type = LTTNG_UST_ABI_FIELD_INTEGER;
					break;
				case lttng_ust_type_string:
					list_entry->field.type = LTTNG_UST_ABI_FIELD_STRING;
					break;
				case lttng_ust_type_array:
					if (lttng_ust_get_type_array(event_field->type)->encoding == lttng_ust_string_encoding_none)
						list_entry->field.type = LTTNG_UST_ABI_FIELD_OTHER;
					else
						list_entry->field.type = LTTNG_UST_ABI_FIELD_STRING;
					break;
				case lttng_ust_type_sequence:
					if (lttng_ust_get_type_sequence(event_field->type)->encoding == lttng_ust_string_encoding_none)
						list_entry->field.type = LTTNG_UST_ABI_FIELD_OTHER;
					else
						list_entry->field.type = LTTNG_UST_ABI_FIELD_STRING;
					break;
				case lttng_ust_type_float:
					list_entry->field.type = LTTNG_UST_ABI_FIELD_FLOAT;
					break;
				case lttng_ust_type_enum:
					list_entry->field.type = LTTNG_UST_ABI_FIELD_ENUM;
					break;
				default:
					list_entry->field.type = LTTNG_UST_ABI_FIELD_OTHER;
				}
				if (!event_desc->loglevel) {
					list_entry->field.loglevel = LTTNG_UST_TRACEPOINT_LOGLEVEL_DEFAULT;
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
struct lttng_ust_abi_field_iter *
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
