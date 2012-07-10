/*
 * lttng-filter.c
 *
 * LTTng UST filter code.
 *
 * Copyright (C) 2010-2012 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
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

#include <errno.h>
#include <stdio.h>
#include <helper.h>
#include <lttng/ust-events.h>

static
int lttng_filter_interpret_bytecode(void *filter_data,
		const char *filter_stack_data)
{
	/* TODO */
	return 0;
}

static
int _lttng_filter_event_link_bytecode(struct ltt_event *event,
		struct lttng_ust_filter_bytecode *filter_bytecode)
{
	if (!filter_bytecode)
		return 0;

	event->filter = lttng_filter_interpret_bytecode;
	/* TODO */
	/* event->filter_data = ; */
	return 0;
}

void lttng_filter_event_link_bytecode(struct ltt_event *event,
		struct lttng_ust_filter_bytecode *filter_bytecode)
{
	int ret;

	ret = _lttng_filter_event_link_bytecode(event, event->filter_bytecode);
	if (ret) {
		fprintf(stderr, "[lttng filter] error linking event bytecode\n");
	}
}

/*
 * Link bytecode to all events for a wildcard. Skips events that already
 * have a bytecode linked.
 * We do not set each event's filter_bytecode field, because they do not
 * own the filter_bytecode: the wildcard owns it.
 */
void lttng_filter_wildcard_link_bytecode(struct session_wildcard *wildcard)
{
	struct ltt_event *event;
	int ret;

	if (!wildcard->filter_bytecode)
		return;

	cds_list_for_each_entry(event, &wildcard->events, wildcard_list) {
		if (event->filter)
			continue;
		ret = _lttng_filter_event_link_bytecode(event,
				wildcard->filter_bytecode);
		if (ret) {
			fprintf(stderr, "[lttng filter] error linking wildcard bytecode\n");
		}

	}
	return;
}

/*
 * Need to attach filter to an event before starting tracing for the
 * session.
 */
int lttng_filter_event_attach_bytecode(struct ltt_event *event,
		struct lttng_ust_filter_bytecode *filter_bytecode)
{
	struct lttng_ust_filter_bytecode *bc;

	if (event->chan->session->been_active)
		return -EPERM;
	if (event->filter_bytecode)
		return -EEXIST;

	bc = zmalloc(sizeof(struct lttng_ust_filter_bytecode)
			+ filter_bytecode->len);
	if (!bc)
		return -ENOMEM;
	event->filter_bytecode = bc;
	return 0;
}

/*
 * Need to attach filter to a wildcard before starting tracing for the
 * session.
 */
int lttng_filter_wildcard_attach_bytecode(struct session_wildcard *wildcard,
		struct lttng_ust_filter_bytecode *filter_bytecode)
{
	struct lttng_ust_filter_bytecode *bc;

	if (wildcard->chan->session->been_active)
		return -EPERM;
	if (wildcard->filter_bytecode)
		return -EEXIST;

	bc = zmalloc(sizeof(struct lttng_ust_filter_bytecode)
			+ filter_bytecode->len);
	if (!bc)
		return -ENOMEM;
	wildcard->filter_bytecode = bc;
	return 0;
}
