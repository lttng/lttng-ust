/*
 * ust-core.c
 *
 * Copyright (C) 2011 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
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

#include <lttng/usterr-signal-safe.h>
#include <lttng/ust-events.h>
#include <stdlib.h>

CDS_LIST_HEAD(ltt_transport_list);

volatile enum ust_loglevel ust_loglevel;

void init_usterr(void)
{
	char *ust_debug;

	if (ust_loglevel == UST_LOGLEVEL_UNKNOWN) {
		ust_debug = getenv("LTTNG_UST_DEBUG");
		if (ust_debug)
			ust_loglevel = UST_LOGLEVEL_DEBUG;
		else
			ust_loglevel = UST_LOGLEVEL_NORMAL;
	}
}

struct ltt_transport *ltt_transport_find(const char *name)
{
	struct ltt_transport *transport;

	cds_list_for_each_entry(transport, &ltt_transport_list, node) {
		if (!strcmp(transport->name, name))
			return transport;
	}
	return NULL;
}

/**
 * ltt_transport_register - LTT transport registration
 * @transport: transport structure
 *
 * Registers a transport which can be used as output to extract the data out of
 * LTTng. Called with ust_lock held.
 */
void ltt_transport_register(struct ltt_transport *transport)
{
	cds_list_add_tail(&transport->node, &ltt_transport_list);
}

/**
 * ltt_transport_unregister - LTT transport unregistration
 * @transport: transport structure
 * Called with ust_lock held.
 */
void ltt_transport_unregister(struct ltt_transport *transport)
{
	cds_list_del(&transport->node);
}
