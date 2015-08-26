/*
 * statedump-notifier.c
 *
 * Copyright (C) 2015 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
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
#define _GNU_SOURCE
#include <lttng/statedump-notifier.h>
#include <urcu/rculist.h>
#include <urcu-bp.h>
#include <lttng/ust-events.h>
#include "lttng-ust-statedump.h"
#include "lttng-tracer-core.h"

/*
 * The notifier list is a RCU list (RCU read-side, synchronize_rcu
 * between removal and re-use) that has updates protected by the
 * ust_lock().
 */
static CDS_LIST_HEAD(notifiers);

/*
 * The ust lock ensures consistency of the notifier between the
 * per-session notifier hash set and the notifiers list.
 */
void lttng_ust_init_statedump_notifier(struct lttng_ust_notifier *notifier,
		lttng_ust_statedump_cb callback, void *priv)
{
	notifier->callback = callback;
	notifier->priv = priv;
}

void lttng_ust_register_statedump_notifier(struct lttng_ust_notifier *notifier)
{
	struct lttng_session *session;
	struct cds_list_head *sessionsp;

	ust_lock_nocheck();
	cds_list_add_tail_rcu(&notifier->node, &notifiers);

	sessionsp = _lttng_get_sessions();
	cds_list_for_each_entry(session, sessionsp, node) {
		/*
		 * Adding this notifier to the statedump table of each
		 * session ensures that we don't have duplicate events.
		 */
		if (lttng_statedump_table_add(session->statedump_table, notifier))
			abort();
	}
	ust_unlock();

	/* Run this notifier for each session. */
	lttng_ust_run_statedump_notifier_for_each_session(notifier);
}

void lttng_ust_unregister_statedump_notifier(struct lttng_ust_notifier *notifier)
{
	struct lttng_session *session;
	struct cds_list_head *sessionsp;

	ust_lock_nocheck();
	cds_list_del_rcu(&notifier->node);

	sessionsp = _lttng_get_sessions();
	cds_list_for_each_entry(session, sessionsp, node) {
		if (lttng_statedump_table_del(session->statedump_table, notifier))
			abort();
	}
	ust_unlock();
	/*
	 * Ensure we wait for a grace period before letting the
	 * application re-use the notifier.
	 */
	synchronize_rcu();
}

/* Returns 1 if notifier was already run, 0 otherwise. */
static int lttng_ust_notifier_test_and_set(struct lttng_session *session,
		struct lttng_ust_notifier *notifier)
{
	int ret;

	if (ust_lock()) {
		ret = -EEXIST;
		goto unlock;
	}
	ret = lttng_statedump_table_add(session->statedump_table,
			notifier);
unlock:
	ust_unlock();
	if (ret == -ENOMEM)
		abort();
	if (ret == -EEXIST)
		return 1;
	return 0;
}

void lttng_ust_run_statedump_notifiers(void *owner)
{
	struct cds_list_head *sessionsp;
	struct lttng_session *session;

	rcu_read_lock();
	sessionsp = _lttng_get_sessions();
	cds_list_for_each_entry_rcu(session, sessionsp, node) {
		struct lttng_ust_notifier *notifier;

		if (session->owner != owner)
			continue;
		if (!session->statedump_pending)
			continue;
		cds_list_for_each_entry_rcu(notifier, &notifiers, node) {
			if (!lttng_ust_notifier_test_and_set(session, notifier))
				notifier->callback(session, notifier->priv);
		}
	}
	rcu_read_unlock();
}
