// SPDX-FileCopyrightText: 2011 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
//
// SPDX-License-Identifier: LGPL-2.1-or-later

#include <string.h>

#include "common/events.h"
#include "common/jhash.h"

/*
 * Needed by comm layer.
 */
struct lttng_enum *lttng_ust_enum_get_from_desc(struct lttng_ust_session *session,
		const struct lttng_ust_enum_desc *enum_desc)
{
	struct lttng_enum *_enum;
	struct cds_hlist_head *head;
	struct cds_hlist_node *node;
	size_t name_len = strlen(enum_desc->name);
	uint32_t hash;

	hash = jhash(enum_desc->name, name_len, 0);
	head = &session->priv->enums_ht.table[hash & (LTTNG_UST_ENUM_HT_SIZE - 1)];
	cds_hlist_for_each_entry(_enum, node, head, hlist) {
		assert(_enum->desc);
		if (_enum->desc == enum_desc)
			return _enum;
	}
	return NULL;
}
