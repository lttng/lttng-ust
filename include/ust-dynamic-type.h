/*
 * SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2016 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 */

#ifndef _LTTNG_UST_DYNAMIC_TYPE_H
#define _LTTNG_UST_DYNAMIC_TYPE_H

#include <lttng/ust-events.h>

#include "ust-helper.h"

LTTNG_HIDDEN
int lttng_ust_dynamic_type_choices(size_t *nr_choices,
		const struct lttng_event_field **choices);
LTTNG_HIDDEN
const struct lttng_event_field *lttng_ust_dynamic_type_field(int64_t value);
LTTNG_HIDDEN
const struct lttng_event_field *lttng_ust_dynamic_type_tag_field(void);

#endif /* _LTTNG_UST_DYNAMIC_TYPE_H */
