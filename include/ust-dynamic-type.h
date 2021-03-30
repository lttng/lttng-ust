/*
 * SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2016 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 */

#ifndef _LTTNG_UST_DYNAMIC_TYPE_H
#define _LTTNG_UST_DYNAMIC_TYPE_H

#include <lttng/ust-events.h>

enum lttng_ust_dynamic_type {
	LTTNG_UST_DYNAMIC_TYPE_NONE,
	LTTNG_UST_DYNAMIC_TYPE_S8,
	LTTNG_UST_DYNAMIC_TYPE_S16,
	LTTNG_UST_DYNAMIC_TYPE_S32,
	LTTNG_UST_DYNAMIC_TYPE_S64,
	LTTNG_UST_DYNAMIC_TYPE_U8,
	LTTNG_UST_DYNAMIC_TYPE_U16,
	LTTNG_UST_DYNAMIC_TYPE_U32,
	LTTNG_UST_DYNAMIC_TYPE_U64,
	LTTNG_UST_DYNAMIC_TYPE_FLOAT,
	LTTNG_UST_DYNAMIC_TYPE_DOUBLE,
	LTTNG_UST_DYNAMIC_TYPE_STRING,
	_NR_LTTNG_UST_DYNAMIC_TYPES,
};

int lttng_ust_dynamic_type_choices(size_t *nr_choices,
		struct lttng_ust_event_field ***choices)
	__attribute__((visibility("hidden")));

struct lttng_ust_event_field *lttng_ust_dynamic_type_field(int64_t value)
	__attribute__((visibility("hidden")));

struct lttng_ust_event_field *lttng_ust_dynamic_type_tag_field(void)
	__attribute__((visibility("hidden")));

#endif /* _LTTNG_UST_DYNAMIC_TYPE_H */
