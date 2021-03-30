/*
 * SPDX-License-Identifier: LGPL-2.1-or-later
 *
 * Copyright (C) 2013 Paul Woegerer <paul_woegerer@mentor.com>
 * Copyright (C) 2015 Antoine Busque <abusque@efficios.com>
 */

#ifndef LTTNG_UST_STATEDUMP_H
#define LTTNG_UST_STATEDUMP_H

#include <lttng/ust-events.h>

void lttng_ust_statedump_init(void)
	__attribute__((visibility("hidden")));

void lttng_ust_statedump_destroy(void)
	__attribute__((visibility("hidden")));

int do_lttng_ust_statedump(void *owner)
	__attribute__((visibility("hidden")));

#endif /* LTTNG_UST_STATEDUMP_H */
