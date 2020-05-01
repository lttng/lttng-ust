/*
 * SPDX-License-Identifier: LGPL-2.1-or-later
 *
 * Copyright (C) 2013 Paul Woegerer <paul_woegerer@mentor.com>
 * Copyright (C) 2015 Antoine Busque <abusque@efficios.com>
 */

#ifndef LTTNG_UST_STATEDUMP_H
#define LTTNG_UST_STATEDUMP_H

#include <lttng/ust-events.h>

void lttng_ust_statedump_init(void);
void lttng_ust_statedump_destroy(void);

int do_lttng_ust_statedump(void *owner);

#endif /* LTTNG_UST_STATEDUMP_H */
