/*
 * SPDX-License-Identifier: MIT
 *
 * Copyright 2020 (C) Francis Deslauriers <francis.deslauriers@efficios.com>
 */

#ifndef _LTTNG_UST_CONTEXT_INTERNAL_H
#define _LTTNG_UST_CONTEXT_INTERNAL_H

#include <lttng/ust-events.h>
#include "helper.h"

LTTNG_HIDDEN
int lttng_context_init_all(struct lttng_ctx **ctx);

LTTNG_HIDDEN
void lttng_context_time_ns_reset(void);

LTTNG_HIDDEN
int lttng_add_time_ns_to_ctx(struct lttng_ctx **ctx);

#endif /* _LTTNG_UST_CONTEXT_INTERNAL_H */
