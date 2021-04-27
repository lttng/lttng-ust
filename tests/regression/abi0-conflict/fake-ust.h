/*
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 * Copyright (C) 2021 Michael Jeanson <mjeanson@efficios.com>
 */

#define LTTNG_UST_PROBE_DESC_PADDING    12
struct lttng_probe_desc {
        char padding[LTTNG_UST_PROBE_DESC_PADDING];
};

void init_usterr(void);

/*
 * The symbol used by liblttng-ust.so.1 to detect liblttng-ust.so.0 in a
 * process.
 */
int ltt_probe_register(struct lttng_probe_desc *desc);
