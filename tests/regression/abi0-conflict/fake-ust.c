/*
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 * Copyright (C) 2021 Michael Jeanson <mjeanson@efficios.com>
 */

#include <stdio.h>
#include <stdint.h>

#include "./fake-ust.h"

 __attribute__((noinline)) void init_usterr(void)
{
	fprintf(stderr, "libfakeust0: init_usterr() called.\n");
}

/*
 * The symbol used by liblttng-ust.so.1 to detect liblttng-ust.so.0 in a
 * process.
 */
int ltt_probe_register(struct lttng_probe_desc *desc __attribute__((unused)))
{
	fprintf(stderr, "libfakeust0: ltt_probe_register() called.\n");
	return 0;
}

/*
 * This constructor calls the 'init_usterr' canary function which is provided
 * by liblttng-ust.so.1.
 */
static
void fake_ust_ctor(void)
	__attribute__((constructor));
static void fake_ust_ctor(void)
{
	init_usterr();
}
