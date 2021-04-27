/*
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 * Copyright (C) 2021 Michael Jeanson <mjeanson@efficios.com>
 */

#include <stdio.h>
#include <lttng/ust-fork.h>

#include "./libone.h"

/*
 * Dummy function to ensure we are properly linked on liblttng-ust.so.1.
 */
void libone_dummy(void)
{
	lttng_ust_after_setns();
}

void libone(void)
{
	printf("libone: this is libone()\n");
}
