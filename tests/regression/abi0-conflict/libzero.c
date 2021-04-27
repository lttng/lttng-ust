/*
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 * Copyright (C) 2021 Michael Jeanson <mjeanson@efficios.com>
 */

#include <stdio.h>

#include "./libzero.h"
#include "./fake-ust.h"

/*
 * Dummy function to ensure we are properly linked on libfakeust0.
 */
int libzero_dummy(void)
{
	struct lttng_probe_desc probe_desc;

	return ltt_probe_register(&probe_desc);
}

void libzero(void)
{
	printf("libzero: this is libzero()\n");
}
