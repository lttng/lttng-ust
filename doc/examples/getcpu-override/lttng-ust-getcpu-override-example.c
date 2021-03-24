/*
 * SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2014 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 */

#include <stdlib.h>
#include <time.h>
#include <string.h>
#include <stdio.h>
#include <lttng/ust-getcpu.h>

static
int plugin_getcpu(void)
{
	/* Dummy: always return CPU 0. */
	return 0;
}

/*
 * Entry-point called by liblttng-ust through dlsym();
 */
void lttng_ust_getcpu_plugin_init(void);
void lttng_ust_getcpu_plugin_init(void)
{
	int ret;

	ret = lttng_ust_getcpu_override(plugin_getcpu);
	if (ret) {
		fprintf(stderr, "Error enabling getcpu override: %s\n",
			strerror(-ret));
		goto error;
	}
	return;

error:
	exit(EXIT_FAILURE);
}
