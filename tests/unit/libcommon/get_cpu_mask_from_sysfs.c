/*
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 * Copyright (C) 2022 Michael Jeanson <mjeanson@efficios.com>
 */

#include <stdio.h>
#include <stdlib.h>

#include "common/smp.h"

int main(int argc, char *argv[])
{
	int ret;
	char buf[LTTNG_UST_CPUMASK_SIZE];

	if( argc < 2 ) {
		fprintf(stderr, "Missing argument.\n");
		return EXIT_FAILURE;
	}

	ret = get_cpu_mask_from_sysfs((char *) &buf, LTTNG_UST_CPUMASK_SIZE, argv[1]);

	printf("%s", buf);

	if (ret >= 0)
		return EXIT_SUCCESS;
	else
		return EXIT_FAILURE;
}
