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

	if( argc < 2 ) {
		fprintf(stderr, "Missing argument.\n");
		return EXIT_FAILURE;
	}

	ret = _get_max_cpuid_from_sysfs(argv[1]);

	printf("%d\n", ret);

	if (ret >= 0)
		return EXIT_SUCCESS;
	else
		return EXIT_FAILURE;
}
