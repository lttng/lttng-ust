/*
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 * Copyright (C) 2021 Michael Jeanson <mjeanson@efficios.com>
 */

#include <stdio.h>

#include "./libzero.h"
#include "./libone.h"

int main(void)
{
	printf("This application is NOT linked on liblttng-ust.\n");

#ifdef USE_LIBZERO
	libzero();
#endif
#ifdef USE_LIBONE
	libone();
#endif

	return 0;
}
