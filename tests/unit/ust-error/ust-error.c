/*
 * SPDX-License-Identifier: LGPL-2.1-or-later
 *
 * Copyright (C) 2021 Michael Jeanson <mjeanson@efficios.com>
 */

#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <lttng/ust-error.h>

#include "tap.h"

/*
 * Sync with liblttng-ust-comm/lttng-ust-comm.c
 */
static const char *ok_str = "Success";
static const char *unknown_str = "Unknown error";
static const char *noent_str = "No entry";
static const char *peercred_str = "Peer credentials PID is invalid. Socket appears to belong to a distinct, non-nested pid namespace.";

#define NUM_TESTS 12

static
void test_ust_error(void)
{
	const char *error_str = NULL;

	error_str = lttng_ust_strerror(LTTNG_UST_OK);
	ok(strcmp(ok_str, error_str) == 0, "lttng_ust_strerror - Positive LTTNG_UST_OK returns '%s' (%s)", ok_str, error_str);

	error_str = lttng_ust_strerror(-LTTNG_UST_OK);
	ok(strcmp(ok_str, error_str) == 0, "lttng_ust_strerror - Negative LTTNG_UST_OK returns '%s' (%s)", ok_str, error_str);

	error_str = lttng_ust_strerror(INT_MAX);
	ok(strcmp(unknown_str, error_str) == 0, "lttng_ust_strerror - Positive large int returns '%s' (%s)", unknown_str, error_str);

	error_str = lttng_ust_strerror(INT_MIN);
	ok(strcmp(unknown_str, error_str) == 0, "lttng_ust_strerror - Negative large int returns '%s' (%s)", unknown_str, error_str);

	error_str = lttng_ust_strerror(LTTNG_UST_ERR_NR);
	ok(strcmp(unknown_str, error_str) == 0, "lttng_ust_strerror - Positive LTTNG_UST_ERR_NR returns '%s' (%s)", unknown_str, error_str);

	error_str = lttng_ust_strerror(-LTTNG_UST_ERR_NR);
	ok(strcmp(unknown_str, error_str) == 0, "lttng_ust_strerror - Negative LTTNG_UST_ERR_NR returns '%s' (%s)", unknown_str, error_str);

	error_str = lttng_ust_strerror(LTTNG_UST_ERR_NR + 1);
	ok(strcmp(unknown_str, error_str) == 0, "lttng_ust_strerror - Positive LTTNG_UST_ERR_NR + 1 returns '%s' (%s)", unknown_str, error_str);

	error_str = lttng_ust_strerror(-LTTNG_UST_ERR_NR - 1);
	ok(strcmp(unknown_str, error_str) == 0, "lttng_ust_strerror - Negative LTTNG_UST_ERR_NR - 1 returns '%s' (%s)", unknown_str, error_str);

	error_str = lttng_ust_strerror(LTTNG_UST_ERR_NOENT);
	ok(strcmp(unknown_str, error_str) == 0, "lttng_ust_strerror - Positive LTTNG_UST_ERR_NOENT returns '%s' (%s)", unknown_str, error_str);

	error_str = lttng_ust_strerror(-LTTNG_UST_ERR_NOENT);
	ok(strcmp(noent_str, error_str) == 0, "lttng_ust_strerror - Negative LTTNG_UST_ERR_NOENT returns '%s' (%s)", noent_str, error_str);

	/* Last error code */
	error_str = lttng_ust_strerror(LTTNG_UST_ERR_PEERCRED_PID);
	ok(strcmp(unknown_str, error_str) == 0, "lttng_ust_strerror - Positive LTTNG_UST_ERR_PEERCRED_PID returns '%s' (%s)", unknown_str, error_str);

	error_str = lttng_ust_strerror(-LTTNG_UST_ERR_PEERCRED_PID);
	ok(strcmp(peercred_str, error_str) == 0, "lttng_ust_strerror - Negative LTTNG_UST_ERR_PEERCRED_PID returns '%s' (%s)", peercred_str, error_str);
}

int main(void)
{
	plan_tests(NUM_TESTS);

	test_ust_error();

	return exit_status();
}
