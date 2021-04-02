/*
 * SPDX-License-Identifier: LGPL-2.1-or-later
 *
 * Copyright (C) 2009 Pierre-Marc Fournier
 */

#include <stdio.h>
#include <string.h>
#include "common/safe-snprintf.h"

#include "tap.h"

int main(void)
{
	char buf[100];
	const char expected_str[] = "header 9999, hello, 005, '    9'";
	const char test_fmt_str[] = "header %d, %s, %03d, '%*d'";

	plan_tests(1);

	ust_safe_snprintf(buf, 99, test_fmt_str, 9999, "hello", 5, 5, 9);

	ok(strcmp(buf, expected_str) == 0, "Got expected output string with format string \"%s\"", test_fmt_str);

	return exit_status();
}
