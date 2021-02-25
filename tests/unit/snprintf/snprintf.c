/*
 * SPDX-License-Identifier: LGPL-2.1-or-later
 *
 * Copyright (C) 2009 Pierre-Marc Fournier
 */

#include <stdio.h>
#include <string.h>
#include "ust-snprintf.h"

#include "tap.h"

int main()
{
	char buf[100];
	char *expected;
	char test_fmt_str[] = "header %d, %s, %03d, '%3$*d'";
	char escaped_test_fmt_str[] = "header %%d, %%s, %%03d, '%%3$*d'";

	plan_tests(1);

	expected = "header 9999, hello, 005, '    9'";
	ust_safe_snprintf(buf, 99, test_fmt_str, 9999, "hello", 5, 9);

	char test_desc_fmt_str[] = "Got expected output string with format string \"%s\"";
	char test_desc[sizeof(escaped_test_fmt_str) + sizeof(test_desc_fmt_str) - 1];
	sprintf(test_desc, test_desc_fmt_str, escaped_test_fmt_str);
	ok(strcmp(buf, expected) == 0, test_desc);

	return exit_status();
}
