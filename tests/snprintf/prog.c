/* Copyright (C) 2009  Pierre-Marc Fournier
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301 USA
 */

#include <stdio.h>
#include <string.h>
#include "ust_snprintf.h"

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

	return 0;
}
