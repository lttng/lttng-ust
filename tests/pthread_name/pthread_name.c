/* Copyright (C) 2020 Michael Jeanson <mjeanson@efficios.com>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; only
 * version 2.1 of the License.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */

#include <stdio.h>
#include <string.h>
#include "compat.h"

#include "tap.h"

#define TEST_NAME_PROPER_LEN 16

int main()
{
	int ret;
	char name[TEST_NAME_PROPER_LEN];
	char short_name[] = "labatt50";
	char short_name_ust[] = "labatt50-ust";
	char long_name[] = "thisnameistoolong";
	char long_name_ust[] = "thisnameist-ust";

	plan_tests(9);

	ret = lttng_pthread_getname_np(name, TEST_NAME_PROPER_LEN);
	ok(ret == 0, "Get the thread name: %s", name);

	/* Set a thread name of less than 16 bytes */
	ret = lttng_pthread_setname_np(short_name);
	ok(ret == 0, "Set a short thread name: %s", short_name);

	ret = lttng_pthread_getname_np(name, TEST_NAME_PROPER_LEN);
	ok(ret == 0, "Get a short thread name: %s", name);
	ok(strcmp(short_name, name) == 0, "Compare the short thread name: %s == %s", short_name, name);

	/* Append "-ust" to the thread name */
	lttng_ust_setustprocname();
	ret = lttng_pthread_getname_np(name, TEST_NAME_PROPER_LEN);
	ok(strcmp(short_name_ust, name) == 0, "Compare the short UST thread name: %s == %s", short_name_ust, name);


	/* Set a thread name of more than 16 bytes */
	ret = lttng_pthread_setname_np(long_name);
	ok(ret == 0, "Set a long thread name: %s", long_name);

	ret = lttng_pthread_getname_np(name, TEST_NAME_PROPER_LEN);
	ok(ret == 0, "Get a truncated long thread name: %s", name);
	ok(strncmp(long_name, name, TEST_NAME_PROPER_LEN - 1) == 0, "Compare the truncated long thread name: %s == %s", long_name, name);

	/* Append "-ust" to the thread name which will truncate its end */
	lttng_ust_setustprocname();
	ret = lttng_pthread_getname_np(name, TEST_NAME_PROPER_LEN);
	ok(strcmp(long_name_ust, name) == 0, "Compare the long UST thread name: %s == %s", long_name_ust, name);

	return exit_status();
}
