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
	char name1[TEST_NAME_PROPER_LEN];
	char name2[TEST_NAME_PROPER_LEN];
	char too_long_name[] = "thisnameistoolong";
	char short_name[] = "labatt50";
	char short_name_ust[] = "labatt50-ust";
	char long_name[] = "procrastinating";
	char long_name_ust[] = "procrastina-ust";

	plan_tests(12);

	/* Get the initial thread name */
	ret = lttng_pthread_getname_np(name1, TEST_NAME_PROPER_LEN);
	ok(ret == 0, "Get the thread name: '%s'", name1);

	/* Set a thread name of more than 16 bytes, should fail */
	ret = lttng_pthread_setname_np(too_long_name);
	ok(ret == ERANGE, "Set a too long thread name: '%s'", too_long_name);

	/* Get the thread name again, shouldn't have changed */
	ret = lttng_pthread_getname_np(name2, TEST_NAME_PROPER_LEN);
	ok(ret == 0, "Get the thread name: '%s'", name2);
	ok(strcmp(name1, name2) == 0, "Compare the initial thread name: '%s' == '%s'", name1, name2);

	/* Set a thread name of less than 16 bytes */
	ret = lttng_pthread_setname_np(short_name);
	ok(ret == 0, "Set a short thread name: '%s'", short_name);

	/* Get the thread name again, should be the one we set */
	ret = lttng_pthread_getname_np(name1, TEST_NAME_PROPER_LEN);
	ok(ret == 0, "Get a short thread name: '%s'", name1);
	ok(strcmp(short_name, name1) == 0, "Compare the short thread name: '%s' == '%s'", short_name, name1);

	/* Append "-ust" to the thread name */
	lttng_ust_setustprocname();
	ret = lttng_pthread_getname_np(name1, TEST_NAME_PROPER_LEN);
	ok(strcmp(short_name_ust, name1) == 0, "Compare the short UST thread name: '%s' == '%s'", short_name_ust, name1);


	/* Set a thread name of 16 bytes */
	ret = lttng_pthread_setname_np(long_name);
	ok(ret == 0, "Set a long thread name: '%s'", long_name);

	/* Get the thread name again, should be the one we set */
	ret = lttng_pthread_getname_np(name1, TEST_NAME_PROPER_LEN);
	ok(ret == 0, "Get a long thread name: '%s'", name1);
	ok(strncmp(long_name, name1, TEST_NAME_PROPER_LEN - 1) == 0, "Compare the long thread name: '%s' == '%s'", long_name, name1);

	/* Append "-ust" to the thread name which will truncate its end */
	lttng_ust_setustprocname();
	ret = lttng_pthread_getname_np(name1, TEST_NAME_PROPER_LEN);
	ok(strcmp(long_name_ust, name1) == 0, "Compare the long UST thread name: '%s' == '%s'", long_name_ust, name1);

	return exit_status();
}
