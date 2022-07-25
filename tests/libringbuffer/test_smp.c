/*
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 * Copyright (C) 2020 Francis Deslauriers <francis.deslauriers@efficios.com>
 */

#define _GNU_SOURCE
#include <assert.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "tap.h"

#include "../../libringbuffer/smp.h"

struct parse_test_data {
	const char *buf;
	int expected;
};

static struct parse_test_data parse_test_data[] = {
	{ "", 0 },
	{ "abc", 0 },
	{ ",,,", 0 },
	{ "--", 0 },
	{ ",", 0 },
	{ "-", 0 },
	{ "2147483647", 0 },
	{ "18446744073709551615", 0 },
	{ "0-2147483647", 0 },
	{ "0-18446744073709551615", 0 },
	{ "0", 1 },
	{ "1", 2 },
	{ "0-1", 2 },
	{ "1-3", 4 },
	{ "0,2", 3 },
	{ "1,2", 3 },
	{ "0,4-6,127", 128 },
	{ "0-4095", 4096 },

	{ "\n", 0 },
	{ "abc\n", 0 },
	{ ",,,\n", 0 },
	{ "--\n", 0 },
	{ ",\n", 0 },
	{ "-\n", 0 },
	{ "2147483647\n", 0 },
	{ "18446744073709551615\n", 0 },
	{ "0-2147483647\n", 0 },
	{ "0-18446744073709551615\n", 0 },
	{ "0\n", 1 },
	{ "1\n", 2 },
	{ "0-1\n", 2 },
	{ "1-3\n", 4 },
	{ "0,2\n", 3 },
	{ "1,2\n", 3 },
	{ "0,4-6,127\n", 128 },
	{ "0-4095\n", 4096 },
};

static int parse_test_data_len = sizeof(parse_test_data) / sizeof(parse_test_data[0]);

int main(void)
{
	int ret, i;

	plan_tests(parse_test_data_len + 1);

	diag("Testing smp helpers");

	for (i = 0; i < parse_test_data_len; i++) {
		ret = get_num_possible_cpus_from_mask(parse_test_data[i].buf,
				strlen(parse_test_data[i].buf));
		ok(ret == parse_test_data[i].expected,
			"get_num_possible_cpus_from_mask '%s', expected: '%d', result: '%d'",
			parse_test_data[i].buf, parse_test_data[i].expected, ret);
	}

	ok(num_possible_cpus() > 0, "num_possible_cpus (%d > 0)", num_possible_cpus());

	return exit_status();
}
