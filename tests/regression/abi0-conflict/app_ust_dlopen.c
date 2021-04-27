/*
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 * Copyright (C) 2021 Michael Jeanson <mjeanson@efficios.com>
 */

#include <dlfcn.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <arpa/inet.h>

#define LTTNG_UST_TRACEPOINT_DEFINE
#include "ust_tests_hello.h"

#define LTTNG_UST_LIB_ABI0_SO_NAME "libfakeust0.so"
#define LTTNG_UST_LIB_ABI1_SO_NAME "liblttng-ust.so.1"

static
int dlopen_ust(const char *lib_soname)
{
	int ret = EXIT_SUCCESS;
	void *handle;

	handle = dlopen(lib_soname, RTLD_NOW | RTLD_GLOBAL);
	if (!handle) {
		printf("Error: dlopen of liblttng-ust shared library (%s).\n", lib_soname);
		ret = EXIT_FAILURE;
	} else {
		printf("Success: dlopen of liblttng-ust shared library (%s).\n", lib_soname);
	}

	return ret;
}

static
int dlopen_abi0(void)
{
	return dlopen_ust(LTTNG_UST_LIB_ABI0_SO_NAME);
}

static
int dlopen_abi1(void)
{
	return dlopen_ust(LTTNG_UST_LIB_ABI1_SO_NAME);
}

static
int dlopen_abi0_abi1(void)
{
	int ret = EXIT_SUCCESS;

	ret = dlopen_ust(LTTNG_UST_LIB_ABI0_SO_NAME);
	if (ret != EXIT_SUCCESS)
		return ret;

	ret = dlopen_ust(LTTNG_UST_LIB_ABI1_SO_NAME);

	return ret;
}

static
int dlopen_abi1_abi0(void)
{
	int ret = EXIT_SUCCESS;

	ret = dlopen_ust(LTTNG_UST_LIB_ABI1_SO_NAME);
	if (ret != EXIT_SUCCESS)
		return ret;

	ret = dlopen_ust(LTTNG_UST_LIB_ABI0_SO_NAME);

	return ret;
}

static
int dlopen_abi1_abi1(void)
{
	int ret = EXIT_SUCCESS;

	ret = dlopen_ust(LTTNG_UST_LIB_ABI1_SO_NAME);
	if (ret != EXIT_SUCCESS)
		return ret;

	ret = dlopen_ust(LTTNG_UST_LIB_ABI1_SO_NAME);

	return ret;
}

static
void usage(char **argv)
{
	printf("Usage: %s <test_type>\n", argv[0]);
	printf("  test_type: abi0, abi1, abi0_abi1, abi1_abi0, abi1_abi1\n");
}

int main(int argc, char **argv)
{
	int ret = EXIT_SUCCESS;
	const char *test_type;

	int i, netint;
	long values[] = { 1, 2, 3 };
	char text[10] = "test";
	double dbl = 2.0;
	float flt = 2222.0;
	bool mybool = 123;	/* should print "1" */


	if (argc != 2) {
		usage(argv);
		return EXIT_FAILURE;
	} else {
		test_type = argv[1];
	}

	printf("This application is linked on liblttng-ust.\n");

	if (strcmp(test_type, "abi0") == 0)
		ret = dlopen_abi0();
	else if (strcmp(test_type, "abi1") == 0)
		ret = dlopen_abi1();
	else if (strcmp(test_type, "abi0_abi1") == 0)
		ret = dlopen_abi0_abi1();
	else if (strcmp(test_type, "abi1_abi0") == 0)
		ret = dlopen_abi1_abi0();
	else if (strcmp(test_type, "abi1_abi1") == 0)
		ret = dlopen_abi1_abi1();
	else {
		usage(argv);
		ret = EXIT_FAILURE;
	}

	for (i = 0; i < 10; i++) {
		netint = htonl(i);
		lttng_ust_tracepoint(ust_tests_hello, tptest, i, netint, values,
			   text, strlen(text), dbl, flt, mybool);
	}

	return ret;
}
