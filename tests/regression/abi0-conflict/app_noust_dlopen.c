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

#define LTTNG_UST_LIB_ABI0_SO_NAME "libfakeust0.so"
#define LTTNG_UST_LIB_ABI1_SO_NAME "liblttng-ust.so.1"

struct lib_desc {
	const char *soname;
	void *handle;
};

static struct lib_desc lib_desc[] = {
	[0] = {
		.soname = LTTNG_UST_LIB_ABI0_SO_NAME,
	},
	[1] = {
		.soname = LTTNG_UST_LIB_ABI1_SO_NAME,
	},
	[2] = {
		.soname = LTTNG_UST_LIB_ABI1_SO_NAME,
	},
};

static
int dlopen_ust(struct lib_desc *desc)
{
	int ret = EXIT_SUCCESS;

	desc->handle = dlopen(desc->soname, RTLD_NOW | RTLD_GLOBAL);
	if (!desc->handle) {
		printf("Error: dlopen of liblttng-ust shared library (%s).\n", desc->soname);
		ret = EXIT_FAILURE;
	} else {
		printf("Success: dlopen of liblttng-ust shared library (%s).\n", desc->soname);
	}

	return ret;
}

static
int dlopen_abi0(void)
{
	return dlopen_ust(&lib_desc[0]);
}

static
int dlopen_abi1(void)
{
	return dlopen_ust(&lib_desc[1]);
}

static
int dlopen_abi0_abi1(void)
{
	int ret = EXIT_SUCCESS;

	ret = dlopen_ust(&lib_desc[0]);
	if (ret != EXIT_SUCCESS)
		return ret;

	ret = dlopen_ust(&lib_desc[1]);

	return ret;
}

static
int dlopen_abi1_abi0(void)
{
	int ret = EXIT_SUCCESS;

	ret = dlopen_ust(&lib_desc[1]);
	if (ret != EXIT_SUCCESS)
		return ret;

	ret = dlopen_ust(&lib_desc[0]);

	return ret;
}

static
int dlopen_abi1_abi1(void)
{
	int ret = EXIT_SUCCESS;

	ret = dlopen_ust(&lib_desc[1]);
	if (ret != EXIT_SUCCESS)
		return ret;

	ret = dlopen_ust(&lib_desc[2]);

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

	if (argc != 2) {
		usage(argv);
		return EXIT_FAILURE;
	} else {
		test_type = argv[1];
	}

	printf("This application is NOT linked on liblttng-ust.\n");

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

	return ret;
}
