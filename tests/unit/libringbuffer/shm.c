/*
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 * Copyright (C) 2020 Michael Jeanson <mjeanson@efficios.com>
 */

#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <fcntl.h>

#include "common/ringbuffer/shm.h"
#include "common/align.h"

#include "tap.h"

#define SHM_PATH "/ust-shm-test"

int main(void)
{
	int shmfd;
	size_t shmsize = LTTNG_UST_PAGE_SIZE * 10;
	struct shm_object_table *table;
	struct shm_object *shmobj;
	struct shm_ref shm_ref;

	plan_tests(5);

	/* Open a zero byte shm fd */
	shmfd = shm_open(SHM_PATH, O_RDWR | O_CREAT, S_IRUSR | S_IWUSR);
	ok(shmfd > 0, "Open a POSIX shm fd");

	/* Create a dummy shm object table to test the allocation function */
	table = shm_object_table_create(1, false);
	ok(table, "Create a shm object table");
	assert(table);

	/* This function sets the initial size of the shm with ftruncate and zeros it */
	shmobj = shm_object_table_alloc(table, shmsize, SHM_OBJECT_SHM, shmfd, -1, false);
	ok(shmobj, "Allocate the shm object table");
	assert(shmobj);

	shm_ref = zalloc_shm(shmobj, LTTNG_UST_PAGE_SIZE * 5);
	ok(shm_ref.index != -1, "Allocate an object in the shm with sufficient space");

	shm_ref = zalloc_shm(shmobj, LTTNG_UST_PAGE_SIZE * 6);
	ok(shm_ref.index == -1, "Allocate an object in the shm with insufficient space");

	/* Cleanup */
	shm_object_table_destroy(table, 1);

	return exit_status();
}
