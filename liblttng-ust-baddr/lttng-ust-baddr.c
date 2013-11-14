/*
 * Copyright (C) 2013  Paul Woegerer <paul_woegerer@mentor.com>
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

#define _GNU_SOURCE
#include <dlfcn.h>
#include <link.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/stat.h>
#include <unistd.h>
#include <limits.h>
#include <stdlib.h>
#include <errno.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include "usterr.h"

#define TRACEPOINT_DEFINE
#include "ust_baddr.h"

int
lttng_ust_push_baddr(void *so_base, const char *so_name)
{
	char resolved_path[PATH_MAX];
	struct stat sostat;

	if (!realpath(so_name, resolved_path)) {
		ERR("could not resolve path '%s'", so_name);
		return 0;
	}

	if (stat(resolved_path, &sostat)) {
		ERR("could not access file status for %s", resolved_path);
		return 0;
	}

	tracepoint(ust_baddr, push,
		so_base, resolved_path, sostat.st_size, sostat.st_mtime);
	return 0;
}

int
lttng_ust_pop_baddr(void *so_base)
{
	tracepoint(ust_baddr, pop, so_base);
	return 0;
}
