/*
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 * Copyright (C) 2011 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 */

#ifndef _UST_COMMON_ERR_PTR_H
#define _UST_COMMON_ERR_PTR_H

#include <urcu/compiler.h>
#include <unistd.h>

#define MAX_ERRNO	4095

static inline
int IS_ERR_VALUE(long value)
{
	if (caa_unlikely((unsigned long) value >= (unsigned long) -MAX_ERRNO))
		return 1;
	else
		return 0;
}

static inline
void *ERR_PTR(long error)
{
	return (void *) error;
}

static inline
long PTR_ERR(const void *ptr)
{
	return (long) ptr;
}

static inline
int IS_ERR(const void *ptr)
{
	return IS_ERR_VALUE((long) ptr);
}

#endif /* _UST_COMMON_ERR_PTR_H */
