/*	$OpenBSD: snprintf.c,v 1.16 2009/10/22 01:23:16 guenther Exp $ */
/*
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * Copyright (C) 1990, 1993
 *	The Regents of the University of California.  All rights reserved.
 *
 * This code is derived from software contributed to Berkeley by
 * Chris Torek.
 */

#include <limits.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include "local.h"
#include "common/safe-snprintf.h"

#define DUMMY_LEN	1

int ust_safe_vsnprintf(char *str, size_t n, const char *fmt, va_list ap)
{
	int ret;
	char dummy[DUMMY_LEN];
	LTTNG_UST_LFILE f;
	struct __lttng_ust_sfileext fext;

	/* While snprintf(3) specifies size_t stdio uses an int internally */
	if (n > INT_MAX)
		n = INT_MAX;
	/* Stdio internals do not deal correctly with zero length buffer */
	if (n == 0) {
		str = dummy;
		n = DUMMY_LEN;
	}
	_FILEEXT_SETUP(&f, &fext);
	f._file = -1;
	f._flags = __SWR | __SSTR;
	f._bf._base = f._p = (unsigned char *)str;
	f._bf._size = f._w = n - 1;
	ret = ust_safe_vfprintf(&f, fmt, ap);
	*f._p = '\0';
	return (ret);
}

int ust_safe_snprintf(char *str, size_t n, const char *fmt, ...)
{
	va_list ap;
	int ret;

	va_start(ap, fmt);
	ret = ust_safe_vsnprintf(str, n, fmt, ap);
	va_end(ap);

	return ret;
}
