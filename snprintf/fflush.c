/*	$OpenBSD: fflush.c,v 1.7 2009/10/22 01:23:16 guenther Exp $ */
/*
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * Copyright (C) 1990, 1993
 *	The Regents of the University of California.  All rights reserved.
 *
 * This code is derived from software contributed to Berkeley by
 * Chris Torek.
 */

#include <errno.h>
#include <stdio.h>
#include "local.h"

/* Flush a single file, or (if fp is NULL) all files.  */
int ust_safe_fflush(LTTNG_UST_LFILE *fp)
{

	if (fp == NULL)
		return 0;
//		return (_fwalk(__sflush));
	if ((fp->_flags & (__SWR | __SRW)) == 0) {
		errno = EBADF;
		return (EOF);
	}
	return (__sflush(fp));
}

int
__sflush(LTTNG_UST_LFILE *fp)
{
	unsigned char *p;
	int n, t;

	t = fp->_flags;
	if ((t & __SWR) == 0)
		return (0);

	if ((p = fp->_bf._base) == NULL)
		return (0);

	n = fp->_p - p;		/* write this much */

	/*
	 * Set these immediately to avoid problems with longjmp and to allow
	 * exchange buffering (via setvbuf) in user write function.
	 */
	fp->_p = p;
	fp->_w = t & (__SLBF|__SNBF) ? 0 : fp->_bf._size;

	for (; n > 0; n -= t, p += t) {
		t = (*fp->_write)(fp->_cookie, (char *)p, n);
		if (t <= 0) {
			fp->_flags |= __SERR;
			return (EOF);
		}
	}
	return (0);
}
