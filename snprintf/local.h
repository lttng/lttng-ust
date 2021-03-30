/*	$OpenBSD: local.h,v 1.14 2009/10/22 01:23:16 guenther Exp $	*/

/*
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * Copyright (C) 1990, 1993
 *	The Regents of the University of California.  All rights reserved.
 *
 * This code is derived from software contributed to Berkeley by
 * Chris Torek.
 */

/*
 * Information local to this implementation of stdio,
 * in particular, macros and private variables.
 */

#include <stdio.h>
#include <wchar.h>
#include "various.h"
#include "wcio.h"
#include "fileext.h"

int	__sflush(LTTNG_UST_LFILE *)
	__attribute__((visibility("hidden")));

LTTNG_UST_LFILE	*__sfp(void)
	__attribute__((visibility("hidden")));

int	__srefill(LTTNG_UST_LFILE *)
	__attribute__((visibility("hidden")));

int	__sread(void *, char *, int)
	__attribute__((visibility("hidden")));

int	__swrite(void *, const char *, int)
	__attribute__((visibility("hidden")));

fpos_t	__sseek(void *, fpos_t, int)
	__attribute__((visibility("hidden")));

int	__sclose(void *)
	__attribute__((visibility("hidden")));

void	__sinit(void)
	__attribute__((visibility("hidden")));

void	_cleanup(void)
	__attribute__((visibility("hidden")));

void	__smakebuf(LTTNG_UST_LFILE *)
	__attribute__((visibility("hidden")));

int	__swhatbuf(LTTNG_UST_LFILE *, size_t *, int *)
	__attribute__((visibility("hidden")));

int	_fwalk(int (*)(LTTNG_UST_LFILE *))
	__attribute__((visibility("hidden")));

int	__swsetup(LTTNG_UST_LFILE *)
	__attribute__((visibility("hidden")));

int	__sflags(const char *, int *)
	__attribute__((visibility("hidden")));

wint_t __fgetwc_unlock(LTTNG_UST_LFILE *)
	__attribute__((visibility("hidden")));

extern void __atexit_register_cleanup(void (*)(void))
	__attribute__((visibility("hidden")));

extern int __sdidinit
	__attribute__((visibility("hidden")));

/*
 * Return true if the given LTTNG_UST_LFILE cannot be written now.
 */
#define	cantwrite(fp) \
	((((fp)->_flags & __SWR) == 0 || (fp)->_bf._base == NULL) && \
	 __swsetup(fp))

/*
 * Test whether the given stdio file has an active ungetc buffer;
 * release such a buffer, without restoring ordinary unread data.
 */
#define	HASUB(fp) (_UB(fp)._base != NULL)
#define	FREEUB(fp) { \
	if (_UB(fp)._base != (fp)->_ubuf) \
		free(_UB(fp)._base); \
	_UB(fp)._base = NULL; \
}

/*
 * test for an fgetln() buffer.
 */
#define	HASLB(fp) ((fp)->_lb._base != NULL)
#define	FREELB(fp) { \
	free((char *)(fp)->_lb._base); \
	(fp)->_lb._base = NULL; \
}
