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

int	__sflush(LTTNG_UST_LFILE *);
LTTNG_UST_LFILE	*__sfp(void);
int	__srefill(LTTNG_UST_LFILE *);
int	__sread(void *, char *, int);
int	__swrite(void *, const char *, int);
fpos_t	__sseek(void *, fpos_t, int);
int	__sclose(void *);
void	__sinit(void);
void	_cleanup(void);
void	__smakebuf(LTTNG_UST_LFILE *);
int	__swhatbuf(LTTNG_UST_LFILE *, size_t *, int *);
int	_fwalk(int (*)(LTTNG_UST_LFILE *));
int	__swsetup(LTTNG_UST_LFILE *);
int	__sflags(const char *, int *);
wint_t __fgetwc_unlock(LTTNG_UST_LFILE *);

extern void __atexit_register_cleanup(void (*)(void));
extern int __sdidinit;

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
