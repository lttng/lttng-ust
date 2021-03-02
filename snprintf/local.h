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
#include "ust-helper.h"
#include "various.h"
#include "wcio.h"
#include "fileext.h"

LTTNG_HIDDEN
int	__sflush(LTTNG_UST_LFILE *);
LTTNG_HIDDEN
LTTNG_UST_LFILE	*__sfp(void);
LTTNG_HIDDEN
int	__srefill(LTTNG_UST_LFILE *);
LTTNG_HIDDEN
int	__sread(void *, char *, int);
LTTNG_HIDDEN
int	__swrite(void *, const char *, int);
LTTNG_HIDDEN
fpos_t	__sseek(void *, fpos_t, int);
LTTNG_HIDDEN
int	__sclose(void *);
LTTNG_HIDDEN
void	__sinit(void);
LTTNG_HIDDEN
void	_cleanup(void);
LTTNG_HIDDEN
void	__smakebuf(LTTNG_UST_LFILE *);
LTTNG_HIDDEN
int	__swhatbuf(LTTNG_UST_LFILE *, size_t *, int *);
LTTNG_HIDDEN
int	_fwalk(int (*)(LTTNG_UST_LFILE *));
LTTNG_HIDDEN
int	__swsetup(LTTNG_UST_LFILE *);
LTTNG_HIDDEN
int	__sflags(const char *, int *);
LTTNG_HIDDEN
wint_t __fgetwc_unlock(LTTNG_UST_LFILE *);

LTTNG_HIDDEN
extern void __atexit_register_cleanup(void (*)(void));
LTTNG_HIDDEN
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
