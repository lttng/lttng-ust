/*	$OpenBSD: fileext.h,v 1.2 2005/06/17 20:40:32 espie Exp $	*/
/* $NetBSD: fileext.h,v 1.5 2003/07/18 21:46:41 nathanw Exp $ */

/*
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (C)2001 Citrus Project,
 * All rights reserved.
 *
 * $Citrus$
 */

/*
 * file extension
 */
struct __lttng_ust_sfileext {
	struct	__lttng_ust_sbuf _ub; /* ungetc buffer */
	struct wchar_io_data _wcio;	/* wide char io status */
};

#define _EXT(fp) ((struct __lttng_ust_sfileext *)((fp)->_ext._base))
#define _UB(fp) _EXT(fp)->_ub

#define _FILEEXT_INIT(fp) \
do { \
	_UB(fp)._base = NULL; \
	_UB(fp)._size = 0; \
	WCIO_INIT(fp); \
} while (0)

#define _FILEEXT_SETUP(f, fext) \
do { \
	(f)->_ext._base = (unsigned char *)(fext); \
	_FILEEXT_INIT(f); \
} while (0)
