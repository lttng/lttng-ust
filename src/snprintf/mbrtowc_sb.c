/*	$OpenBSD: mbrtowc_sb.c,v 1.4 2005/11/27 20:03:06 cloder Exp $	*/
/*	$NetBSD: multibyte_sb.c,v 1.4 2003/08/07 16:43:04 agc Exp $	*/

/*
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * Copyright (C) 1991 The Regents of the University of California.
 * All rights reserved.
 */

#include <errno.h>
#include <stdlib.h>
#include <wchar.h>

#include "various.h"

/*ARGSUSED*/
size_t
ust_safe_mbrtowc(wchar_t *pwc, const char *s, size_t n,
		mbstate_t *ps __attribute__((unused)))
{

	/* pwc may be NULL */
	/* s may be NULL */
	/* ps appears to be unused */

	if (s == NULL)
		return 0;
	if (n == 0)
		return (size_t)-1;
	if (pwc)
		*pwc = (wchar_t)(unsigned char)*s;
	return (*s != '\0');
}
