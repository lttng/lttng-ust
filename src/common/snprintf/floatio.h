/*	$OpenBSD: floatio.h,v 1.4 2008/09/07 20:36:08 martynas Exp $	*/

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
 * Floating point scanf/printf (input/output) definitions.
 */

/* 11-bit exponent (VAX G floating point) is 308 decimal digits */
#define	MAXEXP		308
/* 128 bit fraction takes up 39 decimal digits; max reasonable precision */
#define	MAXFRACT	39

/*
 * MAXEXPDIG is the maximum number of decimal digits needed to store a
 * floating point exponent in the largest supported format.  It should
 * be ceil(log10(LDBL_MAX_10_EXP)) or, if hexadecimal floating point
 * conversions are supported, ceil(log10(LDBL_MAX_EXP)).  But since it
 * is presently never greater than 5 in practice, we fudge it.
 */
#define	MAXEXPDIG	6
#if LDBL_MAX_EXP > 999999
#error "floating point buffers too small"
#endif

char *__hdtoa(double, const char *, int, int *, int *, char **)
	__attribute__((visibility("hidden")));

char *__hldtoa(long double, const char *, int, int *, int *, char **)
	__attribute__((visibility("hidden")));

char *__ldtoa(long double *, int, int, int *, int *, char **)
	__attribute__((visibility("hidden")));
