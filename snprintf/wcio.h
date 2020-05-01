/*	$OpenBSD: wcio.h,v 1.1 2005/06/17 20:40:32 espie Exp $	*/
/* $NetBSD: wcio.h,v 1.3 2003/01/18 11:30:00 thorpej Exp $ */

/*
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (C)2001 Citrus Project,
 * All rights reserved.
 *
 * $Citrus$
 */

#ifndef _WCIO_H_
#define _WCIO_H_

#include <stddef.h>
#include <wchar.h>

/* minimal requirement of SUSv2 */
#define WCIO_UNGETWC_BUFSIZE 1

struct wchar_io_data {
	mbstate_t wcio_mbstate_in;
	mbstate_t wcio_mbstate_out;

	wchar_t wcio_ungetwc_buf[WCIO_UNGETWC_BUFSIZE];
	size_t wcio_ungetwc_inbuf;

	int wcio_mode; /* orientation */
};

#define WCIO_GET(fp) \
	(_EXT(fp) ? &(_EXT(fp)->_wcio) : (struct wchar_io_data *)0)

#define WCIO_GET_NONULL(fp) \
	(&(_EXT(fp)->_wcio))

#define _SET_ORIENTATION(fp, mode) \
do {\
	struct wchar_io_data *_wcio = WCIO_GET(fp); \
	if (_wcio && _wcio->wcio_mode == 0) \
		_wcio->wcio_mode = (mode);\
} while (0)

/*
 * WCIO_FREE should be called by fclose
 */
#define WCIO_FREE(fp) \
do {\
	struct wchar_io_data *_wcio = WCIO_GET(fp); \
	if (_wcio) { \
		_wcio->wcio_mode = 0;\
		_wcio->wcio_ungetwc_inbuf = 0;\
	} \
} while (0)

#define WCIO_FREEUB(fp) \
do {\
	struct wchar_io_data *_wcio = WCIO_GET(fp); \
	if (_wcio) { \
		_wcio->wcio_ungetwc_inbuf = 0;\
	} \
} while (0)

#define WCIO_INIT(fp) \
	memset(WCIO_GET_NONULL(fp), 0, sizeof(struct wchar_io_data))

#endif /*_WCIO_H_*/
