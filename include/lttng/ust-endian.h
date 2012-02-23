#ifndef _LTTNG_UST_ENDIAN_H
#define _LTTNG_UST_ENDIAN_H

/*
 * lttng/ust-endian.h
 *
 * Copyright 2012 (c) - Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 *
 * endian.h compatibility layer.
 *
 * THIS MATERIAL IS PROVIDED AS IS, WITH ABSOLUTELY NO WARRANTY EXPRESSED
 * OR IMPLIED.  ANY USE IS AT YOUR OWN RISK.
 *
 * Permission is hereby granted to use or copy this program
 * for any purpose,  provided the above notices are retained on all copies.
 * Permission to modify the code and to distribute modified code is granted,
 * provided the above notices are retained, and a notice that the code was
 * modified is included with the above copyright notice.
 */

#ifdef __linux__
#include <endian.h>
#elif defined(__FreeBSD__)
#include <machine/endian.h>
#else
#error "Please add support for your OS."
#endif

#ifndef FLOAT_WORD_ORDER
#ifdef __FLOAT_WORD_ORDER
#define FLOAT_WORD_ORDER	__FLOAT_WORD_ORDER
#else /* __FLOAT_WORD_ORDER */
#define FLOAT_WORD_ORDER	BYTE_ORDER
#endif /* __FLOAT_WORD_ORDER */
#endif /* FLOAT_WORD_ORDER */

#endif /* _LTTNG_UST_ENDIAN_H */
