/*
 * SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2012 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 */

/*
 * This header defines the following endian macros based on the current
 * platform endian headers:
 *
 *   BYTE_ORDER         this macro shall have a value equal to one
 *                      of the *_ENDIAN macros in this header.
 *   FLOAT_WORD_ORDER   this macro shall have a value equal to one
 *                      of the *_ENDIAN macros in this header.
 *   LITTLE_ENDIAN      if BYTE_ORDER == LITTLE_ENDIAN, the host
 *                      byte order is from least significant to
 *                      most significant.
 *   BIG_ENDIAN         if BYTE_ORDER == BIG_ENDIAN, the host byte
 *                      order is from most significant to least
 *                      significant.
 *
 * Direct byte swapping interfaces:
 *
 *   uint16_t bswap_16(uint16_t x); (* swap bytes 16-bit word *)
 *   uint32_t bswap_32(uint32_t x); (* swap bytes 32-bit word *)
 *   uint64_t bswap_64(uint32_t x); (* swap bytes 64-bit word *)
 */

#ifndef _LTTNG_UST_ENDIAN_H
#define _LTTNG_UST_ENDIAN_H

#if (defined(__linux__) || defined(__CYGWIN__))
#include <endian.h>
#include <byteswap.h>
#elif defined(__FreeBSD__)
#include <sys/endian.h>
#define bswap_16(x)	bswap16(x)
#define bswap_32(x)	bswap32(x)
#define bswap_64(x)	bswap64(x)
#else
#error "Please add support for your OS."
#endif

/*
 * BYTE_ORDER, LITTLE_ENDIAN, and BIG_ENDIAN are only defined on Linux
 * if __USE_BSD is defined. Force their definition.
 */
#ifndef BYTE_ORDER
#define BYTE_ORDER __BYTE_ORDER
#endif

#ifndef LITTLE_ENDIAN
#define LITTLE_ENDIAN __LITTLE_ENDIAN
#endif

#ifndef BIG_ENDIAN
#define BIG_ENDIAN __BIG_ENDIAN
#endif

#ifndef FLOAT_WORD_ORDER
#ifdef __FLOAT_WORD_ORDER
#define FLOAT_WORD_ORDER	__FLOAT_WORD_ORDER
#else /* __FLOAT_WORD_ORDER */
#define FLOAT_WORD_ORDER	BYTE_ORDER
#endif /* __FLOAT_WORD_ORDER */
#endif /* FLOAT_WORD_ORDER */

#endif /* _LTTNG_UST_ENDIAN_H */
