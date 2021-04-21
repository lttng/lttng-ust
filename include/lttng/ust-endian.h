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

#define lttng_ust_bswap_16(x)		bswap_16(x)
#define lttng_ust_bswap_32(x)		bswap_32(x)
#define lttng_ust_bswap_64(x)		bswap_64(x)

#define LTTNG_UST_BYTE_ORDER		__BYTE_ORDER
#define LTTNG_UST_LITTLE_ENDIAN		__LITTLE_ENDIAN
#define LTTNG_UST_BIG_ENDIAN		__BIG_ENDIAN

#ifdef __FLOAT_WORD_ORDER
#define LTTNG_UST_FLOAT_WORD_ORDER	__FLOAT_WORD_ORDER
#else /* __FLOAT_WORD_ORDER */
#define LTTNG_UST_FLOAT_WORD_ORDER	__BYTE_ORDER
#endif /* __FLOAT_WORD_ORDER */

#elif defined(__FreeBSD__)

#include <sys/endian.h>

#define lttng_ust_bswap_16(x)		bswap16(x)
#define lttng_ust_bswap_32(x)		bswap32(x)
#define lttng_ust_bswap_64(x)		bswap64(x)

#define LTTNG_UST_BYTE_ORDER		BYTE_ORDER
#define LTTNG_UST_LITTLE_ENDIAN		LITTLE_ENDIAN
#define LTTNG_UST_BIG_ENDIAN		BIG_ENDIAN
#define FLOAT_WORD_ORDER		BYTE_ORDER

#else
#error "Please add support for your OS."
#endif

#endif /* _LTTNG_UST_ENDIAN_H */
