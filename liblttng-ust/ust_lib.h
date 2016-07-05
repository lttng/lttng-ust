#undef TRACEPOINT_PROVIDER
#define TRACEPOINT_PROVIDER lttng_ust_lib

#if !defined(_TRACEPOINT_UST_LIB_H) || defined(TRACEPOINT_HEADER_MULTI_READ)
#define _TRACEPOINT_UST_LIB_H

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Copyright (C) 2013  Paul Woegerer <paul_woegerer@mentor.com>
 * Copyright (C) 2015  Antoine Busque <abusque@efficios.com>
 * Copyright (C) 2016  Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#include <stdint.h>
#include <unistd.h>

#define LTTNG_UST_LIB_PROVIDER
#include <lttng/tracepoint.h>

TRACEPOINT_EVENT(lttng_ust_lib, load,
	TP_ARGS(void *, ip, void *, baddr, const char*, path,
		uint64_t, memsz, uint8_t, has_build_id,
		uint8_t, has_debug_link),
	TP_FIELDS(
		ctf_integer_hex(void *, baddr, baddr)
		ctf_integer(uint64_t, memsz, memsz)
		ctf_string(path, path)
		ctf_integer(uint8_t, has_build_id, has_build_id)
		ctf_integer(uint8_t, has_debug_link, has_debug_link)
	)
)

TRACEPOINT_EVENT(lttng_ust_lib, build_id,
	TP_ARGS(
		void *, ip,
		void *, baddr,
		uint8_t *, build_id,
		size_t, build_id_len
	),
	TP_FIELDS(
		ctf_integer_hex(void *, baddr, baddr)
		ctf_sequence_hex(uint8_t, build_id, build_id,
			size_t, build_id_len)
	)
)

TRACEPOINT_EVENT(lttng_ust_lib, debug_link,
	TP_ARGS(
		void *, ip,
		void *, baddr,
		char *, filename,
		uint32_t, crc
	),
	TP_FIELDS(
		ctf_integer_hex(void *, baddr, baddr)
		ctf_integer(uint32_t, crc, crc)
		ctf_string(filename, filename)
	)
)

TRACEPOINT_EVENT(lttng_ust_lib, unload,
	TP_ARGS(void *, ip, void *, baddr),
	TP_FIELDS(
		ctf_integer_hex(void *, baddr, baddr)
	)
)

#endif /* _TRACEPOINT_UST_LIB_H */

#undef TRACEPOINT_INCLUDE
#define TRACEPOINT_INCLUDE "./ust_lib.h"

/* This part must be outside ifdef protection */
#include <lttng/tracepoint-event.h>

#ifdef __cplusplus
}
#endif
