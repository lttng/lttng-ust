#ifndef _LTTNG_UST_TRACEF_H
#define _LTTNG_UST_TRACEF_H

/*
 * Copyright (C) 2013-2014  Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
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

#include <lttng/lttng-ust-tracef.h>

#ifdef __cplusplus
extern "C" {
#endif

extern
void _lttng_ust_tracef(const char *fmt, ...);

#define tracef(fmt, ...)						\
	do {								\
		LTTNG_STAP_PROBEV(tracepoint_lttng_ust_tracef, event, ## __VA_ARGS__); \
		if (caa_unlikely(__tracepoint_lttng_ust_tracef___event.state)) \
			_lttng_ust_tracef(fmt, ## __VA_ARGS__);		\
	} while (0)

#ifdef __cplusplus
}
#endif

#endif /* _LTTNG_UST_TRACEF_H */
