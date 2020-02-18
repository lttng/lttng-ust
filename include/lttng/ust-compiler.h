#ifndef _LTTNG_UST_COMPILER_H
#define _LTTNG_UST_COMPILER_H

/*
 * Copyright 2011-2012 - Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 *                       Paul Woegerer <paul_woegerer@mentor.com>
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

#define lttng_ust_notrace __attribute__((no_instrument_function))
#define LTTNG_PACKED	__attribute__((__packed__))

/*
 * Clang supports the no_sanitize variable attribute on global variables.
 * GCC only supports the no_sanitize_address function attribute, which is
 * not what we need.
 */
#if defined(__clang__)
# if __has_feature(address_sanitizer)
#  define __lttng_ust_variable_attribute_no_sanitize_address \
	__attribute__((no_sanitize("address")))
# else
#  define __lttng_ust_variable_attribute_no_sanitize_address
# endif
#else
#  define __lttng_ust_variable_attribute_no_sanitize_address
#endif

#endif /* _LTTNG_UST_COMPILER_H */
