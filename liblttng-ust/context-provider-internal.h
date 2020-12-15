#ifndef _LTTNG_UST_CONTEXT_PROVIDER_INTERNAL_H
#define _LTTNG_UST_CONTEXT_PROVIDER_INTERNAL_H

/*
 * Copyright 2019 - Francis Deslauriers <francis.deslauriers@efficios.com>
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

#include <stddef.h>
#include <lttng/ust-events.h>
#include "helper.h"

LTTNG_HIDDEN
void lttng_ust_context_set_event_notifier_group_provider(const char *name,
		size_t (*get_size)(struct lttng_ctx_field *field, size_t offset),
		void (*record)(struct lttng_ctx_field *field,
			struct lttng_ust_lib_ring_buffer_ctx *ctx,
			struct lttng_channel *chan),
		void (*get_value)(struct lttng_ctx_field *field,
			struct lttng_ctx_value *value));

#endif /* _LTTNG_UST_CONTEXT_PROVIDER_INTERNAL_H */
