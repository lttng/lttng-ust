#ifndef _LTTNG_UST_EVENTS_INTERNAL_H
#define _LTTNG_UST_EVENTS_INTERNAL_H

/*
 * ust-events-internal.h
 *
 * Copyright 2019 (c) - Francis Deslauriers <francis.deslauriers@efficios.com>
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

#include <urcu/list.h>
#include <urcu/hlist.h>

#include <helper.h>
#include <lttng/ust-events.h>

struct lttng_event_enabler {
	struct lttng_enabler base;
	struct cds_list_head node;	/* per-session list of enablers */
	struct lttng_channel *chan;
	/*
	 * Unused, but kept around to make it explicit that the tracer can do
	 * it.
	 */
	struct lttng_ctx *ctx;
};

struct lttng_ust_filter_bytecode_node {
	struct cds_list_head node;
	struct lttng_enabler *enabler;
	/*
	 * struct lttng_ust_filter_bytecode has var. sized array, must
	 * be last field.
	 */
	struct lttng_ust_filter_bytecode bc;
};

struct lttng_ust_excluder_node {
	struct cds_list_head node;
	struct lttng_enabler *enabler;
	/*
	 * struct lttng_ust_event_exclusion had variable sized array,
	 * must be last field.
	 */
	struct lttng_ust_event_exclusion excluder;
};

static inline
struct lttng_enabler *lttng_event_enabler_as_enabler(
		struct lttng_event_enabler *event_enabler)
{
	return &event_enabler->base;
}


/*
 * Allocate and initialize a `struct lttng_event_enabler` object.
 *
 * On success, returns a `struct lttng_event_enabler`,
 * On memory error, returns NULL.
 */
LTTNG_HIDDEN
struct lttng_event_enabler *lttng_event_enabler_create(
		enum lttng_enabler_format_type format_type,
		struct lttng_ust_event *event_param,
		struct lttng_channel *chan);

/*
 * Destroy a `struct lttng_event_enabler` object.
 */
LTTNG_HIDDEN
void lttng_event_enabler_destroy(struct lttng_event_enabler *enabler);

/*
 * Enable a `struct lttng_event_enabler` object and all events related to this
 * enabler.
 */
LTTNG_HIDDEN
int lttng_event_enabler_enable(struct lttng_event_enabler *enabler);

/*
 * Disable a `struct lttng_event_enabler` object and all events related to this
 * enabler.
 */
LTTNG_HIDDEN
int lttng_event_enabler_disable(struct lttng_event_enabler *enabler);

/*
 * Attach filter bytecode program to `struct lttng_event_enabler` and all
 * events related to this enabler.
 */
LTTNG_HIDDEN
int lttng_event_enabler_attach_bytecode(struct lttng_event_enabler *enabler,
		struct lttng_ust_filter_bytecode_node *bytecode);

/*
 * Attach an application context to an event enabler.
 *
 * Not implemented.
 */
LTTNG_HIDDEN
int lttng_event_enabler_attach_context(struct lttng_event_enabler *enabler,
		struct lttng_ust_context *ctx);

/*
 * Attach exclusion list to `struct lttng_event_enabler` and all
 * events related to this enabler.
 */
LTTNG_HIDDEN
int lttng_event_enabler_attach_exclusion(struct lttng_event_enabler *enabler,
		struct lttng_ust_excluder_node *excluder);

/*
 * Synchronize bytecodes for the enabler and the event.
 *
 * This function goes over all bytecode programs of the event enabler to ensure
 * each is linked to the provided event.
 */
LTTNG_HIDDEN
void lttng_event_enabler_link_bytecode(struct lttng_event *event,
		struct lttng_event_enabler *enabler);

#endif /* _LTTNG_UST_EVENTS_INTERNAL_H */
