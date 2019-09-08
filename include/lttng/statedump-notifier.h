#ifndef _LTTNG_STATEDUMP_NOTIFIER_H
#define _LTTNG_STATEDUMP_NOTIFIER_H

/*
 * Copyright 2015 - Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
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

#include <urcu/rculist.h>

/*
 * Application statedump notifiers can be registered by applications.
 * They will be called at trace start for a specific session, or
 * whenever the application connects to a session daemon with an active
 * UST session.
 *
 * We expect the application to call register/unregister from execution
 * contexts that do not run concurrently with fork() or clone(). The
 * application should unregister all its statedump notifiers before
 * using fork() or clone().
 *
 * The session argument is internal to lttng-ust, should be passed
 * to the instrumentation to trace statedump into the caller session
 * only.
 */
struct lttng_session;	/* Opaque to users. */

typedef void (*lttng_ust_statedump_cb)(struct lttng_session *session,
		void *priv);

struct lttng_ust_notifier {
	lttng_ust_statedump_cb callback;
	void *priv;
	struct cds_list_head node;
};

void lttng_ust_init_statedump_notifier(struct lttng_ust_notifier *notifier,
		lttng_ust_statedump_cb callback, void *priv);
void lttng_ust_register_statedump_notifier(struct lttng_ust_notifier *notifier);
void lttng_ust_unregister_statedump_notifier(struct lttng_ust_notifier *notifier);

#endif /* _LTTNG_STATEDUMP_NOTIFIER_H */
