/*
 * Copyright (C) 2015  Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
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

#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <lttng/statedump-notifier.h>

#define TRACEPOINT_DEFINE
#define TRACEPOINT_CREATE_PROBES
#define TP_SESSION_CHECK
#include "lttng-ust-demo-statedump-provider.h"

static struct lttng_ust_notifier notifier;

static void notifier_cb(struct lttng_session *session, void *priv)
{
	tracepoint(lttng_ust_demo_statedump, myevent, session, 123,
		"test string");
	tracepoint(lttng_ust_demo_statedump, myevent, session, 444,
		"another string");
}

int main(int argc, char **argv)
{
	int delay = 0;

	if (argc == 2)
		delay = atoi(argv[1]);

	fprintf(stderr, "Demo program starting.\n");

	lttng_ust_init_statedump_notifier(&notifier, notifier_cb, NULL);
	lttng_ust_register_statedump_notifier(&notifier);

	sleep(delay);

	lttng_ust_unregister_statedump_notifier(&notifier);

	fprintf(stderr, " done.\n");
	return 0;
}
