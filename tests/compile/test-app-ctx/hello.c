/*
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 * Copyright (C) 2009 Pierre-Marc Fournier
 * Copyright (C) 2011 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 */

#include <fcntl.h>
#include <signal.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
/*
 * Work-around inet.h missing struct mmsghdr forward declaration, with
 * triggers a warning when system files warnings are enabled.
 */
struct mmsghdr;
#include <arpa/inet.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdbool.h>

#define TRACEPOINT_DEFINE
#include "ust_tests_hello.h"

#include <lttng/ust-events.h>
#include <lttng/ringbuffer-context.h>
/* Internal header. */
#include <ust-context-provider.h>

static __thread unsigned int test_count;

void test_inc_count(void)
{
	test_count++;
}

static
size_t test_get_size(struct lttng_ust_ctx_field *field, size_t offset)
{
	int sel = test_count % _NR_LTTNG_UST_DYNAMIC_TYPES;
	size_t size = 0;

	size += lttng_ust_lib_ring_buffer_align(offset, lttng_ust_rb_alignof(char));
	size += sizeof(char);		/* tag */
	switch (sel) {
	case LTTNG_UST_DYNAMIC_TYPE_NONE:
		break;
	case LTTNG_UST_DYNAMIC_TYPE_S8:
		size += lttng_ust_lib_ring_buffer_align(offset, lttng_ust_rb_alignof(int8_t));
		size += sizeof(int8_t);		/* variant */
		break;
	case LTTNG_UST_DYNAMIC_TYPE_S16:
		size += lttng_ust_lib_ring_buffer_align(offset, lttng_ust_rb_alignof(int16_t));
		size += sizeof(int16_t);	/* variant */
		break;
	case LTTNG_UST_DYNAMIC_TYPE_S32:
		size += lttng_ust_lib_ring_buffer_align(offset, lttng_ust_rb_alignof(int32_t));
		size += sizeof(int32_t);	/* variant */
		break;
	case LTTNG_UST_DYNAMIC_TYPE_S64:
		size += lttng_ust_lib_ring_buffer_align(offset, lttng_ust_rb_alignof(int64_t));
		size += sizeof(int64_t);	/* variant */
		break;
	case LTTNG_UST_DYNAMIC_TYPE_U8:
		size += lttng_ust_lib_ring_buffer_align(offset, lttng_ust_rb_alignof(uint8_t));
		size += sizeof(uint8_t);		/* variant */
		break;
	case LTTNG_UST_DYNAMIC_TYPE_U16:
		size += lttng_ust_lib_ring_buffer_align(offset, lttng_ust_rb_alignof(uint16_t));
		size += sizeof(uint16_t);	/* variant */
		break;
	case LTTNG_UST_DYNAMIC_TYPE_U32:
		size += lttng_ust_lib_ring_buffer_align(offset, lttng_ust_rb_alignof(uint32_t));
		size += sizeof(uint32_t);	/* variant */
		break;
	case LTTNG_UST_DYNAMIC_TYPE_U64:
		size += lttng_ust_lib_ring_buffer_align(offset, lttng_ust_rb_alignof(uint64_t));
		size += sizeof(uint64_t);	/* variant */
		break;
	case LTTNG_UST_DYNAMIC_TYPE_FLOAT:
		size += lttng_ust_lib_ring_buffer_align(offset, lttng_ust_rb_alignof(float));
		size += sizeof(float);		/* variant */
		break;
	case LTTNG_UST_DYNAMIC_TYPE_DOUBLE:
		size += lttng_ust_lib_ring_buffer_align(offset, lttng_ust_rb_alignof(double));
		size += sizeof(double);		/* variant */
		break;
	case LTTNG_UST_DYNAMIC_TYPE_STRING:
		size += strlen("teststr") + 1;
		break;
	default:
		abort();
	}

	return size;
}

static
void test_record(struct lttng_ust_ctx_field *field,
		 struct lttng_ust_lib_ring_buffer_ctx *ctx,
		 struct lttng_ust_channel_buffer *lttng_chan_buf)
{
	int sel = test_count % _NR_LTTNG_UST_DYNAMIC_TYPES;
	char sel_char = (char) sel;

	lttng_ust_lib_ring_buffer_align_ctx(ctx, lttng_ust_rb_alignof(char));
	lttng_chan_buf->ops->event_write(ctx, &sel_char, sizeof(sel_char));
	switch (sel) {
	case LTTNG_UST_DYNAMIC_TYPE_NONE:
		break;
	case LTTNG_UST_DYNAMIC_TYPE_S8:
	{
		int8_t v = -8;

		lttng_ust_lib_ring_buffer_align_ctx(ctx, lttng_ust_rb_alignof(v));
		lttng_chan_buf->ops->event_write(ctx, &v, sizeof(v));
		break;
	}
	case LTTNG_UST_DYNAMIC_TYPE_S16:
	{
		int16_t v = -16;

		lttng_ust_lib_ring_buffer_align_ctx(ctx, lttng_ust_rb_alignof(v));
		lttng_chan_buf->ops->event_write(ctx, &v, sizeof(v));
		break;
	}
	case LTTNG_UST_DYNAMIC_TYPE_S32:
	{
		int32_t v = -32;

		lttng_ust_lib_ring_buffer_align_ctx(ctx, lttng_ust_rb_alignof(v));
		lttng_chan_buf->ops->event_write(ctx, &v, sizeof(v));
		break;
	}
	case LTTNG_UST_DYNAMIC_TYPE_S64:
	{
		int64_t v = -64;

		lttng_ust_lib_ring_buffer_align_ctx(ctx, lttng_ust_rb_alignof(v));
		lttng_chan_buf->ops->event_write(ctx, &v, sizeof(v));
		break;
	}
	case LTTNG_UST_DYNAMIC_TYPE_U8:
	{
		uint8_t v = 8;

		lttng_ust_lib_ring_buffer_align_ctx(ctx, lttng_ust_rb_alignof(v));
		lttng_chan_buf->ops->event_write(ctx, &v, sizeof(v));
		break;
	}
	case LTTNG_UST_DYNAMIC_TYPE_U16:
	{
		uint16_t v = 16;

		lttng_ust_lib_ring_buffer_align_ctx(ctx, lttng_ust_rb_alignof(v));
		lttng_chan_buf->ops->event_write(ctx, &v, sizeof(v));
		break;
	}
	case LTTNG_UST_DYNAMIC_TYPE_U32:
	{
		uint32_t v = 32;

		lttng_ust_lib_ring_buffer_align_ctx(ctx, lttng_ust_rb_alignof(v));
		lttng_chan_buf->ops->event_write(ctx, &v, sizeof(v));
		break;
	}
	case LTTNG_UST_DYNAMIC_TYPE_U64:
	{
		uint64_t v = 64;

		lttng_ust_lib_ring_buffer_align_ctx(ctx, lttng_ust_rb_alignof(v));
		lttng_chan_buf->ops->event_write(ctx, &v, sizeof(v));
		break;
	}
	case LTTNG_UST_DYNAMIC_TYPE_FLOAT:
	{
		float f = 22322.0;

		lttng_ust_lib_ring_buffer_align_ctx(ctx, lttng_ust_rb_alignof(f));
		lttng_chan_buf->ops->event_write(ctx, &f, sizeof(f));
		break;
	}
	case LTTNG_UST_DYNAMIC_TYPE_DOUBLE:
	{
		double d = 2.0;

		lttng_ust_lib_ring_buffer_align_ctx(ctx, lttng_ust_rb_alignof(d));
		lttng_chan_buf->ops->event_write(ctx, &d, sizeof(d));
		break;
	}
	case LTTNG_UST_DYNAMIC_TYPE_STRING:
	{
		const char *str = "teststr";
		lttng_chan_buf->ops->event_write(ctx, str, strlen(str) + 1);
		break;
	}
	default:
		abort();
	}
}

static
void test_get_value(struct lttng_ust_ctx_field *field,
		struct lttng_ust_ctx_value *value)
{
	int sel = test_count % _NR_LTTNG_UST_DYNAMIC_TYPES;

	value->sel = sel;
	switch (sel) {
	case LTTNG_UST_DYNAMIC_TYPE_NONE:
		break;
	case LTTNG_UST_DYNAMIC_TYPE_S8:
		value->u.s64 = -8;
		break;
	case LTTNG_UST_DYNAMIC_TYPE_S16:
		value->u.s64 = -16;
		break;
	case LTTNG_UST_DYNAMIC_TYPE_S32:
		value->u.s64 = -32;
		break;
	case LTTNG_UST_DYNAMIC_TYPE_S64:
		value->u.s64 = -64;
		break;
	case LTTNG_UST_DYNAMIC_TYPE_U8:
		value->u.u64 = 8;
		break;
	case LTTNG_UST_DYNAMIC_TYPE_U16:
		value->u.u64 = 16;
		break;
	case LTTNG_UST_DYNAMIC_TYPE_U32:
		value->u.u64 = 32;
		break;
	case LTTNG_UST_DYNAMIC_TYPE_U64:
		value->u.u64 = 64;
		break;
	case LTTNG_UST_DYNAMIC_TYPE_FLOAT:
		value->u.d = 22322.0;
		break;
	case LTTNG_UST_DYNAMIC_TYPE_DOUBLE:
		value->u.d = 2.0;
		break;
	case LTTNG_UST_DYNAMIC_TYPE_STRING:
		value->u.str = "teststr";
		break;
	default:
		abort();
	}
}

struct lttng_ust_context_provider myprovider = {
	.struct_size = sizeof(struct lttng_ust_context_provider),
	.name = "$app.myprovider",
	.get_size = test_get_size,
	.record = test_record,
	.get_value = test_get_value,
};

void inthandler(int sig)
{
	printf("in SIGUSR1 handler\n");
	tracepoint(ust_tests_hello, tptest_sighandler);
}

int init_int_handler(void)
{
	int result;
	struct sigaction act;

	memset(&act, 0, sizeof(act));
	result = sigemptyset(&act.sa_mask);
	if (result == -1) {
		perror("sigemptyset");
		return -1;
	}

	act.sa_handler = inthandler;
	act.sa_flags = SA_RESTART;

	/* Only defer ourselves. Also, try to restart interrupted
	 * syscalls to disturb the traced program as little as possible.
	 */
	result = sigaction(SIGUSR1, &act, NULL);
	if (result == -1) {
		perror("sigaction");
		return -1;
	}

	return 0;
}

void test_inc_count(void);

int main(int argc, char **argv)
{
	int i, netint;
	long values[] = { 1, 2, 3 };
	char text[10] = "test";
	double dbl = 2.0;
	float flt = 2222.0;
	int delay = 0;
	bool mybool = 123;	/* should print "1" */

	init_int_handler();

	if (argc == 2)
		delay = atoi(argv[1]);

	if (lttng_ust_context_provider_register(&myprovider))
		abort();

	fprintf(stderr, "Hello, World!\n");

	sleep(delay);

	fprintf(stderr, "Tracing... ");
	for (i = 0; i < 1000000; i++) {
		netint = htonl(i);
		tracepoint(ust_tests_hello, tptest, i, netint, values,
			   text, strlen(text), dbl, flt, mybool);
		test_inc_count();
		//usleep(100000);
	}
	lttng_ust_context_provider_unregister(&myprovider);
	fprintf(stderr, " done.\n");
	return 0;
}
