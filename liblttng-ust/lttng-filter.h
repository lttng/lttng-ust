#ifndef _LTTNG_FILTER_H
#define _LTTNG_FILTER_H

/*
 * lttng-filter.h
 *
 * LTTng UST filter header.
 *
 * Copyright (C) 2010-2016 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
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

#include <errno.h>
#include <stdio.h>
#include <helper.h>
#include <lttng/ust-events.h>
#include <lttng/ust-context-provider.h>
#include <stdint.h>
#include <assert.h>
#include <errno.h>
#include <string.h>
#include <inttypes.h>
#include <limits.h>
#include <usterr-signal-safe.h>
#include "filter-bytecode.h"

/* Filter stack length, in number of entries */
#define FILTER_STACK_LEN	10	/* includes 2 dummy */
#define FILTER_STACK_EMPTY	1

#ifndef min_t
#define min_t(type, a, b)	\
		((type) (a) < (type) (b) ? (type) (a) : (type) (b))
#endif

#ifndef likely
#define likely(x)	__builtin_expect(!!(x), 1)
#endif

#ifndef unlikely
#define unlikely(x)	__builtin_expect(!!(x), 0)
#endif

#ifdef DEBUG
#define dbg_printf(fmt, args...)				\
	printf("[debug bytecode in %s:%s@%u] " fmt,		\
		__FILE__, __func__, __LINE__, ## args)
#else
#define dbg_printf(fmt, args...)				\
do {								\
	/* do nothing but check printf format */		\
	if (0)							\
		printf("[debug bytecode in %s:%s@%u] " fmt,	\
			__FILE__, __func__, __LINE__, ## args);	\
} while (0)
#endif

/* Linked bytecode. Child of struct lttng_bytecode_runtime. */
struct bytecode_runtime {
	struct lttng_bytecode_runtime p;
	uint16_t len;
	char data[0];
};

enum entry_type {
	REG_S64,
	REG_DOUBLE,
	REG_STRING,
	REG_STAR_GLOB_STRING,
	REG_UNKNOWN,
};

/* Validation stack */
struct vstack_entry {
	enum entry_type type;
};

struct vstack {
	int top;	/* top of stack */
	struct vstack_entry e[FILTER_STACK_LEN];
};

static inline
void vstack_init(struct vstack *stack)
{
	stack->top = -1;
}

static inline
struct vstack_entry *vstack_ax(struct vstack *stack)
{
	if (unlikely(stack->top < 0))
		return NULL;
	return &stack->e[stack->top];
}

static inline
struct vstack_entry *vstack_bx(struct vstack *stack)
{
	if (unlikely(stack->top < 1))
		return NULL;
	return &stack->e[stack->top - 1];
}

static inline
int vstack_push(struct vstack *stack)
{
	if (stack->top >= FILTER_STACK_LEN - 1) {
		ERR("Stack full\n");
		return -EINVAL;
	}
	++stack->top;
	return 0;
}

static inline
int vstack_pop(struct vstack *stack)
{
	if (unlikely(stack->top < 0)) {
		ERR("Stack empty\n");
		return -EINVAL;
	}
	stack->top--;
	return 0;
}

/* Execution stack */
enum estack_string_literal_type {
	ESTACK_STRING_LITERAL_TYPE_NONE,
	ESTACK_STRING_LITERAL_TYPE_PLAIN,
	ESTACK_STRING_LITERAL_TYPE_STAR_GLOB,
};

struct estack_entry {
	enum entry_type type;	/* For dynamic typing. */
	union {
		int64_t v;
		double d;

		struct {
			const char *str;
			size_t seq_len;
			enum estack_string_literal_type literal_type;
		} s;
	} u;
};

struct estack {
	int top;	/* top of stack */
	struct estack_entry e[FILTER_STACK_LEN];
};

/*
 * Always use aliased type for ax/bx (top of stack).
 * When ax/bx are S64, use aliased value.
 */
#define estack_ax_v	ax
#define estack_bx_v	bx
#define estack_ax_t	ax_t
#define estack_bx_t	bx_t

/*
 * ax and bx registers can hold either integer, double or string.
 */
#define estack_ax(stack, top)					\
	({							\
		assert((top) > FILTER_STACK_EMPTY);		\
		&(stack)->e[top];				\
	})

#define estack_bx(stack, top)					\
	({							\
		assert((top) > FILTER_STACK_EMPTY + 1);		\
		&(stack)->e[(top) - 1];				\
	})

/*
 * Currently, only integers (REG_S64) can be pushed into the stack.
 */
#define estack_push(stack, top, ax, bx, ax_t, bx_t)		\
	do {							\
		assert((top) < FILTER_STACK_LEN - 1);		\
		(stack)->e[(top) - 1].u.v = (bx);		\
		(stack)->e[(top) - 1].type = (bx_t);		\
		(bx) = (ax);					\
		(bx_t) = (ax_t);				\
		++(top);					\
	} while (0)

#define estack_pop(stack, top, ax, bx, ax_t, bx_t)		\
	do {							\
		assert((top) > FILTER_STACK_EMPTY);		\
		(ax) = (bx);					\
		(ax_t) = (bx_t);				\
		(bx) = (stack)->e[(top) - 2].u.v;		\
		(bx_t) = (stack)->e[(top) - 2].type;		\
		(top)--;					\
	} while (0)

const char *print_op(enum filter_op op);

int lttng_filter_validate_bytecode(struct bytecode_runtime *bytecode);
int lttng_filter_specialize_bytecode(struct bytecode_runtime *bytecode);

uint64_t lttng_filter_false(void *filter_data,
		const char *filter_stack_data);
uint64_t lttng_filter_interpret_bytecode(void *filter_data,
		const char *filter_stack_data);

#endif /* _LTTNG_FILTER_H */
