#ifndef _LTTNG_FILTER_H
#define _LTTNG_FILTER_H

/*
 * lttng-filter.h
 *
 * LTTng UST filter header.
 *
 * Copyright (C) 2010-2012 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; only
 * version 2.1 of the License.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */

#include <errno.h>
#include <stdio.h>
#include <helper.h>
#include <lttng/ust-events.h>
#include <stdint.h>
#include <assert.h>
#include <errno.h>
#include <string.h>
#include <inttypes.h>
#include <limits.h>
#include <usterr-signal-safe.h>
#include "filter-bytecode.h"

/* Filter stack length, in number of entries */
#define FILTER_STACK_LEN	8

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
#define dbg_printf(fmt, args...)     printf("[debug bytecode] " fmt, ## args)
#else
#define dbg_printf(fmt, args...)				\
do {								\
	/* do nothing but check printf format */		\
	if (0)							\
		printf("[debug bytecode] " fmt, ## args);	\
} while (0)
#endif

/* Linked bytecode */
struct bytecode_runtime {
	uint16_t len;
	char data[0];
};

enum entry_type {
	REG_S64,
	REG_DOUBLE,
	REG_STRING,
	REG_TYPE_UNKNOWN,
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
struct estack_entry {
	union {
		int64_t v;
		double d;

		struct {
			const char *str;
		size_t seq_len;
		int literal;		/* is string literal ? */
		} s;
	} u;
};

struct estack {
	int top;	/* top of stack */
	struct estack_entry e[FILTER_STACK_LEN];
};

static inline
void estack_init(struct estack *stack)
{
	stack->top = -1;
}

static inline
struct estack_entry *estack_ax(struct estack *stack)
{
	assert(stack->top >= 0);
	return &stack->e[stack->top];
}

static inline
struct estack_entry *estack_bx(struct estack *stack)
{
	assert(stack->top >= 1);
	return &stack->e[stack->top - 1];
}

static inline
void estack_push(struct estack *stack)
{
	assert(stack->top < FILTER_STACK_LEN - 1);
	++stack->top;
}

static inline
void estack_pop(struct estack *stack)
{
	assert(stack->top >= 0);
	stack->top--;
}

const char *print_op(enum filter_op op);

int lttng_filter_validate_bytecode(struct bytecode_runtime *bytecode);
int lttng_filter_specialize_bytecode(struct bytecode_runtime *bytecode);

int lttng_filter_false(void *filter_data,
		const char *filter_stack_data);
int lttng_filter_interpret_bytecode(void *filter_data,
		const char *filter_stack_data);

#endif /* _LTTNG_FILTER_H */
