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
#include <errno.h>
#include <string.h>
#include <inttypes.h>
#include <limits.h>
#include <usterr-signal-safe.h>
#include "filter-bytecode.h"

#define NR_REG		2

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

enum reg_type {
	REG_S64,
	REG_DOUBLE,
	REG_STRING,
	REG_TYPE_UNKNOWN,
};

/* Validation registers */
struct vreg {
	enum reg_type type;
	int literal;		/* is string literal ? */
};

/* Execution registers */
struct reg {
	enum reg_type type;
	int64_t v;
	double d;

	const char *str;
	size_t seq_len;
	int literal;		/* is string literal ? */
};

const char *print_op(enum filter_op op);

int lttng_filter_validate_bytecode(struct bytecode_runtime *bytecode);
int lttng_filter_specialize_bytecode(struct bytecode_runtime *bytecode);

int lttng_filter_false(void *filter_data,
		const char *filter_stack_data);
int lttng_filter_interpret_bytecode(void *filter_data,
		const char *filter_stack_data);

#endif /* _LTTNG_FILTER_H */
