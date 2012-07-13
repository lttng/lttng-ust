/*
 * lttng-filter.c
 *
 * LTTng UST filter code.
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

static const char *opnames[] = {
	[ FILTER_OP_UNKNOWN ] = "UNKNOWN",

	[ FILTER_OP_RETURN ] = "RETURN",

	/* binary */
	[ FILTER_OP_MUL ] = "MUL",
	[ FILTER_OP_DIV ] = "DIV",
	[ FILTER_OP_MOD ] = "MOD",
	[ FILTER_OP_PLUS ] = "PLUS",
	[ FILTER_OP_MINUS ] = "MINUS",
	[ FILTER_OP_RSHIFT ] = "RSHIFT",
	[ FILTER_OP_LSHIFT ] = "LSHIFT",
	[ FILTER_OP_BIN_AND ] = "BIN_AND",
	[ FILTER_OP_BIN_OR ] = "BIN_OR",
	[ FILTER_OP_BIN_XOR ] = "BIN_XOR",

	/* binary comparators */
	[ FILTER_OP_EQ ] = "EQ",
	[ FILTER_OP_NE ] = "NE",
	[ FILTER_OP_GT ] = "GT",
	[ FILTER_OP_LT ] = "LT",
	[ FILTER_OP_GE ] = "GE",
	[ FILTER_OP_LE ] = "LE",

	/* string binary comparators */
	[ FILTER_OP_EQ_STRING ] = "EQ_STRING",
	[ FILTER_OP_NE_STRING ] = "NE_STRING",
	[ FILTER_OP_GT_STRING ] = "GT_STRING",
	[ FILTER_OP_LT_STRING ] = "LT_STRING",
	[ FILTER_OP_GE_STRING ] = "GE_STRING",
	[ FILTER_OP_LE_STRING ] = "LE_STRING",

	/* s64 binary comparators */
	[ FILTER_OP_EQ_S64 ] = "EQ_S64",
	[ FILTER_OP_NE_S64 ] = "NE_S64",
	[ FILTER_OP_GT_S64 ] = "GT_S64",
	[ FILTER_OP_LT_S64 ] = "LT_S64",
	[ FILTER_OP_GE_S64 ] = "GE_S64",
	[ FILTER_OP_LE_S64 ] = "LE_S64",

	/* double binary comparators */
	[ FILTER_OP_EQ_DOUBLE ] = "EQ_DOUBLE",
	[ FILTER_OP_NE_DOUBLE ] = "NE_DOUBLE",
	[ FILTER_OP_GT_DOUBLE ] = "GT_DOUBLE",
	[ FILTER_OP_LT_DOUBLE ] = "LT_DOUBLE",
	[ FILTER_OP_GE_DOUBLE ] = "GE_DOUBLE",
	[ FILTER_OP_LE_DOUBLE ] = "LE_DOUBLE",


	/* unary */
	[ FILTER_OP_UNARY_PLUS ] = "UNARY_PLUS",
	[ FILTER_OP_UNARY_MINUS ] = "UNARY_MINUS",
	[ FILTER_OP_UNARY_NOT ] = "UNARY_NOT",
	[ FILTER_OP_UNARY_PLUS_S64 ] = "UNARY_PLUS_S64",
	[ FILTER_OP_UNARY_MINUS_S64 ] = "UNARY_MINUS_S64",
	[ FILTER_OP_UNARY_NOT_S64 ] = "UNARY_NOT_S64",
	[ FILTER_OP_UNARY_PLUS_DOUBLE ] = "UNARY_PLUS_DOUBLE",
	[ FILTER_OP_UNARY_MINUS_DOUBLE ] = "UNARY_MINUS_DOUBLE",
	[ FILTER_OP_UNARY_NOT_DOUBLE ] = "UNARY_NOT_DOUBLE",

	/* logical */
	[ FILTER_OP_AND ] = "AND",
	[ FILTER_OP_OR ] = "OR",

	/* load */
	[ FILTER_OP_LOAD_FIELD_REF ] = "LOAD_FIELD_REF",
	[ FILTER_OP_LOAD_FIELD_REF_STRING ] = "LOAD_FIELD_REF_STRING",
	[ FILTER_OP_LOAD_FIELD_REF_SEQUENCE ] = "LOAD_FIELD_REF_SEQUENCE",
	[ FILTER_OP_LOAD_FIELD_REF_S64 ] = "LOAD_FIELD_REF_S64",
	[ FILTER_OP_LOAD_FIELD_REF_DOUBLE ] = "LOAD_FIELD_REF_DOUBLE",

	[ FILTER_OP_LOAD_STRING ] = "LOAD_STRING",
	[ FILTER_OP_LOAD_S64 ] = "LOAD_S64",
	[ FILTER_OP_LOAD_DOUBLE ] = "LOAD_DOUBLE",
};

static
const char *print_op(enum filter_op op)
{
	if (op >= NR_FILTER_OPS)
		return "UNKNOWN";
	else
		return opnames[op];
}

/*
 * -1: wildcard found.
 * -2: unknown escape char.
 * 0: normal char.
 */

static
int parse_char(const char **p)
{
	switch (**p) {
	case '\\':
		(*p)++;
		switch (**p) {
		case '\\':
		case '*':
			return 0;
		default:
			return -2;
		}
	case '*':
		return -1;
	default:
		return 0;
	}
}

static
int reg_strcmp(struct reg reg[NR_REG], const char *cmp_type)
{
	const char *p = reg[REG_R0].str, *q = reg[REG_R1].str;
	int ret;
	int diff;

	for (;;) {
		int escaped_r0 = 0;

		if (unlikely(p - reg[REG_R0].str > reg[REG_R0].seq_len || *p == '\0')) {
			if (q - reg[REG_R1].str > reg[REG_R1].seq_len || *q == '\0')
				diff = 0;
			else
				diff = -1;
			break;
		}
		if (unlikely(q - reg[REG_R1].str > reg[REG_R1].seq_len || *q == '\0')) {
			if (p - reg[REG_R0].str > reg[REG_R0].seq_len || *p == '\0')
				diff = 0;
			else
				diff = 1;
			break;
		}
		if (reg[REG_R0].literal) {
			ret = parse_char(&p);
			if (ret == -1) {
				return 0;
			} else if (ret == -2) {
				escaped_r0 = 1;
			}
			/* else compare both char */
		}
		if (reg[REG_R1].literal) {
			ret = parse_char(&q);
			if (ret == -1) {
				return 0;
			} else if (ret == -2) {
				if (!escaped_r0)
					return -1;
			} else {
				if (escaped_r0)
					return 1;
			}
		} else {
			if (escaped_r0)
				return 1;
		}
		diff = *p - *q;
		if (diff != 0)
			break;
		p++;
		q++;
	}
	return diff;
}

static
int lttng_filter_false(void *filter_data,
		const char *filter_stack_data)
{
	return 0;
}

#ifdef INTERPRETER_USE_SWITCH

/*
 * Fallback for compilers that do not support taking address of labels.
 */

#define START_OP	\
	start_pc = &bytecode->data[0]; \
	for (pc = next_pc = start_pc; pc - start_pc < bytecode->len; \
			pc = next_pc) { \
		dbg_printf("Executing op %s (%u)\n", \
			print_op((unsigned int) *(filter_opcode_t *) pc), \
			(unsigned int) *(filter_opcode_t *) pc); \
		switch (*(filter_opcode_t *) pc) {

#define OP(name)	case name

#define PO		break

#define END_OP		} \
	}

#else

/*
 * Dispatch-table based interpreter.
 */

#define START_OP					\
	start_pc = &bytecode->data[0];			\
	pc = next_pc = start_pc;			\
	if (unlikely(pc - start_pc >= bytecode->len))	\
		goto end;				\
	goto *dispatch[*(filter_opcode_t *) pc];

#define OP(name)					\
LABEL_##name

#define PO						\
		pc = next_pc;				\
		goto *dispatch[*(filter_opcode_t *) pc];

#define END_OP

#endif

static
int lttng_filter_interpret_bytecode(void *filter_data,
		const char *filter_stack_data)
{
	struct bytecode_runtime *bytecode = filter_data;
	void *pc, *next_pc, *start_pc;
	int ret = -EINVAL;
	int retval = 0;
	struct reg reg[NR_REG];
#ifndef INTERPRETER_USE_SWITCH
	static void *dispatch[NR_FILTER_OPS] = {
		[ FILTER_OP_UNKNOWN ] = &&LABEL_FILTER_OP_UNKNOWN,

		[ FILTER_OP_RETURN ] = &&LABEL_FILTER_OP_RETURN,

		/* binary */
		[ FILTER_OP_MUL ] = &&LABEL_FILTER_OP_MUL,
		[ FILTER_OP_DIV ] = &&LABEL_FILTER_OP_DIV,
		[ FILTER_OP_MOD ] = &&LABEL_FILTER_OP_MOD,
		[ FILTER_OP_PLUS ] = &&LABEL_FILTER_OP_PLUS,
		[ FILTER_OP_MINUS ] = &&LABEL_FILTER_OP_MINUS,
		[ FILTER_OP_RSHIFT ] = &&LABEL_FILTER_OP_RSHIFT,
		[ FILTER_OP_LSHIFT ] = &&LABEL_FILTER_OP_LSHIFT,
		[ FILTER_OP_BIN_AND ] = &&LABEL_FILTER_OP_BIN_AND,
		[ FILTER_OP_BIN_OR ] = &&LABEL_FILTER_OP_BIN_OR,
		[ FILTER_OP_BIN_XOR ] = &&LABEL_FILTER_OP_BIN_XOR,

		/* binary comparators */
		[ FILTER_OP_EQ ] = &&LABEL_FILTER_OP_EQ,
		[ FILTER_OP_NE ] = &&LABEL_FILTER_OP_NE,
		[ FILTER_OP_GT ] = &&LABEL_FILTER_OP_GT,
		[ FILTER_OP_LT ] = &&LABEL_FILTER_OP_LT,
		[ FILTER_OP_GE ] = &&LABEL_FILTER_OP_GE,
		[ FILTER_OP_LE ] = &&LABEL_FILTER_OP_LE,

		/* string binary comparator */
		[ FILTER_OP_EQ_STRING ] = &&LABEL_FILTER_OP_EQ_STRING,
		[ FILTER_OP_NE_STRING ] = &&LABEL_FILTER_OP_NE_STRING,
		[ FILTER_OP_GT_STRING ] = &&LABEL_FILTER_OP_GT_STRING,
		[ FILTER_OP_LT_STRING ] = &&LABEL_FILTER_OP_LT_STRING,
		[ FILTER_OP_GE_STRING ] = &&LABEL_FILTER_OP_GE_STRING,
		[ FILTER_OP_LE_STRING ] = &&LABEL_FILTER_OP_LE_STRING,

		/* s64 binary comparator */
		[ FILTER_OP_EQ_S64 ] = &&LABEL_FILTER_OP_EQ_S64,
		[ FILTER_OP_NE_S64 ] = &&LABEL_FILTER_OP_NE_S64,
		[ FILTER_OP_GT_S64 ] = &&LABEL_FILTER_OP_GT_S64,
		[ FILTER_OP_LT_S64 ] = &&LABEL_FILTER_OP_LT_S64,
		[ FILTER_OP_GE_S64 ] = &&LABEL_FILTER_OP_GE_S64,
		[ FILTER_OP_LE_S64 ] = &&LABEL_FILTER_OP_LE_S64,

		/* double binary comparator */
		[ FILTER_OP_EQ_DOUBLE ] = &&LABEL_FILTER_OP_EQ_DOUBLE,
		[ FILTER_OP_NE_DOUBLE ] = &&LABEL_FILTER_OP_NE_DOUBLE,
		[ FILTER_OP_GT_DOUBLE ] = &&LABEL_FILTER_OP_GT_DOUBLE,
		[ FILTER_OP_LT_DOUBLE ] = &&LABEL_FILTER_OP_LT_DOUBLE,
		[ FILTER_OP_GE_DOUBLE ] = &&LABEL_FILTER_OP_GE_DOUBLE,
		[ FILTER_OP_LE_DOUBLE ] = &&LABEL_FILTER_OP_LE_DOUBLE,

		/* unary */
		[ FILTER_OP_UNARY_PLUS ] = &&LABEL_FILTER_OP_UNARY_PLUS,
		[ FILTER_OP_UNARY_MINUS ] = &&LABEL_FILTER_OP_UNARY_MINUS,
		[ FILTER_OP_UNARY_NOT ] = &&LABEL_FILTER_OP_UNARY_NOT,
		[ FILTER_OP_UNARY_PLUS_S64 ] = &&LABEL_FILTER_OP_UNARY_PLUS_S64,
		[ FILTER_OP_UNARY_MINUS_S64 ] = &&LABEL_FILTER_OP_UNARY_MINUS_S64,
		[ FILTER_OP_UNARY_NOT_S64 ] = &&LABEL_FILTER_OP_UNARY_NOT_S64,
		[ FILTER_OP_UNARY_PLUS_DOUBLE ] = &&LABEL_FILTER_OP_UNARY_PLUS_DOUBLE,
		[ FILTER_OP_UNARY_MINUS_DOUBLE ] = &&LABEL_FILTER_OP_UNARY_MINUS_DOUBLE,
		[ FILTER_OP_UNARY_NOT_DOUBLE ] = &&LABEL_FILTER_OP_UNARY_NOT_DOUBLE,

		/* logical */
		[ FILTER_OP_AND ] = &&LABEL_FILTER_OP_AND,
		[ FILTER_OP_OR ] = &&LABEL_FILTER_OP_OR,

		/* load */
		[ FILTER_OP_LOAD_FIELD_REF ] = &&LABEL_FILTER_OP_LOAD_FIELD_REF,
		[ FILTER_OP_LOAD_FIELD_REF_STRING ] = &&LABEL_FILTER_OP_LOAD_FIELD_REF_STRING,
		[ FILTER_OP_LOAD_FIELD_REF_SEQUENCE ] = &&LABEL_FILTER_OP_LOAD_FIELD_REF_SEQUENCE,
		[ FILTER_OP_LOAD_FIELD_REF_S64 ] = &&LABEL_FILTER_OP_LOAD_FIELD_REF_S64,
		[ FILTER_OP_LOAD_FIELD_REF_DOUBLE ] = &&LABEL_FILTER_OP_LOAD_FIELD_REF_DOUBLE,

		[ FILTER_OP_LOAD_STRING ] = &&LABEL_FILTER_OP_LOAD_STRING,
		[ FILTER_OP_LOAD_S64 ] = &&LABEL_FILTER_OP_LOAD_S64,
		[ FILTER_OP_LOAD_DOUBLE ] = &&LABEL_FILTER_OP_LOAD_DOUBLE,
	};
#endif /* #ifndef INTERPRETER_USE_SWITCH */

	START_OP

		OP(FILTER_OP_UNKNOWN):
		OP(FILTER_OP_LOAD_FIELD_REF):
#ifdef INTERPRETER_USE_SWITCH
		default:
#endif /* INTERPRETER_USE_SWITCH */
			ERR("unknown bytecode op %u\n",
				(unsigned int) *(filter_opcode_t *) pc);
			ret = -EINVAL;
			goto end;

		OP(FILTER_OP_RETURN):
			retval = !!reg[0].v;
			ret = 0;
			goto end;

		/* binary */
		OP(FILTER_OP_MUL):
		OP(FILTER_OP_DIV):
		OP(FILTER_OP_MOD):
		OP(FILTER_OP_PLUS):
		OP(FILTER_OP_MINUS):
		OP(FILTER_OP_RSHIFT):
		OP(FILTER_OP_LSHIFT):
		OP(FILTER_OP_BIN_AND):
		OP(FILTER_OP_BIN_OR):
		OP(FILTER_OP_BIN_XOR):
			ERR("unsupported bytecode op %u\n",
				(unsigned int) *(filter_opcode_t *) pc);
			ret = -EINVAL;
			goto end;

		OP(FILTER_OP_EQ):
		OP(FILTER_OP_NE):
		OP(FILTER_OP_GT):
		OP(FILTER_OP_LT):
		OP(FILTER_OP_GE):
		OP(FILTER_OP_LE):
			ERR("unsupported non-specialized bytecode op %u\n",
				(unsigned int) *(filter_opcode_t *) pc);
			ret = -EINVAL;
			goto end;

		OP(FILTER_OP_EQ_STRING):
		{
			reg[REG_R0].v = (reg_strcmp(reg, "==") == 0);
			reg[REG_R0].type = REG_S64;
			next_pc += sizeof(struct binary_op);
			PO;
		}
		OP(FILTER_OP_NE_STRING):
		{
			reg[REG_R0].v = (reg_strcmp(reg, "!=") != 0);
			reg[REG_R0].type = REG_S64;
			next_pc += sizeof(struct binary_op);
			PO;
		}
		OP(FILTER_OP_GT_STRING):
		{
			reg[REG_R0].v = (reg_strcmp(reg, ">") > 0);
			reg[REG_R0].type = REG_S64;
			next_pc += sizeof(struct binary_op);
			PO;
		}
		OP(FILTER_OP_LT_STRING):
		{
			reg[REG_R0].v = (reg_strcmp(reg, "<") < 0);
			reg[REG_R0].type = REG_S64;
			next_pc += sizeof(struct binary_op);
			PO;
		}
		OP(FILTER_OP_GE_STRING):
		{
			reg[REG_R0].v = (reg_strcmp(reg, ">=") >= 0);
			reg[REG_R0].type = REG_S64;
			next_pc += sizeof(struct binary_op);
			PO;
		}
		OP(FILTER_OP_LE_STRING):
		{
			reg[REG_R0].v = (reg_strcmp(reg, "<=") <= 0);
			reg[REG_R0].type = REG_S64;
			next_pc += sizeof(struct binary_op);
			PO;
		}

		OP(FILTER_OP_EQ_S64):
		{
			reg[REG_R0].v = (reg[REG_R0].v == reg[REG_R1].v);
			reg[REG_R0].type = REG_S64;
			next_pc += sizeof(struct binary_op);
			PO;
		}
		OP(FILTER_OP_NE_S64):
		{
			reg[REG_R0].v = (reg[REG_R0].v != reg[REG_R1].v);
			reg[REG_R0].type = REG_S64;
			next_pc += sizeof(struct binary_op);
			PO;
		}
		OP(FILTER_OP_GT_S64):
		{
			reg[REG_R0].v = (reg[REG_R0].v > reg[REG_R1].v);
			reg[REG_R0].type = REG_S64;
			next_pc += sizeof(struct binary_op);
			PO;
		}
		OP(FILTER_OP_LT_S64):
		{
			reg[REG_R0].v = (reg[REG_R0].v < reg[REG_R1].v);
			reg[REG_R0].type = REG_S64;
			next_pc += sizeof(struct binary_op);
			PO;
		}
		OP(FILTER_OP_GE_S64):
		{
			reg[REG_R0].v = (reg[REG_R0].v >= reg[REG_R1].v);
			reg[REG_R0].type = REG_S64;
			next_pc += sizeof(struct binary_op);
			PO;
		}
		OP(FILTER_OP_LE_S64):
		{
			reg[REG_R0].v = (reg[REG_R0].v <= reg[REG_R1].v);
			reg[REG_R0].type = REG_S64;
			next_pc += sizeof(struct binary_op);
			PO;
		}

		OP(FILTER_OP_EQ_DOUBLE):
		{
			if (unlikely(reg[REG_R0].type == REG_S64))
				reg[REG_R0].d = (double) reg[REG_R0].v;
			else if (unlikely(reg[REG_R1].type == REG_S64))
				reg[REG_R1].d = (double) reg[REG_R1].v;
			reg[REG_R0].v = (reg[REG_R0].d == reg[REG_R1].d);
			reg[REG_R0].type = REG_S64;
			next_pc += sizeof(struct binary_op);
			PO;
		}
		OP(FILTER_OP_NE_DOUBLE):
		{
			if (unlikely(reg[REG_R0].type == REG_S64))
				reg[REG_R0].d = (double) reg[REG_R0].v;
			else if (unlikely(reg[REG_R1].type == REG_S64))
				reg[REG_R1].d = (double) reg[REG_R1].v;
			reg[REG_R0].v = (reg[REG_R0].d != reg[REG_R1].d);
			reg[REG_R0].type = REG_S64;
			next_pc += sizeof(struct binary_op);
			PO;
		}
		OP(FILTER_OP_GT_DOUBLE):
		{
			if (unlikely(reg[REG_R0].type == REG_S64))
				reg[REG_R0].d = (double) reg[REG_R0].v;
			else if (unlikely(reg[REG_R1].type == REG_S64))
				reg[REG_R1].d = (double) reg[REG_R1].v;
			reg[REG_R0].v = (reg[REG_R0].d > reg[REG_R1].d);
			reg[REG_R0].type = REG_S64;
			next_pc += sizeof(struct binary_op);
			PO;
		}
		OP(FILTER_OP_LT_DOUBLE):
		{
			if (unlikely(reg[REG_R0].type == REG_S64))
				reg[REG_R0].d = (double) reg[REG_R0].v;
			else if (unlikely(reg[REG_R1].type == REG_S64))
				reg[REG_R1].d = (double) reg[REG_R1].v;
			reg[REG_R0].v = (reg[REG_R0].d < reg[REG_R1].d);
			reg[REG_R0].type = REG_S64;
			next_pc += sizeof(struct binary_op);
			PO;
		}
		OP(FILTER_OP_GE_DOUBLE):
		{
			if (unlikely(reg[REG_R0].type == REG_S64))
				reg[REG_R0].d = (double) reg[REG_R0].v;
			else if (unlikely(reg[REG_R1].type == REG_S64))
				reg[REG_R1].d = (double) reg[REG_R1].v;
			reg[REG_R0].v = (reg[REG_R0].d >= reg[REG_R1].d);
			reg[REG_R0].type = REG_S64;
			next_pc += sizeof(struct binary_op);
			PO;
		}
		OP(FILTER_OP_LE_DOUBLE):
		{
			if (unlikely(reg[REG_R0].type == REG_S64))
				reg[REG_R0].d = (double) reg[REG_R0].v;
			else if (unlikely(reg[REG_R1].type == REG_S64))
				reg[REG_R1].d = (double) reg[REG_R1].v;
			reg[REG_R0].v = (reg[REG_R0].d <= reg[REG_R1].d);
			reg[REG_R0].type = REG_S64;
			next_pc += sizeof(struct binary_op);
			PO;
		}

		/* unary */
		OP(FILTER_OP_UNARY_PLUS):
		OP(FILTER_OP_UNARY_MINUS):
		OP(FILTER_OP_UNARY_NOT):
			ERR("unsupported non-specialized bytecode op %u\n",
				(unsigned int) *(filter_opcode_t *) pc);
			ret = -EINVAL;
			goto end;


		OP(FILTER_OP_UNARY_PLUS_S64):
		OP(FILTER_OP_UNARY_PLUS_DOUBLE):
		{
			next_pc += sizeof(struct unary_op);
			PO;
		}
		OP(FILTER_OP_UNARY_MINUS_S64):
		{
			struct unary_op *insn = (struct unary_op *) pc;

			reg[insn->reg].v = -reg[insn->reg].v;
			next_pc += sizeof(struct unary_op);
			PO;
		}
		OP(FILTER_OP_UNARY_MINUS_DOUBLE):
		{
			struct unary_op *insn = (struct unary_op *) pc;

			reg[insn->reg].d = -reg[insn->reg].d;
			next_pc += sizeof(struct unary_op);
			PO;
		}
		OP(FILTER_OP_UNARY_NOT_S64):
		{
			struct unary_op *insn = (struct unary_op *) pc;

			reg[insn->reg].v = !reg[insn->reg].v;
			next_pc += sizeof(struct unary_op);
			PO;
		}
		OP(FILTER_OP_UNARY_NOT_DOUBLE):
		{
			struct unary_op *insn = (struct unary_op *) pc;

			reg[insn->reg].d = !reg[insn->reg].d;
			next_pc += sizeof(struct unary_op);
			PO;
		}

		/* logical */
		OP(FILTER_OP_AND):
		{
			struct logical_op *insn = (struct logical_op *) pc;

			/* If REG_R0 is 0, skip and evaluate to 0 */
			if ((reg[REG_R0].type == REG_S64 && reg[REG_R0].v == 0)
					|| unlikely(reg[REG_R0].type == REG_DOUBLE && reg[REG_R0].d == 0.0)) {
				dbg_printf("Jumping to bytecode offset %u\n",
					(unsigned int) insn->skip_offset);
				next_pc = start_pc + insn->skip_offset;
			} else {
				next_pc += sizeof(struct logical_op);
			}
			PO;
		}
		OP(FILTER_OP_OR):
		{
			struct logical_op *insn = (struct logical_op *) pc;

			/* If REG_R0 is nonzero, skip and evaluate to 1 */

			if ((reg[REG_R0].type == REG_S64 && reg[REG_R0].v != 0)
					|| unlikely(reg[REG_R0].type == REG_DOUBLE && reg[REG_R0].d != 0.0)) {
				reg[REG_R0].v = 1;
				dbg_printf("Jumping to bytecode offset %u\n",
					(unsigned int) insn->skip_offset);
				next_pc = start_pc + insn->skip_offset;
			} else {
				next_pc += sizeof(struct logical_op);
			}
			PO;
		}

		/* load */
		OP(FILTER_OP_LOAD_FIELD_REF_STRING):
		{
			struct load_op *insn = (struct load_op *) pc;
			struct field_ref *ref = (struct field_ref *) insn->data;

			dbg_printf("load field ref offset %u type string\n",
				ref->offset);
			reg[insn->reg].str =
				*(const char * const *) &filter_stack_data[ref->offset];
			reg[insn->reg].type = REG_STRING;
			reg[insn->reg].seq_len = UINT_MAX;
			reg[insn->reg].literal = 0;
			dbg_printf("ref load string %s\n", reg[insn->reg].str);
			next_pc += sizeof(struct load_op) + sizeof(struct field_ref);
			PO;
		}

		OP(FILTER_OP_LOAD_FIELD_REF_SEQUENCE):
		{
			struct load_op *insn = (struct load_op *) pc;
			struct field_ref *ref = (struct field_ref *) insn->data;

			dbg_printf("load field ref offset %u type sequence\n",
				ref->offset);
			reg[insn->reg].seq_len =
				*(unsigned long *) &filter_stack_data[ref->offset];
			reg[insn->reg].str =
				*(const char **) (&filter_stack_data[ref->offset
								+ sizeof(unsigned long)]);
			reg[insn->reg].type = REG_STRING;
			reg[insn->reg].literal = 0;
			next_pc += sizeof(struct load_op) + sizeof(struct field_ref);
			PO;
		}

		OP(FILTER_OP_LOAD_FIELD_REF_S64):
		{
			struct load_op *insn = (struct load_op *) pc;
			struct field_ref *ref = (struct field_ref *) insn->data;

			dbg_printf("load field ref offset %u type s64\n",
				ref->offset);
			memcpy(&reg[insn->reg].v, &filter_stack_data[ref->offset],
				sizeof(struct literal_numeric));
			reg[insn->reg].type = REG_S64;
			reg[insn->reg].literal = 0;
			dbg_printf("ref load s64 %" PRIi64 "\n", reg[insn->reg].v);
			next_pc += sizeof(struct load_op) + sizeof(struct field_ref);
			PO;
		}

		OP(FILTER_OP_LOAD_FIELD_REF_DOUBLE):
		{
			struct load_op *insn = (struct load_op *) pc;
			struct field_ref *ref = (struct field_ref *) insn->data;

			dbg_printf("load field ref offset %u type double\n",
				ref->offset);
			memcpy(&reg[insn->reg].d, &filter_stack_data[ref->offset],
				sizeof(struct literal_double));
			reg[insn->reg].type = REG_DOUBLE;
			reg[insn->reg].literal = 0;
			dbg_printf("ref load double %g\n", reg[insn->reg].d);
			next_pc += sizeof(struct load_op) + sizeof(struct field_ref);
			PO;
		}

		OP(FILTER_OP_LOAD_STRING):
		{
			struct load_op *insn = (struct load_op *) pc;

			dbg_printf("load string %s\n", insn->data);
			reg[insn->reg].str = insn->data;
			reg[insn->reg].type = REG_STRING;
			reg[insn->reg].seq_len = UINT_MAX;
			reg[insn->reg].literal = 1;
			next_pc += sizeof(struct load_op) + strlen(insn->data) + 1;
			PO;
		}

		OP(FILTER_OP_LOAD_S64):
		{
			struct load_op *insn = (struct load_op *) pc;

			memcpy(&reg[insn->reg].v, insn->data,
				sizeof(struct literal_numeric));
			dbg_printf("load s64 %" PRIi64 "\n", reg[insn->reg].v);
			reg[insn->reg].type = REG_S64;
			reg[insn->reg].literal = 1;
			next_pc += sizeof(struct load_op)
					+ sizeof(struct literal_numeric);
			PO;
		}

		OP(FILTER_OP_LOAD_DOUBLE):
		{
			struct load_op *insn = (struct load_op *) pc;

			memcpy(&reg[insn->reg].d, insn->data,
				sizeof(struct literal_double));
			dbg_printf("load s64 %g\n", reg[insn->reg].d);
			reg[insn->reg].type = REG_DOUBLE;
			reg[insn->reg].literal = 1;
			next_pc += sizeof(struct load_op)
					+ sizeof(struct literal_double);
			PO;
		}

	END_OP
end:
	/* return 0 (discard) on error */
	if (ret)
		return 0;
	return retval;
}

#undef START_OP
#undef OP
#undef PO
#undef END_OP

static
int bin_op_compare_check(struct vreg reg[NR_REG], const char *str)
{
	switch (reg[REG_R0].type) {
	default:
		goto error_unknown;

	case REG_STRING:
		switch (reg[REG_R1].type) {
		default:
			goto error_unknown;

		case REG_STRING:
			break;
		case REG_S64:
		case REG_DOUBLE:
			goto error_mismatch;
		}
		break;
	case REG_S64:
	case REG_DOUBLE:
		switch (reg[REG_R1].type) {
		default:
			goto error_unknown;

		case REG_STRING:
			goto error_mismatch;

		case REG_S64:
		case REG_DOUBLE:
			break;
		}
		break;
	}
	return 0;

error_unknown:

	return -EINVAL;
error_mismatch:
	ERR("type mismatch for '%s' binary operator\n", str);
	return -EINVAL;
}

static
int lttng_filter_validate_bytecode(struct bytecode_runtime *bytecode)
{
	void *pc, *next_pc, *start_pc;
	int ret = -EINVAL;
	struct vreg reg[NR_REG];
	int i;

	for (i = 0; i < NR_REG; i++) {
		reg[i].type = REG_TYPE_UNKNOWN;
		reg[i].literal = 0;
	}

	start_pc = &bytecode->data[0];
	for (pc = next_pc = start_pc; pc - start_pc < bytecode->len;
			pc = next_pc) {
		if (unlikely(pc >= start_pc + bytecode->len)) {
			ERR("filter bytecode overflow\n");
			ret = -EINVAL;
			goto end;
		}
		dbg_printf("Validating op %s (%u)\n",
			print_op((unsigned int) *(filter_opcode_t *) pc),
			(unsigned int) *(filter_opcode_t *) pc);
		switch (*(filter_opcode_t *) pc) {
		case FILTER_OP_UNKNOWN:
		default:
			ERR("unknown bytecode op %u\n",
				(unsigned int) *(filter_opcode_t *) pc);
			ret = -EINVAL;
			goto end;

		case FILTER_OP_RETURN:
			ret = 0;
			goto end;

		/* binary */
		case FILTER_OP_MUL:
		case FILTER_OP_DIV:
		case FILTER_OP_MOD:
		case FILTER_OP_PLUS:
		case FILTER_OP_MINUS:
		case FILTER_OP_RSHIFT:
		case FILTER_OP_LSHIFT:
		case FILTER_OP_BIN_AND:
		case FILTER_OP_BIN_OR:
		case FILTER_OP_BIN_XOR:
			ERR("unsupported bytecode op %u\n",
				(unsigned int) *(filter_opcode_t *) pc);
			ret = -EINVAL;
			goto end;

		case FILTER_OP_EQ:
		{
			ret = bin_op_compare_check(reg, "==");
			if (ret)
				goto end;
			reg[REG_R0].type = REG_S64;
			next_pc += sizeof(struct binary_op);
			break;
		}
		case FILTER_OP_NE:
		{
			ret = bin_op_compare_check(reg, "!=");
			if (ret)
				goto end;
			reg[REG_R0].type = REG_S64;
			next_pc += sizeof(struct binary_op);
			break;
		}
		case FILTER_OP_GT:
		{
			ret = bin_op_compare_check(reg, ">");
			if (ret)
				goto end;
			reg[REG_R0].type = REG_S64;
			next_pc += sizeof(struct binary_op);
			break;
		}
		case FILTER_OP_LT:
		{
			ret = bin_op_compare_check(reg, "<");
			if (ret)
				goto end;
			reg[REG_R0].type = REG_S64;
			next_pc += sizeof(struct binary_op);
			break;
		}
		case FILTER_OP_GE:
		{
			ret = bin_op_compare_check(reg, ">=");
			if (ret)
				goto end;
			reg[REG_R0].type = REG_S64;
			next_pc += sizeof(struct binary_op);
			break;
		}
		case FILTER_OP_LE:
		{
			ret = bin_op_compare_check(reg, "<=");
			if (ret)
				goto end;
			reg[REG_R0].type = REG_S64;
			next_pc += sizeof(struct binary_op);
			break;
		}

		case FILTER_OP_EQ_STRING:
		case FILTER_OP_NE_STRING:
		case FILTER_OP_GT_STRING:
		case FILTER_OP_LT_STRING:
		case FILTER_OP_GE_STRING:
		case FILTER_OP_LE_STRING:
		{
			if (reg[REG_R0].type != REG_STRING
					|| reg[REG_R1].type != REG_STRING) {
				ERR("Unexpected register type for string comparator\n");
				ret = -EINVAL;
				goto end;
			}
			reg[REG_R0].type = REG_S64;
			next_pc += sizeof(struct binary_op);
			break;
		}

		case FILTER_OP_EQ_S64:
		case FILTER_OP_NE_S64:
		case FILTER_OP_GT_S64:
		case FILTER_OP_LT_S64:
		case FILTER_OP_GE_S64:
		case FILTER_OP_LE_S64:
		{
			if (reg[REG_R0].type != REG_S64
					|| reg[REG_R1].type != REG_S64) {
				ERR("Unexpected register type for s64 comparator\n");
				ret = -EINVAL;
				goto end;
			}
			reg[REG_R0].type = REG_S64;
			next_pc += sizeof(struct binary_op);
			break;
		}

		case FILTER_OP_EQ_DOUBLE:
		case FILTER_OP_NE_DOUBLE:
		case FILTER_OP_GT_DOUBLE:
		case FILTER_OP_LT_DOUBLE:
		case FILTER_OP_GE_DOUBLE:
		case FILTER_OP_LE_DOUBLE:
		{
			if ((reg[REG_R0].type != REG_DOUBLE && reg[REG_R0].type != REG_S64)
					|| (reg[REG_R1].type != REG_DOUBLE && reg[REG_R1].type != REG_S64)) {
				ERR("Unexpected register type for double comparator\n");
				ret = -EINVAL;
				goto end;
			}
			reg[REG_R0].type = REG_DOUBLE;
			next_pc += sizeof(struct binary_op);
			break;
		}

		/* unary */
		case FILTER_OP_UNARY_PLUS:
		case FILTER_OP_UNARY_MINUS:
		case FILTER_OP_UNARY_NOT:
		{
			struct unary_op *insn = (struct unary_op *) pc;

			if (unlikely(insn->reg >= REG_ERROR)) {
				ERR("invalid register %u\n",
					(unsigned int) insn->reg);
				ret = -EINVAL;
				goto end;
			}
			switch (reg[insn->reg].type) {
			default:
				ERR("unknown register type\n");
				ret = -EINVAL;
				goto end;

			case REG_STRING:
				ERR("Unary op can only be applied to numeric or floating point registers\n");
				ret = -EINVAL;
				goto end;
			case REG_S64:
				break;
			case REG_DOUBLE:
				break;
			}
			next_pc += sizeof(struct unary_op);
			break;
		}

		case FILTER_OP_UNARY_PLUS_S64:
		case FILTER_OP_UNARY_MINUS_S64:
		case FILTER_OP_UNARY_NOT_S64:
		{
			struct unary_op *insn = (struct unary_op *) pc;

			if (unlikely(insn->reg >= REG_ERROR)) {
				ERR("invalid register %u\n",
					(unsigned int) insn->reg);
				ret = -EINVAL;
				goto end;
			}
			if (reg[insn->reg].type != REG_S64) {
				ERR("Invalid register type\n");
				ret = -EINVAL;
				goto end;
			}
			next_pc += sizeof(struct unary_op);
			break;
		}

		case FILTER_OP_UNARY_PLUS_DOUBLE:
		case FILTER_OP_UNARY_MINUS_DOUBLE:
		case FILTER_OP_UNARY_NOT_DOUBLE:
		{
			struct unary_op *insn = (struct unary_op *) pc;

			if (unlikely(insn->reg >= REG_ERROR)) {
				ERR("invalid register %u\n",
					(unsigned int) insn->reg);
				ret = -EINVAL;
				goto end;
			}
			if (reg[insn->reg].type != REG_DOUBLE) {
				ERR("Invalid register type\n");
				ret = -EINVAL;
				goto end;
			}
			next_pc += sizeof(struct unary_op);
			break;
		}

		/* logical */
		case FILTER_OP_AND:
		case FILTER_OP_OR:
		{
			struct logical_op *insn = (struct logical_op *) pc;

			if (unlikely(reg[REG_R0].type == REG_TYPE_UNKNOWN
					|| reg[REG_R1].type == REG_TYPE_UNKNOWN
					|| reg[REG_R0].type == REG_STRING
					|| reg[REG_R1].type == REG_STRING)) {
				ERR("Logical comparator can only be applied to numeric and floating point registers\n");
				ret = -EINVAL;
				goto end;
			}

			dbg_printf("Validate jumping to bytecode offset %u\n",
				(unsigned int) insn->skip_offset);
			if (unlikely(start_pc + insn->skip_offset <= pc)) {
				ERR("Loops are not allowed in bytecode\n");
				ret = -EINVAL;
				goto end;
			}
			next_pc += sizeof(struct logical_op);
			break;
		}

		/* load */
		case FILTER_OP_LOAD_FIELD_REF:
		{
			ERR("Unknown field ref type\n");
			ret = -EINVAL;
			goto end;
		}
		case FILTER_OP_LOAD_FIELD_REF_STRING:
		case FILTER_OP_LOAD_FIELD_REF_SEQUENCE:
		{
			struct load_op *insn = (struct load_op *) pc;
			struct field_ref *ref = (struct field_ref *) insn->data;

			if (unlikely(insn->reg >= REG_ERROR)) {
				ERR("invalid register %u\n",
					(unsigned int) insn->reg);
				ret = -EINVAL;
				goto end;
			}
			dbg_printf("Validate load field ref offset %u type string\n",
				ref->offset);
			reg[insn->reg].type = REG_STRING;
			reg[insn->reg].literal = 0;
			next_pc += sizeof(struct load_op) + sizeof(struct field_ref);
			break;
		}
		case FILTER_OP_LOAD_FIELD_REF_S64:
		{
			struct load_op *insn = (struct load_op *) pc;
			struct field_ref *ref = (struct field_ref *) insn->data;

			if (unlikely(insn->reg >= REG_ERROR)) {
				ERR("invalid register %u\n",
					(unsigned int) insn->reg);
				ret = -EINVAL;
				goto end;
			}
			dbg_printf("Validate load field ref offset %u type s64\n",
				ref->offset);
			reg[insn->reg].type = REG_S64;
			reg[insn->reg].literal = 0;
			next_pc += sizeof(struct load_op) + sizeof(struct field_ref);
			break;
		}
		case FILTER_OP_LOAD_FIELD_REF_DOUBLE:
		{
			struct load_op *insn = (struct load_op *) pc;
			struct field_ref *ref = (struct field_ref *) insn->data;

			if (unlikely(insn->reg >= REG_ERROR)) {
				ERR("invalid register %u\n",
					(unsigned int) insn->reg);
				ret = -EINVAL;
				goto end;
			}
			dbg_printf("Validate load field ref offset %u type double\n",
				ref->offset);
			reg[insn->reg].type = REG_DOUBLE;
			reg[insn->reg].literal = 0;
			next_pc += sizeof(struct load_op) + sizeof(struct field_ref);
			break;
		}

		case FILTER_OP_LOAD_STRING:
		{
			struct load_op *insn = (struct load_op *) pc;

			if (unlikely(insn->reg >= REG_ERROR)) {
				ERR("invalid register %u\n",
					(unsigned int) insn->reg);
				ret = -EINVAL;
				goto end;
			}
			reg[insn->reg].type = REG_STRING;
			reg[insn->reg].literal = 1;
			next_pc += sizeof(struct load_op) + strlen(insn->data) + 1;
			break;
		}

		case FILTER_OP_LOAD_S64:
		{
			struct load_op *insn = (struct load_op *) pc;

			if (unlikely(insn->reg >= REG_ERROR)) {
				ERR("invalid register %u\n",
					(unsigned int) insn->reg);
				ret = -EINVAL;
				goto end;
			}
			reg[insn->reg].type = REG_S64;
			reg[insn->reg].literal = 1;
			next_pc += sizeof(struct load_op)
					+ sizeof(struct literal_numeric);
			break;
		}

		case FILTER_OP_LOAD_DOUBLE:
		{
			struct load_op *insn = (struct load_op *) pc;

			if (unlikely(insn->reg >= REG_ERROR)) {
				ERR("invalid register %u\n",
					(unsigned int) insn->reg);
				ret = -EINVAL;
				goto end;
			}
			reg[insn->reg].type = REG_DOUBLE;
			reg[insn->reg].literal = 1;
			next_pc += sizeof(struct load_op)
					+ sizeof(struct literal_double);
			break;
		}
		}
	}
end:
	return ret;
}

static
int lttng_filter_specialize_bytecode(struct bytecode_runtime *bytecode)
{
	void *pc, *next_pc, *start_pc;
	int ret = -EINVAL;
	struct vreg reg[NR_REG];
	int i;

	for (i = 0; i < NR_REG; i++) {
		reg[i].type = REG_TYPE_UNKNOWN;
		reg[i].literal = 0;
	}

	start_pc = &bytecode->data[0];
	for (pc = next_pc = start_pc; pc - start_pc < bytecode->len;
			pc = next_pc) {
		switch (*(filter_opcode_t *) pc) {
		case FILTER_OP_UNKNOWN:
		default:
			ERR("unknown bytecode op %u\n",
				(unsigned int) *(filter_opcode_t *) pc);
			ret = -EINVAL;
			goto end;

		case FILTER_OP_RETURN:
			ret = 0;
			goto end;

		/* binary */
		case FILTER_OP_MUL:
		case FILTER_OP_DIV:
		case FILTER_OP_MOD:
		case FILTER_OP_PLUS:
		case FILTER_OP_MINUS:
		case FILTER_OP_RSHIFT:
		case FILTER_OP_LSHIFT:
		case FILTER_OP_BIN_AND:
		case FILTER_OP_BIN_OR:
		case FILTER_OP_BIN_XOR:
			ERR("unsupported bytecode op %u\n",
				(unsigned int) *(filter_opcode_t *) pc);
			ret = -EINVAL;
			goto end;

		case FILTER_OP_EQ:
		{
			struct binary_op *insn = (struct binary_op *) pc;

			switch(reg[REG_R0].type) {
			default:
				ERR("unknown register type\n");
				ret = -EINVAL;
				goto end;

			case REG_STRING:
				insn->op = FILTER_OP_EQ_STRING;
				break;
			case REG_S64:
				if (reg[REG_R1].type == REG_S64)
					insn->op = FILTER_OP_EQ_S64;
				else
					insn->op = FILTER_OP_EQ_DOUBLE;
				break;
			case REG_DOUBLE:
				insn->op = FILTER_OP_EQ_DOUBLE;
				break;
			}
			reg[REG_R0].type = REG_S64;
			next_pc += sizeof(struct binary_op);
			break;
		}

		case FILTER_OP_NE:
		{
			struct binary_op *insn = (struct binary_op *) pc;

			switch(reg[REG_R0].type) {
			default:
				ERR("unknown register type\n");
				ret = -EINVAL;
				goto end;

			case REG_STRING:
				insn->op = FILTER_OP_NE_STRING;
				break;
			case REG_S64:
				if (reg[REG_R1].type == REG_S64)
					insn->op = FILTER_OP_NE_S64;
				else
					insn->op = FILTER_OP_NE_DOUBLE;
				break;
			case REG_DOUBLE:
				insn->op = FILTER_OP_NE_DOUBLE;
				break;
			}
			reg[REG_R0].type = REG_S64;
			next_pc += sizeof(struct binary_op);
			break;
		}

		case FILTER_OP_GT:
		{
			struct binary_op *insn = (struct binary_op *) pc;

			switch(reg[REG_R0].type) {
			default:
				ERR("unknown register type\n");
				ret = -EINVAL;
				goto end;

			case REG_STRING:
				insn->op = FILTER_OP_GT_STRING;
				break;
			case REG_S64:
				if (reg[REG_R1].type == REG_S64)
					insn->op = FILTER_OP_GT_S64;
				else
					insn->op = FILTER_OP_GT_DOUBLE;
				break;
			case REG_DOUBLE:
				insn->op = FILTER_OP_GT_DOUBLE;
				break;
			}
			reg[REG_R0].type = REG_S64;
			next_pc += sizeof(struct binary_op);
			break;
		}

		case FILTER_OP_LT:
		{
			struct binary_op *insn = (struct binary_op *) pc;

			switch(reg[REG_R0].type) {
			default:
				ERR("unknown register type\n");
				ret = -EINVAL;
				goto end;

			case REG_STRING:
				insn->op = FILTER_OP_LT_STRING;
				break;
			case REG_S64:
				if (reg[REG_R1].type == REG_S64)
					insn->op = FILTER_OP_LT_S64;
				else
					insn->op = FILTER_OP_LT_DOUBLE;
				break;
			case REG_DOUBLE:
				insn->op = FILTER_OP_LT_DOUBLE;
				break;
			}
			reg[REG_R0].type = REG_S64;
			next_pc += sizeof(struct binary_op);
			break;
		}

		case FILTER_OP_GE:
		{
			struct binary_op *insn = (struct binary_op *) pc;

			switch(reg[REG_R0].type) {
			default:
				ERR("unknown register type\n");
				ret = -EINVAL;
				goto end;

			case REG_STRING:
				insn->op = FILTER_OP_GE_STRING;
				break;
			case REG_S64:
				if (reg[REG_R1].type == REG_S64)
					insn->op = FILTER_OP_GE_S64;
				else
					insn->op = FILTER_OP_GE_DOUBLE;
				break;
			case REG_DOUBLE:
				insn->op = FILTER_OP_GE_DOUBLE;
				break;
			}
			reg[REG_R0].type = REG_S64;
			next_pc += sizeof(struct binary_op);
			break;
		}
		case FILTER_OP_LE:
		{
			struct binary_op *insn = (struct binary_op *) pc;

			switch(reg[REG_R0].type) {
			default:
				ERR("unknown register type\n");
				ret = -EINVAL;
				goto end;

			case REG_STRING:
				insn->op = FILTER_OP_LE_STRING;
				break;
			case REG_S64:
				if (reg[REG_R1].type == REG_S64)
					insn->op = FILTER_OP_LE_S64;
				else
					insn->op = FILTER_OP_LE_DOUBLE;
				break;
			case REG_DOUBLE:
				insn->op = FILTER_OP_LE_DOUBLE;
				break;
			}
			reg[REG_R0].type = REG_S64;
			next_pc += sizeof(struct binary_op);
			break;
		}

		case FILTER_OP_EQ_STRING:
		case FILTER_OP_NE_STRING:
		case FILTER_OP_GT_STRING:
		case FILTER_OP_LT_STRING:
		case FILTER_OP_GE_STRING:
		case FILTER_OP_LE_STRING:
		case FILTER_OP_EQ_S64:
		case FILTER_OP_NE_S64:
		case FILTER_OP_GT_S64:
		case FILTER_OP_LT_S64:
		case FILTER_OP_GE_S64:
		case FILTER_OP_LE_S64:
		case FILTER_OP_EQ_DOUBLE:
		case FILTER_OP_NE_DOUBLE:
		case FILTER_OP_GT_DOUBLE:
		case FILTER_OP_LT_DOUBLE:
		case FILTER_OP_GE_DOUBLE:
		case FILTER_OP_LE_DOUBLE:
		{
			reg[REG_R0].type = REG_S64;
			next_pc += sizeof(struct binary_op);
			break;
		}

		/* unary */
		case FILTER_OP_UNARY_PLUS:
		{
			struct unary_op *insn = (struct unary_op *) pc;

			switch(reg[insn->reg].type) {
			default:
				ERR("unknown register type\n");
				ret = -EINVAL;
				goto end;

			case REG_S64:
				insn->op = FILTER_OP_UNARY_PLUS_S64;
				break;
			case REG_DOUBLE:
				insn->op = FILTER_OP_UNARY_PLUS_DOUBLE;
				break;
			}
			break;
		}

		case FILTER_OP_UNARY_MINUS:
		{
			struct unary_op *insn = (struct unary_op *) pc;

			switch(reg[insn->reg].type) {
			default:
				ERR("unknown register type\n");
				ret = -EINVAL;
				goto end;

			case REG_S64:
				insn->op = FILTER_OP_UNARY_MINUS_S64;
				break;
			case REG_DOUBLE:
				insn->op = FILTER_OP_UNARY_MINUS_DOUBLE;
				break;
			}
			break;
		}

		case FILTER_OP_UNARY_NOT:
		{
			struct unary_op *insn = (struct unary_op *) pc;

			switch(reg[insn->reg].type) {
			default:
				ERR("unknown register type\n");
				ret = -EINVAL;
				goto end;

			case REG_S64:
				insn->op = FILTER_OP_UNARY_NOT_S64;
				break;
			case REG_DOUBLE:
				insn->op = FILTER_OP_UNARY_NOT_DOUBLE;
				break;
			}
			break;
		}

		case FILTER_OP_UNARY_PLUS_S64:
		case FILTER_OP_UNARY_MINUS_S64:
		case FILTER_OP_UNARY_NOT_S64:
		case FILTER_OP_UNARY_PLUS_DOUBLE:
		case FILTER_OP_UNARY_MINUS_DOUBLE:
		case FILTER_OP_UNARY_NOT_DOUBLE:
		{
			next_pc += sizeof(struct unary_op);
			break;
		}

		/* logical */
		case FILTER_OP_AND:
		case FILTER_OP_OR:
		{
			next_pc += sizeof(struct logical_op);
			break;
		}

		/* load */
		case FILTER_OP_LOAD_FIELD_REF:
		{
			ERR("Unknown field ref type\n");
			ret = -EINVAL;
			goto end;
		}
		case FILTER_OP_LOAD_FIELD_REF_STRING:
		case FILTER_OP_LOAD_FIELD_REF_SEQUENCE:
		{
			struct load_op *insn = (struct load_op *) pc;

			reg[insn->reg].type = REG_STRING;
			reg[insn->reg].literal = 0;
			next_pc += sizeof(struct load_op) + sizeof(struct field_ref);
			break;
		}
		case FILTER_OP_LOAD_FIELD_REF_S64:
		{
			struct load_op *insn = (struct load_op *) pc;

			reg[insn->reg].type = REG_S64;
			reg[insn->reg].literal = 0;
			next_pc += sizeof(struct load_op) + sizeof(struct field_ref);
			break;
		}
		case FILTER_OP_LOAD_FIELD_REF_DOUBLE:
		{
			struct load_op *insn = (struct load_op *) pc;

			reg[insn->reg].type = REG_DOUBLE;
			reg[insn->reg].literal = 0;
			next_pc += sizeof(struct load_op) + sizeof(struct field_ref);
			break;
		}

		case FILTER_OP_LOAD_STRING:
		{
			struct load_op *insn = (struct load_op *) pc;

			reg[insn->reg].type = REG_STRING;
			reg[insn->reg].literal = 1;
			next_pc += sizeof(struct load_op) + strlen(insn->data) + 1;
			break;
		}

		case FILTER_OP_LOAD_S64:
		{
			struct load_op *insn = (struct load_op *) pc;

			reg[insn->reg].type = REG_S64;
			reg[insn->reg].literal = 1;
			next_pc += sizeof(struct load_op)
					+ sizeof(struct literal_numeric);
			break;
		}

		case FILTER_OP_LOAD_DOUBLE:
		{
			struct load_op *insn = (struct load_op *) pc;

			reg[insn->reg].type = REG_DOUBLE;
			reg[insn->reg].literal = 1;
			next_pc += sizeof(struct load_op)
					+ sizeof(struct literal_double);
			break;
		}
		}
	}
end:
	return ret;
}



static
int apply_field_reloc(struct ltt_event *event,
		struct bytecode_runtime *runtime,
		uint32_t runtime_len,
		uint32_t reloc_offset,
		const char *field_name)
{
	const struct lttng_event_desc *desc;
	const struct lttng_event_field *fields, *field = NULL;
	unsigned int nr_fields, i;
	struct field_ref *field_ref;
	struct load_op *op;
	uint32_t field_offset = 0;

	dbg_printf("Apply reloc: %u %s\n", reloc_offset, field_name);

	/* Ensure that the reloc is within the code */
	if (runtime_len - reloc_offset < sizeof(uint16_t))
		return -EINVAL;

	/* Lookup event by name */
	desc = event->desc;
	if (!desc)
		return -EINVAL;
	fields = desc->fields;
	if (!fields)
		return -EINVAL;
	nr_fields = desc->nr_fields;
	for (i = 0; i < nr_fields; i++) {
		if (!strcmp(fields[i].name, field_name)) {
			field = &fields[i];
			break;
		}
		/* compute field offset */
		switch (fields[i].type.atype) {
		case atype_integer:
		case atype_enum:
			field_offset += sizeof(int64_t);
			break;
		case atype_array:
		case atype_sequence:
			field_offset += sizeof(unsigned long);
			field_offset += sizeof(void *);
			break;
		case atype_string:
			field_offset += sizeof(void *);
			break;
		case atype_float:
			field_offset += sizeof(double);
			break;
		default:
			return -EINVAL;
		}
	}
	if (!field)
		return -EINVAL;

	/* Check if field offset is too large for 16-bit offset */
	if (field_offset > FILTER_BYTECODE_MAX_LEN)
		return -EINVAL;

	/* set type */
	op = (struct load_op *) &runtime->data[reloc_offset];
	field_ref = (struct field_ref *) op->data;
	switch (field->type.atype) {
	case atype_integer:
	case atype_enum:
		op->op = FILTER_OP_LOAD_FIELD_REF_S64;
		break;
	case atype_array:
	case atype_sequence:
		op->op = FILTER_OP_LOAD_FIELD_REF_SEQUENCE;
		break;
	case atype_string:
		op->op = FILTER_OP_LOAD_FIELD_REF_STRING;
		break;
	case atype_float:
		op->op = FILTER_OP_LOAD_FIELD_REF_DOUBLE;
		break;
	default:
		return -EINVAL;
	}
	/* set offset */
	field_ref->offset = (uint16_t) field_offset;
	return 0;
}

/*
 * Take a bytecode with reloc table and link it to an event to create a
 * bytecode runtime.
 */
static
int _lttng_filter_event_link_bytecode(struct ltt_event *event,
		struct lttng_ust_filter_bytecode *filter_bytecode)
{
	int ret, offset, next_offset;
	struct bytecode_runtime *runtime = NULL;
	size_t runtime_alloc_len;

	if (!filter_bytecode)
		return 0;
	/* Even is not connected to any description */
	if (!event->desc)
		return 0;
	/* Bytecode already linked */
	if (event->filter || event->filter_data)
		return 0;

	dbg_printf("Linking\n");

	/* We don't need the reloc table in the runtime */
	runtime_alloc_len = sizeof(*runtime) + filter_bytecode->reloc_offset;
	runtime = zmalloc(runtime_alloc_len);
	if (!runtime) {
		ret = -ENOMEM;
		goto link_error;
	}
	runtime->len = filter_bytecode->reloc_offset;
	/* copy original bytecode */
	memcpy(runtime->data, filter_bytecode->data, runtime->len);
	/*
	 * apply relocs. Those are a uint16_t (offset in bytecode)
	 * followed by a string (field name).
	 */
	for (offset = filter_bytecode->reloc_offset;
			offset < filter_bytecode->len;
			offset = next_offset) {
		uint16_t reloc_offset =
			*(uint16_t *) &filter_bytecode->data[offset];
		const char *field_name =
			(const char *) &filter_bytecode->data[offset + sizeof(uint16_t)];

		ret = apply_field_reloc(event, runtime, runtime->len, reloc_offset, field_name);
		if (ret) {
			goto link_error;
		}
		next_offset = offset + sizeof(uint16_t) + strlen(field_name) + 1;
	}
	/* Validate bytecode */
	ret = lttng_filter_validate_bytecode(runtime);
	if (ret) {
		goto link_error;
	}
	/* Specialize bytecode */
	ret = lttng_filter_specialize_bytecode(runtime);
	if (ret) {
		goto link_error;
	}
	event->filter_data = runtime;
	event->filter = lttng_filter_interpret_bytecode;
	return 0;

link_error:
	event->filter = lttng_filter_false;
	free(runtime);
	return ret;
}

void lttng_filter_event_link_bytecode(struct ltt_event *event,
		struct lttng_ust_filter_bytecode *filter_bytecode)
{
	int ret;

	ret = _lttng_filter_event_link_bytecode(event, filter_bytecode);
	if (ret) {
		fprintf(stderr, "[lttng filter] error linking event bytecode\n");
	}
}

/*
 * Link bytecode to all events for a wildcard. Skips events that already
 * have a bytecode linked.
 * We do not set each event's filter_bytecode field, because they do not
 * own the filter_bytecode: the wildcard owns it.
 */
void lttng_filter_wildcard_link_bytecode(struct session_wildcard *wildcard)
{
	struct ltt_event *event;
	int ret;

	if (!wildcard->filter_bytecode)
		return;

	cds_list_for_each_entry(event, &wildcard->events, wildcard_list) {
		if (event->filter)
			continue;
		ret = _lttng_filter_event_link_bytecode(event,
				wildcard->filter_bytecode);
		if (ret) {
			fprintf(stderr, "[lttng filter] error linking wildcard bytecode\n");
		}

	}
	return;
}

/*
 * Need to attach filter to an event before starting tracing for the
 * session. We own the filter_bytecode if we return success.
 */
int lttng_filter_event_attach_bytecode(struct ltt_event *event,
		struct lttng_ust_filter_bytecode *filter_bytecode)
{
	if (event->chan->session->been_active)
		return -EPERM;
	if (event->filter_bytecode)
		return -EEXIST;
	event->filter_bytecode = filter_bytecode;
	return 0;
}

/*
 * Need to attach filter to a wildcard before starting tracing for the
 * session. We own the filter_bytecode if we return success.
 */
int lttng_filter_wildcard_attach_bytecode(struct session_wildcard *wildcard,
		struct lttng_ust_filter_bytecode *filter_bytecode)
{
	if (wildcard->chan->session->been_active)
		return -EPERM;
	if (wildcard->filter_bytecode)
		return -EEXIST;
	wildcard->filter_bytecode = filter_bytecode;
	return 0;
}
