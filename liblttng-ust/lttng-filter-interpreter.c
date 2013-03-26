/*
 * lttng-filter-interpreter.c
 *
 * LTTng UST filter interpreter.
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

#include "lttng-filter.h"

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
int stack_strcmp(struct estack *stack, int top, const char *cmp_type)
{
	const char *p = estack_bx(stack, top)->u.s.str, *q = estack_ax(stack, top)->u.s.str;
	int ret;
	int diff;

	for (;;) {
		int escaped_r0 = 0;

		if (unlikely(p - estack_bx(stack, top)->u.s.str > estack_bx(stack, top)->u.s.seq_len || *p == '\0')) {
			if (q - estack_ax(stack, top)->u.s.str > estack_ax(stack, top)->u.s.seq_len || *q == '\0') {
				return 0;
			} else {
				if (estack_ax(stack, top)->u.s.literal) {
					ret = parse_char(&q);
					if (ret == -1)
						return 0;
				}
				return -1;
			}
		}
		if (unlikely(q - estack_ax(stack, top)->u.s.str > estack_ax(stack, top)->u.s.seq_len || *q == '\0')) {
			if (p - estack_bx(stack, top)->u.s.str > estack_bx(stack, top)->u.s.seq_len || *p == '\0') {
				return 0;
			} else {
				if (estack_bx(stack, top)->u.s.literal) {
					ret = parse_char(&p);
					if (ret == -1)
						return 0;
				}
				return 1;
			}
		}
		if (estack_bx(stack, top)->u.s.literal) {
			ret = parse_char(&p);
			if (ret == -1) {
				return 0;
			} else if (ret == -2) {
				escaped_r0 = 1;
			}
			/* else compare both char */
		}
		if (estack_ax(stack, top)->u.s.literal) {
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

uint64_t lttng_filter_false(void *filter_data,
		const char *filter_stack_data)
{
	return 0;
}

#ifdef INTERPRETER_USE_SWITCH

/*
 * Fallback for compilers that do not support taking address of labels.
 */

#define START_OP							\
	start_pc = &bytecode->data[0];					\
	for (pc = next_pc = start_pc; pc - start_pc < bytecode->len;	\
			pc = next_pc) {					\
		dbg_printf("Executing op %s (%u)\n",			\
			print_op((unsigned int) *(filter_opcode_t *) pc), \
			(unsigned int) *(filter_opcode_t *) pc); 	\
		switch (*(filter_opcode_t *) pc)	{

#define OP(name)	case name

#define PO		break

#define END_OP		}						\
	}

#else

/*
 * Dispatch-table based interpreter.
 */

#define START_OP							\
	start_pc = &bytecode->data[0];					\
	pc = next_pc = start_pc;					\
	if (unlikely(pc - start_pc >= bytecode->len))			\
		goto end;						\
	goto *dispatch[*(filter_opcode_t *) pc];

#define OP(name)							\
LABEL_##name

#define PO								\
		pc = next_pc;						\
		goto *dispatch[*(filter_opcode_t *) pc];

#define END_OP

#endif

/*
 * Return 0 (discard), or raise the 0x1 flag (log event).
 * Currently, other flags are kept for future extensions and have no
 * effect.
 */
uint64_t lttng_filter_interpret_bytecode(void *filter_data,
		const char *filter_stack_data)
{
	struct bytecode_runtime *bytecode = filter_data;
	void *pc, *next_pc, *start_pc;
	int ret = -EINVAL;
	uint64_t retval = 0;
	struct estack _stack;
	struct estack *stack = &_stack;
	register int64_t ax = 0, bx = 0;
	register int top = FILTER_STACK_EMPTY;
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

		/* Mixed S64-double binary comparators */
		[ FILTER_OP_EQ_DOUBLE_S64 ] = &&LABEL_FILTER_OP_EQ_DOUBLE_S64,
		[ FILTER_OP_NE_DOUBLE_S64 ] = &&LABEL_FILTER_OP_NE_DOUBLE_S64,
		[ FILTER_OP_GT_DOUBLE_S64 ] = &&LABEL_FILTER_OP_GT_DOUBLE_S64,
		[ FILTER_OP_LT_DOUBLE_S64 ] = &&LABEL_FILTER_OP_LT_DOUBLE_S64,
		[ FILTER_OP_GE_DOUBLE_S64 ] = &&LABEL_FILTER_OP_GE_DOUBLE_S64,
		[ FILTER_OP_LE_DOUBLE_S64 ] = &&LABEL_FILTER_OP_LE_DOUBLE_S64,

		[ FILTER_OP_EQ_S64_DOUBLE ] = &&LABEL_FILTER_OP_EQ_S64_DOUBLE,
		[ FILTER_OP_NE_S64_DOUBLE ] = &&LABEL_FILTER_OP_NE_S64_DOUBLE,
		[ FILTER_OP_GT_S64_DOUBLE ] = &&LABEL_FILTER_OP_GT_S64_DOUBLE,
		[ FILTER_OP_LT_S64_DOUBLE ] = &&LABEL_FILTER_OP_LT_S64_DOUBLE,
		[ FILTER_OP_GE_S64_DOUBLE ] = &&LABEL_FILTER_OP_GE_S64_DOUBLE,
		[ FILTER_OP_LE_S64_DOUBLE ] = &&LABEL_FILTER_OP_LE_S64_DOUBLE,

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

		/* load field ref */
		[ FILTER_OP_LOAD_FIELD_REF ] = &&LABEL_FILTER_OP_LOAD_FIELD_REF,
		[ FILTER_OP_LOAD_FIELD_REF_STRING ] = &&LABEL_FILTER_OP_LOAD_FIELD_REF_STRING,
		[ FILTER_OP_LOAD_FIELD_REF_SEQUENCE ] = &&LABEL_FILTER_OP_LOAD_FIELD_REF_SEQUENCE,
		[ FILTER_OP_LOAD_FIELD_REF_S64 ] = &&LABEL_FILTER_OP_LOAD_FIELD_REF_S64,
		[ FILTER_OP_LOAD_FIELD_REF_DOUBLE ] = &&LABEL_FILTER_OP_LOAD_FIELD_REF_DOUBLE,

		/* load from immediate operand */
		[ FILTER_OP_LOAD_STRING ] = &&LABEL_FILTER_OP_LOAD_STRING,
		[ FILTER_OP_LOAD_S64 ] = &&LABEL_FILTER_OP_LOAD_S64,
		[ FILTER_OP_LOAD_DOUBLE ] = &&LABEL_FILTER_OP_LOAD_DOUBLE,

		/* cast */
		[ FILTER_OP_CAST_TO_S64 ] = &&LABEL_FILTER_OP_CAST_TO_S64,
		[ FILTER_OP_CAST_DOUBLE_TO_S64 ] = &&LABEL_FILTER_OP_CAST_DOUBLE_TO_S64,
		[ FILTER_OP_CAST_NOP ] = &&LABEL_FILTER_OP_CAST_NOP,

		/* get context ref */
		[ FILTER_OP_GET_CONTEXT_REF ] = &&LABEL_FILTER_OP_GET_CONTEXT_REF,
		[ FILTER_OP_GET_CONTEXT_REF_STRING ] = &&LABEL_FILTER_OP_GET_CONTEXT_REF_STRING,
		[ FILTER_OP_GET_CONTEXT_REF_S64 ] = &&LABEL_FILTER_OP_GET_CONTEXT_REF_S64,
		[ FILTER_OP_GET_CONTEXT_REF_DOUBLE ] = &&LABEL_FILTER_OP_GET_CONTEXT_REF_DOUBLE,
	};
#endif /* #ifndef INTERPRETER_USE_SWITCH */

	START_OP

		OP(FILTER_OP_UNKNOWN):
		OP(FILTER_OP_LOAD_FIELD_REF):
		OP(FILTER_OP_GET_CONTEXT_REF):
#ifdef INTERPRETER_USE_SWITCH
		default:
#endif /* INTERPRETER_USE_SWITCH */
			ERR("unknown bytecode op %u\n",
				(unsigned int) *(filter_opcode_t *) pc);
			ret = -EINVAL;
			goto end;

		OP(FILTER_OP_RETURN):
			/* LTTNG_FILTER_DISCARD  or LTTNG_FILTER_RECORD_FLAG */
			retval = !!estack_ax_v;
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
			int res;

			res = (stack_strcmp(stack, top, "==") == 0);
			estack_pop(stack, top, ax, bx);
			estack_ax_v = res;
			next_pc += sizeof(struct binary_op);
			PO;
		}
		OP(FILTER_OP_NE_STRING):
		{
			int res;

			res = (stack_strcmp(stack, top, "!=") != 0);
			estack_pop(stack, top, ax, bx);
			estack_ax_v = res;
			next_pc += sizeof(struct binary_op);
			PO;
		}
		OP(FILTER_OP_GT_STRING):
		{
			int res;

			res = (stack_strcmp(stack, top, ">") > 0);
			estack_pop(stack, top, ax, bx);
			estack_ax_v = res;
			next_pc += sizeof(struct binary_op);
			PO;
		}
		OP(FILTER_OP_LT_STRING):
		{
			int res;

			res = (stack_strcmp(stack, top, "<") < 0);
			estack_pop(stack, top, ax, bx);
			estack_ax_v = res;
			next_pc += sizeof(struct binary_op);
			PO;
		}
		OP(FILTER_OP_GE_STRING):
		{
			int res;

			res = (stack_strcmp(stack, top, ">=") >= 0);
			estack_pop(stack, top, ax, bx);
			estack_ax_v = res;
			next_pc += sizeof(struct binary_op);
			PO;
		}
		OP(FILTER_OP_LE_STRING):
		{
			int res;

			res = (stack_strcmp(stack, top, "<=") <= 0);
			estack_pop(stack, top, ax, bx);
			estack_ax_v = res;
			next_pc += sizeof(struct binary_op);
			PO;
		}

		OP(FILTER_OP_EQ_S64):
		{
			int res;

			res = (estack_bx_v == estack_ax_v);
			estack_pop(stack, top, ax, bx);
			estack_ax_v = res;
			next_pc += sizeof(struct binary_op);
			PO;
		}
		OP(FILTER_OP_NE_S64):
		{
			int res;

			res = (estack_bx_v != estack_ax_v);
			estack_pop(stack, top, ax, bx);
			estack_ax_v = res;
			next_pc += sizeof(struct binary_op);
			PO;
		}
		OP(FILTER_OP_GT_S64):
		{
			int res;

			res = (estack_bx_v > estack_ax_v);
			estack_pop(stack, top, ax, bx);
			estack_ax_v = res;
			next_pc += sizeof(struct binary_op);
			PO;
		}
		OP(FILTER_OP_LT_S64):
		{
			int res;

			res = (estack_bx_v < estack_ax_v);
			estack_pop(stack, top, ax, bx);
			estack_ax_v = res;
			next_pc += sizeof(struct binary_op);
			PO;
		}
		OP(FILTER_OP_GE_S64):
		{
			int res;

			res = (estack_bx_v >= estack_ax_v);
			estack_pop(stack, top, ax, bx);
			estack_ax_v = res;
			next_pc += sizeof(struct binary_op);
			PO;
		}
		OP(FILTER_OP_LE_S64):
		{
			int res;

			res = (estack_bx_v <= estack_ax_v);
			estack_pop(stack, top, ax, bx);
			estack_ax_v = res;
			next_pc += sizeof(struct binary_op);
			PO;
		}

		OP(FILTER_OP_EQ_DOUBLE):
		{
			int res;

			res = (estack_bx(stack, top)->u.d == estack_ax(stack, top)->u.d);
			estack_pop(stack, top, ax, bx);
			estack_ax_v = res;
			next_pc += sizeof(struct binary_op);
			PO;
		}
		OP(FILTER_OP_NE_DOUBLE):
		{
			int res;

			res = (estack_bx(stack, top)->u.d != estack_ax(stack, top)->u.d);
			estack_pop(stack, top, ax, bx);
			estack_ax_v = res;
			next_pc += sizeof(struct binary_op);
			PO;
		}
		OP(FILTER_OP_GT_DOUBLE):
		{
			int res;

			res = (estack_bx(stack, top)->u.d > estack_ax(stack, top)->u.d);
			estack_pop(stack, top, ax, bx);
			estack_ax_v = res;
			next_pc += sizeof(struct binary_op);
			PO;
		}
		OP(FILTER_OP_LT_DOUBLE):
		{
			int res;

			res = (estack_bx(stack, top)->u.d < estack_ax(stack, top)->u.d);
			estack_pop(stack, top, ax, bx);
			estack_ax_v = res;
			next_pc += sizeof(struct binary_op);
			PO;
		}
		OP(FILTER_OP_GE_DOUBLE):
		{
			int res;

			res = (estack_bx(stack, top)->u.d >= estack_ax(stack, top)->u.d);
			estack_pop(stack, top, ax, bx);
			estack_ax_v = res;
			next_pc += sizeof(struct binary_op);
			PO;
		}
		OP(FILTER_OP_LE_DOUBLE):
		{
			int res;

			res = (estack_bx(stack, top)->u.d <= estack_ax(stack, top)->u.d);
			estack_pop(stack, top, ax, bx);
			estack_ax_v = res;
			next_pc += sizeof(struct binary_op);
			PO;
		}

		/* Mixed S64-double binary comparators */
		OP(FILTER_OP_EQ_DOUBLE_S64):
		{
			int res;

			res = (estack_bx(stack, top)->u.d == estack_ax_v);
			estack_pop(stack, top, ax, bx);
			estack_ax_v = res;
			next_pc += sizeof(struct binary_op);
			PO;
		}
		OP(FILTER_OP_NE_DOUBLE_S64):
		{
			int res;

			res = (estack_bx(stack, top)->u.d != estack_ax_v);
			estack_pop(stack, top, ax, bx);
			estack_ax_v = res;
			next_pc += sizeof(struct binary_op);
			PO;
		}
		OP(FILTER_OP_GT_DOUBLE_S64):
		{
			int res;

			res = (estack_bx(stack, top)->u.d > estack_ax_v);
			estack_pop(stack, top, ax, bx);
			estack_ax_v = res;
			next_pc += sizeof(struct binary_op);
			PO;
		}
		OP(FILTER_OP_LT_DOUBLE_S64):
		{
			int res;

			res = (estack_bx(stack, top)->u.d < estack_ax_v);
			estack_pop(stack, top, ax, bx);
			estack_ax_v = res;
			next_pc += sizeof(struct binary_op);
			PO;
		}
		OP(FILTER_OP_GE_DOUBLE_S64):
		{
			int res;

			res = (estack_bx(stack, top)->u.d >= estack_ax_v);
			estack_pop(stack, top, ax, bx);
			estack_ax_v = res;
			next_pc += sizeof(struct binary_op);
			PO;
		}
		OP(FILTER_OP_LE_DOUBLE_S64):
		{
			int res;

			res = (estack_bx(stack, top)->u.d <= estack_ax_v);
			estack_pop(stack, top, ax, bx);
			estack_ax_v = res;
			next_pc += sizeof(struct binary_op);
			PO;
		}

		OP(FILTER_OP_EQ_S64_DOUBLE):
		{
			int res;

			res = (estack_bx_v == estack_ax(stack, top)->u.d);
			estack_pop(stack, top, ax, bx);
			estack_ax_v = res;
			next_pc += sizeof(struct binary_op);
			PO;
		}
		OP(FILTER_OP_NE_S64_DOUBLE):
		{
			int res;

			res = (estack_bx_v != estack_ax(stack, top)->u.d);
			estack_pop(stack, top, ax, bx);
			estack_ax_v = res;
			next_pc += sizeof(struct binary_op);
			PO;
		}
		OP(FILTER_OP_GT_S64_DOUBLE):
		{
			int res;

			res = (estack_bx_v > estack_ax(stack, top)->u.d);
			estack_pop(stack, top, ax, bx);
			estack_ax_v = res;
			next_pc += sizeof(struct binary_op);
			PO;
		}
		OP(FILTER_OP_LT_S64_DOUBLE):
		{
			int res;

			res = (estack_bx_v < estack_ax(stack, top)->u.d);
			estack_pop(stack, top, ax, bx);
			estack_ax_v = res;
			next_pc += sizeof(struct binary_op);
			PO;
		}
		OP(FILTER_OP_GE_S64_DOUBLE):
		{
			int res;

			res = (estack_bx_v >= estack_ax(stack, top)->u.d);
			estack_pop(stack, top, ax, bx);
			estack_ax_v = res;
			next_pc += sizeof(struct binary_op);
			PO;
		}
		OP(FILTER_OP_LE_S64_DOUBLE):
		{
			int res;

			res = (estack_bx_v <= estack_ax(stack, top)->u.d);
			estack_pop(stack, top, ax, bx);
			estack_ax_v = res;
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
			estack_ax_v = -estack_ax_v;
			next_pc += sizeof(struct unary_op);
			PO;
		}
		OP(FILTER_OP_UNARY_MINUS_DOUBLE):
		{
			estack_ax(stack, top)->u.d = -estack_ax(stack, top)->u.d;
			next_pc += sizeof(struct unary_op);
			PO;
		}
		OP(FILTER_OP_UNARY_NOT_S64):
		{
			estack_ax_v = !estack_ax_v;
			next_pc += sizeof(struct unary_op);
			PO;
		}
		OP(FILTER_OP_UNARY_NOT_DOUBLE):
		{
			estack_ax(stack, top)->u.d = !estack_ax(stack, top)->u.d;
			next_pc += sizeof(struct unary_op);
			PO;
		}

		/* logical */
		OP(FILTER_OP_AND):
		{
			struct logical_op *insn = (struct logical_op *) pc;

			/* If AX is 0, skip and evaluate to 0 */
			if (unlikely(estack_ax_v == 0)) {
				dbg_printf("Jumping to bytecode offset %u\n",
					(unsigned int) insn->skip_offset);
				next_pc = start_pc + insn->skip_offset;
			} else {
				/* Pop 1 when jump not taken */
				estack_pop(stack, top, ax, bx);
				next_pc += sizeof(struct logical_op);
			}
			PO;
		}
		OP(FILTER_OP_OR):
		{
			struct logical_op *insn = (struct logical_op *) pc;

			/* If AX is nonzero, skip and evaluate to 1 */

			if (unlikely(estack_ax_v != 0)) {
				estack_ax_v = 1;
				dbg_printf("Jumping to bytecode offset %u\n",
					(unsigned int) insn->skip_offset);
				next_pc = start_pc + insn->skip_offset;
			} else {
				/* Pop 1 when jump not taken */
				estack_pop(stack, top, ax, bx);
				next_pc += sizeof(struct logical_op);
			}
			PO;
		}


		/* load field ref */
		OP(FILTER_OP_LOAD_FIELD_REF_STRING):
		{
			struct load_op *insn = (struct load_op *) pc;
			struct field_ref *ref = (struct field_ref *) insn->data;

			dbg_printf("load field ref offset %u type string\n",
				ref->offset);
			estack_push(stack, top, ax, bx);
			estack_ax(stack, top)->u.s.str =
				*(const char * const *) &filter_stack_data[ref->offset];
			if (unlikely(!estack_ax(stack, top)->u.s.str)) {
				dbg_printf("Filter warning: loading a NULL string.\n");
				ret = -EINVAL;
				goto end;
			}
			estack_ax(stack, top)->u.s.seq_len = UINT_MAX;
			estack_ax(stack, top)->u.s.literal = 0;
			dbg_printf("ref load string %s\n", estack_ax(stack, top)->u.s.str);
			next_pc += sizeof(struct load_op) + sizeof(struct field_ref);
			PO;
		}

		OP(FILTER_OP_LOAD_FIELD_REF_SEQUENCE):
		{
			struct load_op *insn = (struct load_op *) pc;
			struct field_ref *ref = (struct field_ref *) insn->data;

			dbg_printf("load field ref offset %u type sequence\n",
				ref->offset);
			estack_push(stack, top, ax, bx);
			estack_ax(stack, top)->u.s.seq_len =
				*(unsigned long *) &filter_stack_data[ref->offset];
			estack_ax(stack, top)->u.s.str =
				*(const char **) (&filter_stack_data[ref->offset
								+ sizeof(unsigned long)]);
			if (unlikely(!estack_ax(stack, top)->u.s.str)) {
				dbg_printf("Filter warning: loading a NULL sequence.\n");
				ret = -EINVAL;
				goto end;
			}
			estack_ax(stack, top)->u.s.literal = 0;
			next_pc += sizeof(struct load_op) + sizeof(struct field_ref);
			PO;
		}

		OP(FILTER_OP_LOAD_FIELD_REF_S64):
		{
			struct load_op *insn = (struct load_op *) pc;
			struct field_ref *ref = (struct field_ref *) insn->data;

			dbg_printf("load field ref offset %u type s64\n",
				ref->offset);
			estack_push(stack, top, ax, bx);
			estack_ax_v =
				((struct literal_numeric *) &filter_stack_data[ref->offset])->v;
			dbg_printf("ref load s64 %" PRIi64 "\n", estack_ax_v);
			next_pc += sizeof(struct load_op) + sizeof(struct field_ref);
			PO;
		}

		OP(FILTER_OP_LOAD_FIELD_REF_DOUBLE):
		{
			struct load_op *insn = (struct load_op *) pc;
			struct field_ref *ref = (struct field_ref *) insn->data;

			dbg_printf("load field ref offset %u type double\n",
				ref->offset);
			estack_push(stack, top, ax, bx);
			memcpy(&estack_ax(stack, top)->u.d, &filter_stack_data[ref->offset],
				sizeof(struct literal_double));
			dbg_printf("ref load double %g\n", estack_ax(stack, top)->u.d);
			next_pc += sizeof(struct load_op) + sizeof(struct field_ref);
			PO;
		}

		/* load from immediate operand */
		OP(FILTER_OP_LOAD_STRING):
		{
			struct load_op *insn = (struct load_op *) pc;

			dbg_printf("load string %s\n", insn->data);
			estack_push(stack, top, ax, bx);
			estack_ax(stack, top)->u.s.str = insn->data;
			estack_ax(stack, top)->u.s.seq_len = UINT_MAX;
			estack_ax(stack, top)->u.s.literal = 1;
			next_pc += sizeof(struct load_op) + strlen(insn->data) + 1;
			PO;
		}

		OP(FILTER_OP_LOAD_S64):
		{
			struct load_op *insn = (struct load_op *) pc;

			estack_push(stack, top, ax, bx);
			estack_ax_v = ((struct literal_numeric *) insn->data)->v;
			dbg_printf("load s64 %" PRIi64 "\n", estack_ax_v);
			next_pc += sizeof(struct load_op)
					+ sizeof(struct literal_numeric);
			PO;
		}

		OP(FILTER_OP_LOAD_DOUBLE):
		{
			struct load_op *insn = (struct load_op *) pc;

			estack_push(stack, top, ax, bx);
			memcpy(&estack_ax(stack, top)->u.d, insn->data,
				sizeof(struct literal_double));
			dbg_printf("load s64 %g\n", estack_ax(stack, top)->u.d);
			next_pc += sizeof(struct load_op)
					+ sizeof(struct literal_double);
			PO;
		}

		/* cast */
		OP(FILTER_OP_CAST_TO_S64):
			ERR("unsupported non-specialized bytecode op %u\n",
				(unsigned int) *(filter_opcode_t *) pc);
			ret = -EINVAL;
			goto end;

		OP(FILTER_OP_CAST_DOUBLE_TO_S64):
		{
			estack_ax_v = (int64_t) estack_ax(stack, top)->u.d;
			next_pc += sizeof(struct cast_op);
			PO;
		}

		OP(FILTER_OP_CAST_NOP):
		{
			next_pc += sizeof(struct cast_op);
			PO;
		}

		/* get context ref */
		OP(FILTER_OP_GET_CONTEXT_REF_STRING):
		{
			struct load_op *insn = (struct load_op *) pc;
			struct field_ref *ref = (struct field_ref *) insn->data;
			struct lttng_ctx_field *ctx_field;
			union lttng_ctx_value v;

			dbg_printf("get context ref offset %u type string\n",
				ref->offset);
			ctx_field = &lttng_static_ctx->fields[ref->offset];
			ctx_field->get_value(ctx_field, &v);
			estack_push(stack, top, ax, bx);
			estack_ax(stack, top)->u.s.str = v.str;
			if (unlikely(!estack_ax(stack, top)->u.s.str)) {
				dbg_printf("Filter warning: loading a NULL string.\n");
				ret = -EINVAL;
				goto end;
			}
			estack_ax(stack, top)->u.s.seq_len = UINT_MAX;
			estack_ax(stack, top)->u.s.literal = 0;
			dbg_printf("ref get context string %s\n", estack_ax(stack, top)->u.s.str);
			next_pc += sizeof(struct load_op) + sizeof(struct field_ref);
			PO;
		}

		OP(FILTER_OP_GET_CONTEXT_REF_S64):
		{
			struct load_op *insn = (struct load_op *) pc;
			struct field_ref *ref = (struct field_ref *) insn->data;
			struct lttng_ctx_field *ctx_field;
			union lttng_ctx_value v;

			dbg_printf("get context ref offset %u type s64\n",
				ref->offset);
			ctx_field = &lttng_static_ctx->fields[ref->offset];
			ctx_field->get_value(ctx_field, &v);
			estack_push(stack, top, ax, bx);
			estack_ax_v = v.s64;
			dbg_printf("ref get context s64 %" PRIi64 "\n", estack_ax_v);
			next_pc += sizeof(struct load_op) + sizeof(struct field_ref);
			PO;
		}

		OP(FILTER_OP_GET_CONTEXT_REF_DOUBLE):
		{
			struct load_op *insn = (struct load_op *) pc;
			struct field_ref *ref = (struct field_ref *) insn->data;
			struct lttng_ctx_field *ctx_field;
			union lttng_ctx_value v;

			dbg_printf("get context ref offset %u type double\n",
				ref->offset);
			ctx_field = &lttng_static_ctx->fields[ref->offset];
			ctx_field->get_value(ctx_field, &v);
			estack_push(stack, top, ax, bx);
			memcpy(&estack_ax(stack, top)->u.d, &v.d, sizeof(struct literal_double));
			dbg_printf("ref get context double %g\n", estack_ax(stack, top)->u.d);
			next_pc += sizeof(struct load_op) + sizeof(struct field_ref);
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
