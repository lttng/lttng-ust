/*
 * lttng-filter-specialize.c
 *
 * LTTng UST filter code specializer.
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

#define _LGPL_SOURCE
#include "lttng-filter.h"

int lttng_filter_specialize_bytecode(struct bytecode_runtime *bytecode)
{
	void *pc, *next_pc, *start_pc;
	int ret = -EINVAL;
	struct vstack _stack;
	struct vstack *stack = &_stack;

	vstack_init(stack);

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

			switch(vstack_ax(stack)->type) {
			default:
				ERR("unknown register type\n");
				ret = -EINVAL;
				goto end;

			case REG_STRING:
				if (vstack_bx(stack)->type == REG_UNKNOWN)
					break;
				if (vstack_bx(stack)->type == REG_STAR_GLOB_STRING)
					insn->op = FILTER_OP_EQ_STAR_GLOB_STRING;
				else
					insn->op = FILTER_OP_EQ_STRING;
				break;
			case REG_STAR_GLOB_STRING:
				if (vstack_bx(stack)->type == REG_UNKNOWN)
					break;
				insn->op = FILTER_OP_EQ_STAR_GLOB_STRING;
				break;
			case REG_S64:
				if (vstack_bx(stack)->type == REG_UNKNOWN)
					break;
				if (vstack_bx(stack)->type == REG_S64)
					insn->op = FILTER_OP_EQ_S64;
				else
					insn->op = FILTER_OP_EQ_DOUBLE_S64;
				break;
			case REG_DOUBLE:
				if (vstack_bx(stack)->type == REG_UNKNOWN)
					break;
				if (vstack_bx(stack)->type == REG_S64)
					insn->op = FILTER_OP_EQ_S64_DOUBLE;
				else
					insn->op = FILTER_OP_EQ_DOUBLE;
				break;
			case REG_UNKNOWN:
				break;	/* Dynamic typing. */
			}
			/* Pop 2, push 1 */
			if (vstack_pop(stack)) {
				ret = -EINVAL;
				goto end;
			}
			vstack_ax(stack)->type = REG_S64;
			next_pc += sizeof(struct binary_op);
			break;
		}

		case FILTER_OP_NE:
		{
			struct binary_op *insn = (struct binary_op *) pc;

			switch(vstack_ax(stack)->type) {
			default:
				ERR("unknown register type\n");
				ret = -EINVAL;
				goto end;

			case REG_STRING:
				if (vstack_bx(stack)->type == REG_UNKNOWN)
					break;
				if (vstack_bx(stack)->type == REG_STAR_GLOB_STRING)
					insn->op = FILTER_OP_NE_STAR_GLOB_STRING;
				else
					insn->op = FILTER_OP_NE_STRING;
				break;
			case REG_STAR_GLOB_STRING:
				if (vstack_bx(stack)->type == REG_UNKNOWN)
					break;
				insn->op = FILTER_OP_NE_STAR_GLOB_STRING;
				break;
			case REG_S64:
				if (vstack_bx(stack)->type == REG_UNKNOWN)
					break;
				if (vstack_bx(stack)->type == REG_S64)
					insn->op = FILTER_OP_NE_S64;
				else
					insn->op = FILTER_OP_NE_DOUBLE_S64;
				break;
			case REG_DOUBLE:
				if (vstack_bx(stack)->type == REG_UNKNOWN)
					break;
				if (vstack_bx(stack)->type == REG_S64)
					insn->op = FILTER_OP_NE_S64_DOUBLE;
				else
					insn->op = FILTER_OP_NE_DOUBLE;
				break;
			case REG_UNKNOWN:
				break;	/* Dynamic typing. */
			}
			/* Pop 2, push 1 */
			if (vstack_pop(stack)) {
				ret = -EINVAL;
				goto end;
			}
			vstack_ax(stack)->type = REG_S64;
			next_pc += sizeof(struct binary_op);
			break;
		}

		case FILTER_OP_GT:
		{
			struct binary_op *insn = (struct binary_op *) pc;

			switch(vstack_ax(stack)->type) {
			default:
				ERR("unknown register type\n");
				ret = -EINVAL;
				goto end;

			case REG_STAR_GLOB_STRING:
				ERR("invalid register type for > binary operator\n");
				ret = -EINVAL;
				goto end;
			case REG_STRING:
				if (vstack_bx(stack)->type == REG_UNKNOWN)
					break;
				insn->op = FILTER_OP_GT_STRING;
				break;
			case REG_S64:
				if (vstack_bx(stack)->type == REG_UNKNOWN)
					break;
				if (vstack_bx(stack)->type == REG_S64)
					insn->op = FILTER_OP_GT_S64;
				else
					insn->op = FILTER_OP_GT_DOUBLE_S64;
				break;
			case REG_DOUBLE:
				if (vstack_bx(stack)->type == REG_UNKNOWN)
					break;
				if (vstack_bx(stack)->type == REG_S64)
					insn->op = FILTER_OP_GT_S64_DOUBLE;
				else
					insn->op = FILTER_OP_GT_DOUBLE;
				break;
			case REG_UNKNOWN:
				break;	/* Dynamic typing. */
			}
			/* Pop 2, push 1 */
			if (vstack_pop(stack)) {
				ret = -EINVAL;
				goto end;
			}
			vstack_ax(stack)->type = REG_S64;
			next_pc += sizeof(struct binary_op);
			break;
		}

		case FILTER_OP_LT:
		{
			struct binary_op *insn = (struct binary_op *) pc;

			switch(vstack_ax(stack)->type) {
			default:
				ERR("unknown register type\n");
				ret = -EINVAL;
				goto end;

			case REG_STAR_GLOB_STRING:
				ERR("invalid register type for < binary operator\n");
				ret = -EINVAL;
				goto end;
			case REG_STRING:
				if (vstack_bx(stack)->type == REG_UNKNOWN)
					break;
				insn->op = FILTER_OP_LT_STRING;
				break;
			case REG_S64:
				if (vstack_bx(stack)->type == REG_UNKNOWN)
					break;
				if (vstack_bx(stack)->type == REG_S64)
					insn->op = FILTER_OP_LT_S64;
				else
					insn->op = FILTER_OP_LT_DOUBLE_S64;
				break;
			case REG_DOUBLE:
				if (vstack_bx(stack)->type == REG_UNKNOWN)
					break;
				if (vstack_bx(stack)->type == REG_S64)
					insn->op = FILTER_OP_LT_S64_DOUBLE;
				else
					insn->op = FILTER_OP_LT_DOUBLE;
				break;
			case REG_UNKNOWN:
				break;	/* Dynamic typing. */
			}
			/* Pop 2, push 1 */
			if (vstack_pop(stack)) {
				ret = -EINVAL;
				goto end;
			}
			vstack_ax(stack)->type = REG_S64;
			next_pc += sizeof(struct binary_op);
			break;
		}

		case FILTER_OP_GE:
		{
			struct binary_op *insn = (struct binary_op *) pc;

			switch(vstack_ax(stack)->type) {
			default:
				ERR("unknown register type\n");
				ret = -EINVAL;
				goto end;

			case REG_STAR_GLOB_STRING:
				ERR("invalid register type for >= binary operator\n");
				ret = -EINVAL;
				goto end;
			case REG_STRING:
				if (vstack_bx(stack)->type == REG_UNKNOWN)
					break;
				insn->op = FILTER_OP_GE_STRING;
				break;
			case REG_S64:
				if (vstack_bx(stack)->type == REG_UNKNOWN)
					break;
				if (vstack_bx(stack)->type == REG_S64)
					insn->op = FILTER_OP_GE_S64;
				else
					insn->op = FILTER_OP_GE_DOUBLE_S64;
				break;
			case REG_DOUBLE:
				if (vstack_bx(stack)->type == REG_UNKNOWN)
					break;
				if (vstack_bx(stack)->type == REG_S64)
					insn->op = FILTER_OP_GE_S64_DOUBLE;
				else
					insn->op = FILTER_OP_GE_DOUBLE;
				break;
			case REG_UNKNOWN:
				break;	/* Dynamic typing. */
			}
			/* Pop 2, push 1 */
			if (vstack_pop(stack)) {
				ret = -EINVAL;
				goto end;
			}
			vstack_ax(stack)->type = REG_S64;
			next_pc += sizeof(struct binary_op);
			break;
		}
		case FILTER_OP_LE:
		{
			struct binary_op *insn = (struct binary_op *) pc;

			switch(vstack_ax(stack)->type) {
			default:
				ERR("unknown register type\n");
				ret = -EINVAL;
				goto end;

			case REG_STAR_GLOB_STRING:
				ERR("invalid register type for <= binary operator\n");
				ret = -EINVAL;
				goto end;
			case REG_STRING:
				if (vstack_bx(stack)->type == REG_UNKNOWN)
					break;
				insn->op = FILTER_OP_LE_STRING;
				break;
			case REG_S64:
				if (vstack_bx(stack)->type == REG_UNKNOWN)
					break;
				if (vstack_bx(stack)->type == REG_S64)
					insn->op = FILTER_OP_LE_S64;
				else
					insn->op = FILTER_OP_LE_DOUBLE_S64;
				break;
			case REG_DOUBLE:
				if (vstack_bx(stack)->type == REG_UNKNOWN)
					break;
				if (vstack_bx(stack)->type == REG_S64)
					insn->op = FILTER_OP_LE_S64_DOUBLE;
				else
					insn->op = FILTER_OP_LE_DOUBLE;
				break;
			case REG_UNKNOWN:
				break;	/* Dynamic typing. */
			}
			vstack_ax(stack)->type = REG_S64;
			next_pc += sizeof(struct binary_op);
			break;
		}

		case FILTER_OP_EQ_STRING:
		case FILTER_OP_NE_STRING:
		case FILTER_OP_GT_STRING:
		case FILTER_OP_LT_STRING:
		case FILTER_OP_GE_STRING:
		case FILTER_OP_LE_STRING:
		case FILTER_OP_EQ_STAR_GLOB_STRING:
		case FILTER_OP_NE_STAR_GLOB_STRING:
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
		case FILTER_OP_EQ_DOUBLE_S64:
		case FILTER_OP_NE_DOUBLE_S64:
		case FILTER_OP_GT_DOUBLE_S64:
		case FILTER_OP_LT_DOUBLE_S64:
		case FILTER_OP_GE_DOUBLE_S64:
		case FILTER_OP_LE_DOUBLE_S64:
		case FILTER_OP_EQ_S64_DOUBLE:
		case FILTER_OP_NE_S64_DOUBLE:
		case FILTER_OP_GT_S64_DOUBLE:
		case FILTER_OP_LT_S64_DOUBLE:
		case FILTER_OP_GE_S64_DOUBLE:
		case FILTER_OP_LE_S64_DOUBLE:
		{
			/* Pop 2, push 1 */
			if (vstack_pop(stack)) {
				ret = -EINVAL;
				goto end;
			}
			vstack_ax(stack)->type = REG_S64;
			next_pc += sizeof(struct binary_op);
			break;
		}

		/* unary */
		case FILTER_OP_UNARY_PLUS:
		{
			struct unary_op *insn = (struct unary_op *) pc;

			switch(vstack_ax(stack)->type) {
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
			case REG_UNKNOWN:	/* Dynamic typing. */
				break;
			}
			/* Pop 1, push 1 */
			next_pc += sizeof(struct unary_op);
			break;
		}

		case FILTER_OP_UNARY_MINUS:
		{
			struct unary_op *insn = (struct unary_op *) pc;

			switch(vstack_ax(stack)->type) {
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
			case REG_UNKNOWN:	/* Dynamic typing. */
				break;
			}
			/* Pop 1, push 1 */
			next_pc += sizeof(struct unary_op);
			break;
		}

		case FILTER_OP_UNARY_NOT:
		{
			struct unary_op *insn = (struct unary_op *) pc;

			switch(vstack_ax(stack)->type) {
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
			case REG_UNKNOWN:	/* Dynamic typing. */
				break;
			}
			/* Pop 1, push 1 */
			next_pc += sizeof(struct unary_op);
			break;
		}

		case FILTER_OP_UNARY_PLUS_S64:
		case FILTER_OP_UNARY_MINUS_S64:
		case FILTER_OP_UNARY_NOT_S64:
		case FILTER_OP_UNARY_PLUS_DOUBLE:
		case FILTER_OP_UNARY_MINUS_DOUBLE:
		case FILTER_OP_UNARY_NOT_DOUBLE:
		{
			/* Pop 1, push 1 */
			next_pc += sizeof(struct unary_op);
			break;
		}

		/* logical */
		case FILTER_OP_AND:
		case FILTER_OP_OR:
		{
			/* Continue to next instruction */
			/* Pop 1 when jump not taken */
			if (vstack_pop(stack)) {
				ret = -EINVAL;
				goto end;
			}
			next_pc += sizeof(struct logical_op);
			break;
		}

		/* load field ref */
		case FILTER_OP_LOAD_FIELD_REF:
		{
			ERR("Unknown field ref type\n");
			ret = -EINVAL;
			goto end;
		}
		/* get context ref */
		case FILTER_OP_GET_CONTEXT_REF:
		{
			if (vstack_push(stack)) {
				ret = -EINVAL;
				goto end;
			}
			vstack_ax(stack)->type = REG_UNKNOWN;
			next_pc += sizeof(struct load_op) + sizeof(struct field_ref);
			break;
		}
		case FILTER_OP_LOAD_FIELD_REF_STRING:
		case FILTER_OP_LOAD_FIELD_REF_SEQUENCE:
		case FILTER_OP_GET_CONTEXT_REF_STRING:
		{
			if (vstack_push(stack)) {
				ret = -EINVAL;
				goto end;
			}
			vstack_ax(stack)->type = REG_STRING;
			next_pc += sizeof(struct load_op) + sizeof(struct field_ref);
			break;
		}
		case FILTER_OP_LOAD_FIELD_REF_S64:
		case FILTER_OP_GET_CONTEXT_REF_S64:
		{
			if (vstack_push(stack)) {
				ret = -EINVAL;
				goto end;
			}
			vstack_ax(stack)->type = REG_S64;
			next_pc += sizeof(struct load_op) + sizeof(struct field_ref);
			break;
		}
		case FILTER_OP_LOAD_FIELD_REF_DOUBLE:
		case FILTER_OP_GET_CONTEXT_REF_DOUBLE:
		{
			if (vstack_push(stack)) {
				ret = -EINVAL;
				goto end;
			}
			vstack_ax(stack)->type = REG_DOUBLE;
			next_pc += sizeof(struct load_op) + sizeof(struct field_ref);
			break;
		}

		/* load from immediate operand */
		case FILTER_OP_LOAD_STRING:
		{
			struct load_op *insn = (struct load_op *) pc;

			if (vstack_push(stack)) {
				ret = -EINVAL;
				goto end;
			}
			vstack_ax(stack)->type = REG_STRING;
			next_pc += sizeof(struct load_op) + strlen(insn->data) + 1;
			break;
		}

		case FILTER_OP_LOAD_STAR_GLOB_STRING:
		{
			struct load_op *insn = (struct load_op *) pc;

			if (vstack_push(stack)) {
				ret = -EINVAL;
				goto end;
			}
			vstack_ax(stack)->type = REG_STAR_GLOB_STRING;
			next_pc += sizeof(struct load_op) + strlen(insn->data) + 1;
			break;
		}

		case FILTER_OP_LOAD_S64:
		{
			if (vstack_push(stack)) {
				ret = -EINVAL;
				goto end;
			}
			vstack_ax(stack)->type = REG_S64;
			next_pc += sizeof(struct load_op)
					+ sizeof(struct literal_numeric);
			break;
		}

		case FILTER_OP_LOAD_DOUBLE:
		{
			if (vstack_push(stack)) {
				ret = -EINVAL;
				goto end;
			}
			vstack_ax(stack)->type = REG_DOUBLE;
			next_pc += sizeof(struct load_op)
					+ sizeof(struct literal_double);
			break;
		}

		/* cast */
		case FILTER_OP_CAST_TO_S64:
		{
			struct cast_op *insn = (struct cast_op *) pc;

			switch (vstack_ax(stack)->type) {
			default:
				ERR("unknown register type\n");
				ret = -EINVAL;
				goto end;

			case REG_STRING:
			case REG_STAR_GLOB_STRING:
				ERR("Cast op can only be applied to numeric or floating point registers\n");
				ret = -EINVAL;
				goto end;
			case REG_S64:
				insn->op = FILTER_OP_CAST_NOP;
				break;
			case REG_DOUBLE:
				insn->op = FILTER_OP_CAST_DOUBLE_TO_S64;
				break;
			case REG_UNKNOWN:
				break;
			}
			/* Pop 1, push 1 */
			vstack_ax(stack)->type = REG_S64;
			next_pc += sizeof(struct cast_op);
			break;
		}
		case FILTER_OP_CAST_DOUBLE_TO_S64:
		{
			/* Pop 1, push 1 */
			vstack_ax(stack)->type = REG_S64;
			next_pc += sizeof(struct cast_op);
			break;
		}
		case FILTER_OP_CAST_NOP:
		{
			next_pc += sizeof(struct cast_op);
			break;
		}

		}
	}
end:
	return ret;
}
