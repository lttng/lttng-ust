/*
 * lttng-filter-specialize.c
 *
 * LTTng UST filter code specializer.
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
				insn->op = FILTER_OP_EQ_STRING;
				break;
			case REG_S64:
				if (vstack_bx(stack)->type == REG_S64)
					insn->op = FILTER_OP_EQ_S64;
				else
					insn->op = FILTER_OP_EQ_DOUBLE_S64;
				break;
			case REG_DOUBLE:
				if (vstack_bx(stack)->type == REG_S64)
					insn->op = FILTER_OP_EQ_S64_DOUBLE;
				else
					insn->op = FILTER_OP_EQ_DOUBLE;
				break;
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
				insn->op = FILTER_OP_NE_STRING;
				break;
			case REG_S64:
				if (vstack_bx(stack)->type == REG_S64)
					insn->op = FILTER_OP_NE_S64;
				else
					insn->op = FILTER_OP_NE_DOUBLE_S64;
				break;
			case REG_DOUBLE:
				if (vstack_bx(stack)->type == REG_S64)
					insn->op = FILTER_OP_NE_S64_DOUBLE;
				else
					insn->op = FILTER_OP_NE_DOUBLE;
				break;
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

			case REG_STRING:
				insn->op = FILTER_OP_GT_STRING;
				break;
			case REG_S64:
				if (vstack_bx(stack)->type == REG_S64)
					insn->op = FILTER_OP_GT_S64;
				else
					insn->op = FILTER_OP_GT_DOUBLE_S64;
				break;
			case REG_DOUBLE:
				if (vstack_bx(stack)->type == REG_S64)
					insn->op = FILTER_OP_GT_S64_DOUBLE;
				else
					insn->op = FILTER_OP_GT_DOUBLE;
				break;
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

			case REG_STRING:
				insn->op = FILTER_OP_LT_STRING;
				break;
			case REG_S64:
				if (vstack_bx(stack)->type == REG_S64)
					insn->op = FILTER_OP_LT_S64;
				else
					insn->op = FILTER_OP_LT_DOUBLE_S64;
				break;
			case REG_DOUBLE:
				if (vstack_bx(stack)->type == REG_S64)
					insn->op = FILTER_OP_LT_S64_DOUBLE;
				else
					insn->op = FILTER_OP_LT_DOUBLE;
				break;
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

			case REG_STRING:
				insn->op = FILTER_OP_GE_STRING;
				break;
			case REG_S64:
				if (vstack_bx(stack)->type == REG_S64)
					insn->op = FILTER_OP_GE_S64;
				else
					insn->op = FILTER_OP_GE_DOUBLE_S64;
				break;
			case REG_DOUBLE:
				if (vstack_bx(stack)->type == REG_S64)
					insn->op = FILTER_OP_GE_S64_DOUBLE;
				else
					insn->op = FILTER_OP_GE_DOUBLE;
				break;
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

			case REG_STRING:
				insn->op = FILTER_OP_LE_STRING;
				break;
			case REG_S64:
				if (vstack_bx(stack)->type == REG_S64)
					insn->op = FILTER_OP_LE_S64;
				else
					insn->op = FILTER_OP_LE_DOUBLE_S64;
				break;
			case REG_DOUBLE:
				if (vstack_bx(stack)->type == REG_S64)
					insn->op = FILTER_OP_LE_S64_DOUBLE;
				else
					insn->op = FILTER_OP_LE_DOUBLE;
				break;
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
			ERR("Unknown get context ref type\n");
			ret = -EINVAL;
			goto end;
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
				ERR("Cast op can only be applied to numeric or floating point registers\n");
				ret = -EINVAL;
				goto end;
			case REG_S64:
				insn->op = FILTER_OP_CAST_NOP;
				break;
			case REG_DOUBLE:
				insn->op = FILTER_OP_CAST_DOUBLE_TO_S64;
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
