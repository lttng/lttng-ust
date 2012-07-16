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
			next_pc += sizeof(struct unary_op);
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
			next_pc += sizeof(struct unary_op);
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

		/* cast */
		case FILTER_OP_CAST_TO_S64:
		{
			struct cast_op *insn = (struct cast_op *) pc;

			switch (reg[insn->reg].type) {
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
			reg[insn->reg].type = REG_S64;
			next_pc += sizeof(struct cast_op);
			break;
		}
		case FILTER_OP_CAST_DOUBLE_TO_S64:
		{
			struct cast_op *insn = (struct cast_op *) pc;

			reg[insn->reg].type = REG_S64;
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
