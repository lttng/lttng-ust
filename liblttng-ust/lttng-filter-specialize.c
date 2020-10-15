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
#include <stddef.h>
#include <stdint.h>

#include "lttng-filter.h"
#include <lttng/align.h>

static int lttng_fls(int val)
{
	int r = 32;
	unsigned int x = (unsigned int) val;

	if (!x)
		return 0;
	if (!(x & 0xFFFF0000U)) {
		x <<= 16;
		r -= 16;
	}
	if (!(x & 0xFF000000U)) {
		x <<= 8;
		r -= 8;
	}
	if (!(x & 0xF0000000U)) {
		x <<= 4;
		r -= 4;
	}
	if (!(x & 0xC0000000U)) {
		x <<= 2;
		r -= 2;
	}
	if (!(x & 0x80000000U)) {
		r -= 1;
	}
	return r;
}

static int get_count_order(unsigned int count)
{
	int order;

	order = lttng_fls(count) - 1;
	if (count & (count - 1))
		order++;
	return order;
}

static ssize_t bytecode_reserve_data(struct bytecode_runtime *runtime,
		size_t align, size_t len)
{
	ssize_t ret;
	size_t padding = lttng_ust_offset_align(runtime->data_len, align);
	size_t new_len = runtime->data_len + padding + len;
	size_t new_alloc_len = new_len;
	size_t old_alloc_len = runtime->data_alloc_len;

	if (new_len > FILTER_MAX_DATA_LEN)
		return -EINVAL;

	if (new_alloc_len > old_alloc_len) {
		char *newptr;

		new_alloc_len =
			max_t(size_t, 1U << get_count_order(new_alloc_len), old_alloc_len << 1);
		newptr = realloc(runtime->data, new_alloc_len);
		if (!newptr)
			return -ENOMEM;
		runtime->data = newptr;
		/* We zero directly the memory from start of allocation. */
		memset(&runtime->data[old_alloc_len], 0, new_alloc_len - old_alloc_len);
		runtime->data_alloc_len = new_alloc_len;
	}
	runtime->data_len += padding;
	ret = runtime->data_len;
	runtime->data_len += len;
	return ret;
}

static ssize_t bytecode_push_data(struct bytecode_runtime *runtime,
		const void *p, size_t align, size_t len)
{
	ssize_t offset;

	offset = bytecode_reserve_data(runtime, align, len);
	if (offset < 0)
		return -ENOMEM;
	memcpy(&runtime->data[offset], p, len);
	return offset;
}

static int specialize_load_field(struct vstack_entry *stack_top,
		struct load_op *insn)
{
	int ret;

	switch (stack_top->load.type) {
	case LOAD_OBJECT:
		break;
	case LOAD_ROOT_CONTEXT:
	case LOAD_ROOT_APP_CONTEXT:
	case LOAD_ROOT_PAYLOAD:
	default:
		dbg_printf("Filter warning: cannot load root, missing field name.\n");
		ret = -EINVAL;
		goto end;
	}
	switch (stack_top->load.object_type) {
	case OBJECT_TYPE_S8:
		dbg_printf("op load field s8\n");
		stack_top->type = REG_S64;
		if (!stack_top->load.rev_bo)
			insn->op = FILTER_OP_LOAD_FIELD_S8;
		break;
	case OBJECT_TYPE_S16:
		dbg_printf("op load field s16\n");
		stack_top->type = REG_S64;
		if (!stack_top->load.rev_bo)
			insn->op = FILTER_OP_LOAD_FIELD_S16;
		break;
	case OBJECT_TYPE_S32:
		dbg_printf("op load field s32\n");
		stack_top->type = REG_S64;
		if (!stack_top->load.rev_bo)
			insn->op = FILTER_OP_LOAD_FIELD_S32;
		break;
	case OBJECT_TYPE_S64:
		dbg_printf("op load field s64\n");
		stack_top->type = REG_S64;
		if (!stack_top->load.rev_bo)
			insn->op = FILTER_OP_LOAD_FIELD_S64;
		break;
	case OBJECT_TYPE_U8:
		dbg_printf("op load field u8\n");
		stack_top->type = REG_S64;
		insn->op = FILTER_OP_LOAD_FIELD_U8;
		break;
	case OBJECT_TYPE_U16:
		dbg_printf("op load field u16\n");
		stack_top->type = REG_S64;
		if (!stack_top->load.rev_bo)
			insn->op = FILTER_OP_LOAD_FIELD_U16;
		break;
	case OBJECT_TYPE_U32:
		dbg_printf("op load field u32\n");
		stack_top->type = REG_S64;
		if (!stack_top->load.rev_bo)
			insn->op = FILTER_OP_LOAD_FIELD_U32;
		break;
	case OBJECT_TYPE_U64:
		dbg_printf("op load field u64\n");
		stack_top->type = REG_S64;
		if (!stack_top->load.rev_bo)
			insn->op = FILTER_OP_LOAD_FIELD_U64;
		break;
	case OBJECT_TYPE_DOUBLE:
		stack_top->type = REG_DOUBLE;
		insn->op = FILTER_OP_LOAD_FIELD_DOUBLE;
		break;
	case OBJECT_TYPE_STRING:
		dbg_printf("op load field string\n");
		stack_top->type = REG_STRING;
		insn->op = FILTER_OP_LOAD_FIELD_STRING;
		break;
	case OBJECT_TYPE_STRING_SEQUENCE:
		dbg_printf("op load field string sequence\n");
		stack_top->type = REG_STRING;
		insn->op = FILTER_OP_LOAD_FIELD_SEQUENCE;
		break;
	case OBJECT_TYPE_DYNAMIC:
		dbg_printf("op load field dynamic\n");
		stack_top->type = REG_UNKNOWN;
		/* Don't specialize load op. */
		break;
	case OBJECT_TYPE_SEQUENCE:
	case OBJECT_TYPE_ARRAY:
	case OBJECT_TYPE_STRUCT:
	case OBJECT_TYPE_VARIANT:
		ERR("Sequences, arrays, struct and variant cannot be loaded (nested types).");
		ret = -EINVAL;
		goto end;
	}
	return 0;

end:
	return ret;
}

static int specialize_get_index_object_type(enum object_type *otype,
		int signedness, uint32_t elem_len)
{
	switch (elem_len) {
	case 8:
		if (signedness)
			*otype = OBJECT_TYPE_S8;
		else
			*otype = OBJECT_TYPE_U8;
		break;
	case 16:
		if (signedness)
			*otype = OBJECT_TYPE_S16;
		else
			*otype = OBJECT_TYPE_U16;
		break;
	case 32:
		if (signedness)
			*otype = OBJECT_TYPE_S32;
		else
			*otype = OBJECT_TYPE_U32;
		break;
	case 64:
		if (signedness)
			*otype = OBJECT_TYPE_S64;
		else
			*otype = OBJECT_TYPE_U64;
		break;
	default:
		return -EINVAL;
	}
	return 0;
}

static int specialize_get_index(struct bytecode_runtime *runtime,
		struct load_op *insn, uint64_t index,
		struct vstack_entry *stack_top,
		int idx_len)
{
	int ret;
	struct filter_get_index_data gid;
	ssize_t data_offset;

	memset(&gid, 0, sizeof(gid));
	switch (stack_top->load.type) {
	case LOAD_OBJECT:
		switch (stack_top->load.object_type) {
		case OBJECT_TYPE_ARRAY:
		{
			const struct lttng_integer_type *integer_type;
			const struct lttng_event_field *field;
			uint32_t elem_len, num_elems;
			int signedness;

			field = stack_top->load.field;
			switch (field->type.atype) {
			case atype_array:
				integer_type = &field->type.u.legacy.array.elem_type.u.basic.integer;
				num_elems = field->type.u.legacy.array.length;
				break;
			case atype_array_nestable:
				if (field->type.u.array_nestable.elem_type->atype != atype_integer) {
					ret = -EINVAL;
					goto end;
				}
				integer_type = &field->type.u.array_nestable.elem_type->u.integer;
				num_elems = field->type.u.array_nestable.length;
				break;
			default:
				ret = -EINVAL;
				goto end;
			}
			elem_len = integer_type->size;
			signedness = integer_type->signedness;
			if (index >= num_elems) {
				ret = -EINVAL;
				goto end;
			}
			ret = specialize_get_index_object_type(&stack_top->load.object_type,
					signedness, elem_len);
			if (ret)
				goto end;
			gid.offset = index * (elem_len / CHAR_BIT);
			gid.array_len = num_elems * (elem_len / CHAR_BIT);
			gid.elem.type = stack_top->load.object_type;
			gid.elem.len = elem_len;
			if (integer_type->reverse_byte_order)
				gid.elem.rev_bo = true;
			stack_top->load.rev_bo = gid.elem.rev_bo;
			break;
		}
		case OBJECT_TYPE_SEQUENCE:
		{
			const struct lttng_integer_type *integer_type;
			const struct lttng_event_field *field;
			uint32_t elem_len;
			int signedness;

			field = stack_top->load.field;
			switch (field->type.atype) {
			case atype_sequence:
				integer_type = &field->type.u.legacy.sequence.elem_type.u.basic.integer;
				break;
			case atype_sequence_nestable:
				if (field->type.u.sequence_nestable.elem_type->atype != atype_integer) {
					ret = -EINVAL;
					goto end;
				}
				integer_type = &field->type.u.sequence_nestable.elem_type->u.integer;
				break;
			default:
				ret = -EINVAL;
				goto end;
			}
			elem_len = integer_type->size;
			signedness = integer_type->signedness;
			ret = specialize_get_index_object_type(&stack_top->load.object_type,
					signedness, elem_len);
			if (ret)
				goto end;
			gid.offset = index * (elem_len / CHAR_BIT);
			gid.elem.type = stack_top->load.object_type;
			gid.elem.len = elem_len;
			if (integer_type->reverse_byte_order)
				gid.elem.rev_bo = true;
			stack_top->load.rev_bo = gid.elem.rev_bo;
			break;
		}
		case OBJECT_TYPE_STRUCT:
			/* Only generated by the specialize phase. */
		case OBJECT_TYPE_VARIANT:	/* Fall-through */
		default:
			ERR("Unexpected get index type %d",
				(int) stack_top->load.object_type);
			ret = -EINVAL;
			goto end;
		}
		break;
	case LOAD_ROOT_CONTEXT:
	case LOAD_ROOT_APP_CONTEXT:
	case LOAD_ROOT_PAYLOAD:
		ERR("Index lookup for root field not implemented yet.");
		ret = -EINVAL;
		goto end;
	}
	data_offset = bytecode_push_data(runtime, &gid,
		__alignof__(gid), sizeof(gid));
	if (data_offset < 0) {
		ret = -EINVAL;
		goto end;
	}
	switch (idx_len) {
	case 2:
		((struct get_index_u16 *) insn->data)->index = data_offset;
		break;
	case 8:
		((struct get_index_u64 *) insn->data)->index = data_offset;
		break;
	default:
		ret = -EINVAL;
		goto end;
	}

	return 0;

end:
	return ret;
}

static int specialize_context_lookup_name(struct lttng_ctx *ctx,
		struct bytecode_runtime *bytecode,
		struct load_op *insn)
{
	uint16_t offset;
	const char *name;

	offset = ((struct get_symbol *) insn->data)->offset;
	name = bytecode->p.bc->bc.data + bytecode->p.bc->bc.reloc_offset + offset;
	return lttng_get_context_index(ctx, name);
}

static int specialize_load_object(const struct lttng_event_field *field,
		struct vstack_load *load, bool is_context)
{
	load->type = LOAD_OBJECT;
	/*
	 * LTTng-UST layout all integer fields as s64 on the stack for the filter.
	 */
	switch (field->type.atype) {
	case atype_integer:
		if (field->type.u.integer.signedness)
			load->object_type = OBJECT_TYPE_S64;
		else
			load->object_type = OBJECT_TYPE_U64;
		load->rev_bo = false;
		break;
	case atype_enum:
	case atype_enum_nestable:
	{
		const struct lttng_integer_type *itype;

		if (field->type.atype == atype_enum) {
			itype = &field->type.u.legacy.basic.enumeration.container_type;
		} else {
			itype = &field->type.u.enum_nestable.container_type->u.integer;
		}
		if (itype->signedness)
			load->object_type = OBJECT_TYPE_S64;
		else
			load->object_type = OBJECT_TYPE_U64;
		load->rev_bo = false;
		break;
	}
	case atype_array:
		if (field->type.u.legacy.array.elem_type.atype != atype_integer) {
			ERR("Array nesting only supports integer types.");
			return -EINVAL;
		}
		if (is_context) {
			load->object_type = OBJECT_TYPE_STRING;
		} else {
			if (field->type.u.legacy.array.elem_type.u.basic.integer.encoding == lttng_encode_none) {
				load->object_type = OBJECT_TYPE_ARRAY;
				load->field = field;
			} else {
				load->object_type = OBJECT_TYPE_STRING_SEQUENCE;
			}
		}
		break;
	case atype_array_nestable:
		if (field->type.u.array_nestable.elem_type->atype != atype_integer) {
			ERR("Array nesting only supports integer types.");
			return -EINVAL;
		}
		if (is_context) {
			load->object_type = OBJECT_TYPE_STRING;
		} else {
			if (field->type.u.array_nestable.elem_type->u.integer.encoding == lttng_encode_none) {
				load->object_type = OBJECT_TYPE_ARRAY;
				load->field = field;
			} else {
				load->object_type = OBJECT_TYPE_STRING_SEQUENCE;
			}
		}
		break;
	case atype_sequence:
		if (field->type.u.legacy.sequence.elem_type.atype != atype_integer) {
			ERR("Sequence nesting only supports integer types.");
			return -EINVAL;
		}
		if (is_context) {
			load->object_type = OBJECT_TYPE_STRING;
		} else {
			if (field->type.u.legacy.sequence.elem_type.u.basic.integer.encoding == lttng_encode_none) {
				load->object_type = OBJECT_TYPE_SEQUENCE;
				load->field = field;
			} else {
				load->object_type = OBJECT_TYPE_STRING_SEQUENCE;
			}
		}
		break;
	case atype_sequence_nestable:
		if (field->type.u.sequence_nestable.elem_type->atype != atype_integer) {
			ERR("Sequence nesting only supports integer types.");
			return -EINVAL;
		}
		if (is_context) {
			load->object_type = OBJECT_TYPE_STRING;
		} else {
			if (field->type.u.sequence_nestable.elem_type->u.integer.encoding == lttng_encode_none) {
				load->object_type = OBJECT_TYPE_SEQUENCE;
				load->field = field;
			} else {
				load->object_type = OBJECT_TYPE_STRING_SEQUENCE;
			}
		}
		break;

	case atype_string:
		load->object_type = OBJECT_TYPE_STRING;
		break;
	case atype_float:
		load->object_type = OBJECT_TYPE_DOUBLE;
		break;
	case atype_dynamic:
		load->object_type = OBJECT_TYPE_DYNAMIC;
		break;
	case atype_struct:
		ERR("Structure type cannot be loaded.");
		return -EINVAL;
	default:
		ERR("Unknown type: %d", (int) field->type.atype);
		return -EINVAL;
	}
	return 0;
}

static int specialize_context_lookup(struct lttng_session *session,
		struct bytecode_runtime *runtime,
		struct load_op *insn,
		struct vstack_load *load)
{
	int idx, ret;
	struct lttng_ctx_field *ctx_field;
	struct lttng_event_field *field;
	struct filter_get_index_data gid;
	ssize_t data_offset;

	idx = specialize_context_lookup_name(session->ctx, runtime, insn);
	if (idx < 0) {
		return -ENOENT;
	}
	ctx_field = &session->ctx->fields[idx];
	field = &ctx_field->event_field;
	ret = specialize_load_object(field, load, true);
	if (ret)
		return ret;
	/* Specialize each get_symbol into a get_index. */
	insn->op = FILTER_OP_GET_INDEX_U16;
	memset(&gid, 0, sizeof(gid));
	gid.ctx_index = idx;
	gid.elem.type = load->object_type;
	data_offset = bytecode_push_data(runtime, &gid,
		__alignof__(gid), sizeof(gid));
	if (data_offset < 0) {
		return -EINVAL;
	}
	((struct get_index_u16 *) insn->data)->index = data_offset;
	return 0;
}

static int specialize_app_context_lookup(struct lttng_session *session,
		struct bytecode_runtime *runtime,
		struct load_op *insn,
		struct vstack_load *load)
{
	uint16_t offset;
	const char *orig_name;
	char *name = NULL;
	int idx, ret;
	struct lttng_ctx_field *ctx_field;
	struct lttng_event_field *field;
	struct filter_get_index_data gid;
	ssize_t data_offset;

	offset = ((struct get_symbol *) insn->data)->offset;
	orig_name = runtime->p.bc->bc.data + runtime->p.bc->bc.reloc_offset + offset;
	name = zmalloc(strlen(orig_name) + strlen("$app.") + 1);
	if (!name) {
		ret = -ENOMEM;
		goto end;
	}
	strcpy(name, "$app.");
	strcat(name, orig_name);
	idx = lttng_get_context_index(session->ctx, name);
	if (idx < 0) {
		assert(lttng_context_is_app(name));
		ret = lttng_ust_add_app_context_to_ctx_rcu(name,
				&session->ctx);
		if (ret)
			return ret;
		idx = lttng_get_context_index(session->ctx,
			name);
		if (idx < 0)
			return -ENOENT;
	}
	ctx_field = &session->ctx->fields[idx];
	field = &ctx_field->event_field;
	ret = specialize_load_object(field, load, true);
	if (ret)
		goto end;
	/* Specialize each get_symbol into a get_index. */
	insn->op = FILTER_OP_GET_INDEX_U16;
	memset(&gid, 0, sizeof(gid));
	gid.ctx_index = idx;
	gid.elem.type = load->object_type;
	data_offset = bytecode_push_data(runtime, &gid,
		__alignof__(gid), sizeof(gid));
	if (data_offset < 0) {
		ret = -EINVAL;
		goto end;
	}
	((struct get_index_u16 *) insn->data)->index = data_offset;
	ret = 0;
end:
	free(name);
	return ret;
}

static int specialize_event_payload_lookup(struct lttng_event *event,
		struct bytecode_runtime *runtime,
		struct load_op *insn,
		struct vstack_load *load)
{
	const char *name;
	uint16_t offset;
	const struct lttng_event_desc *desc = event->desc;
	unsigned int i, nr_fields;
	bool found = false;
	uint32_t field_offset = 0;
	const struct lttng_event_field *field;
	int ret;
	struct filter_get_index_data gid;
	ssize_t data_offset;

	nr_fields = desc->nr_fields;
	offset = ((struct get_symbol *) insn->data)->offset;
	name = runtime->p.bc->bc.data + runtime->p.bc->bc.reloc_offset + offset;
	for (i = 0; i < nr_fields; i++) {
		field = &desc->fields[i];
		if (field->u.ext.nofilter) {
			continue;
		}
		if (!strcmp(field->name, name)) {
			found = true;
			break;
		}
		/* compute field offset on stack */
		switch (field->type.atype) {
		case atype_integer:
		case atype_enum:
		case atype_enum_nestable:
			field_offset += sizeof(int64_t);
			break;
		case atype_array:
		case atype_array_nestable:
		case atype_sequence:
		case atype_sequence_nestable:
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
			ret = -EINVAL;
			goto end;
		}
	}
	if (!found) {
		ret = -EINVAL;
		goto end;
	}

	ret = specialize_load_object(field, load, false);
	if (ret)
		goto end;

	/* Specialize each get_symbol into a get_index. */
	insn->op = FILTER_OP_GET_INDEX_U16;
	memset(&gid, 0, sizeof(gid));
	gid.offset = field_offset;
	gid.elem.type = load->object_type;
	data_offset = bytecode_push_data(runtime, &gid,
		__alignof__(gid), sizeof(gid));
	if (data_offset < 0) {
		ret = -EINVAL;
		goto end;
	}
	((struct get_index_u16 *) insn->data)->index = data_offset;
	ret = 0;
end:
	return ret;
}

int lttng_filter_specialize_bytecode(struct lttng_event *event,
		struct bytecode_runtime *bytecode)
{
	void *pc, *next_pc, *start_pc;
	int ret = -EINVAL;
	struct vstack _stack;
	struct vstack *stack = &_stack;
	struct lttng_session *session = bytecode->p.session;

	vstack_init(stack);

	start_pc = &bytecode->code[0];
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
			if (vstack_ax(stack)->type == REG_S64)
				*(filter_opcode_t *) pc = FILTER_OP_RETURN_S64;
			ret = 0;
			goto end;

		case FILTER_OP_RETURN_S64:
			if (vstack_ax(stack)->type != REG_S64) {
				ERR("Unexpected register type\n");
				ret = -EINVAL;
				goto end;
			}
			ret = 0;
			goto end;

		/* binary */
		case FILTER_OP_MUL:
		case FILTER_OP_DIV:
		case FILTER_OP_MOD:
		case FILTER_OP_PLUS:
		case FILTER_OP_MINUS:
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
		case FILTER_OP_BIT_RSHIFT:
		case FILTER_OP_BIT_LSHIFT:
		case FILTER_OP_BIT_AND:
		case FILTER_OP_BIT_OR:
		case FILTER_OP_BIT_XOR:
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

		case FILTER_OP_UNARY_BIT_NOT:
		{
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

		/*
		 * Instructions for recursive traversal through composed types.
		 */
		case FILTER_OP_GET_CONTEXT_ROOT:
		{
			if (vstack_push(stack)) {
				ret = -EINVAL;
				goto end;
			}
			vstack_ax(stack)->type = REG_PTR;
			vstack_ax(stack)->load.type = LOAD_ROOT_CONTEXT;
			next_pc += sizeof(struct load_op);
			break;
		}
		case FILTER_OP_GET_APP_CONTEXT_ROOT:
		{
			if (vstack_push(stack)) {
				ret = -EINVAL;
				goto end;
			}
			vstack_ax(stack)->type = REG_PTR;
			vstack_ax(stack)->load.type = LOAD_ROOT_APP_CONTEXT;
			next_pc += sizeof(struct load_op);
			break;
		}
		case FILTER_OP_GET_PAYLOAD_ROOT:
		{
			if (vstack_push(stack)) {
				ret = -EINVAL;
				goto end;
			}
			vstack_ax(stack)->type = REG_PTR;
			vstack_ax(stack)->load.type = LOAD_ROOT_PAYLOAD;
			next_pc += sizeof(struct load_op);
			break;
		}

		case FILTER_OP_LOAD_FIELD:
		{
			struct load_op *insn = (struct load_op *) pc;

			assert(vstack_ax(stack)->type == REG_PTR);
			/* Pop 1, push 1 */
			ret = specialize_load_field(vstack_ax(stack), insn);
			if (ret)
				goto end;

			next_pc += sizeof(struct load_op);
			break;
		}

		case FILTER_OP_LOAD_FIELD_S8:
		case FILTER_OP_LOAD_FIELD_S16:
		case FILTER_OP_LOAD_FIELD_S32:
		case FILTER_OP_LOAD_FIELD_S64:
		case FILTER_OP_LOAD_FIELD_U8:
		case FILTER_OP_LOAD_FIELD_U16:
		case FILTER_OP_LOAD_FIELD_U32:
		case FILTER_OP_LOAD_FIELD_U64:
		{
			/* Pop 1, push 1 */
			vstack_ax(stack)->type = REG_S64;
			next_pc += sizeof(struct load_op);
			break;
		}

		case FILTER_OP_LOAD_FIELD_STRING:
		case FILTER_OP_LOAD_FIELD_SEQUENCE:
		{
			/* Pop 1, push 1 */
			vstack_ax(stack)->type = REG_STRING;
			next_pc += sizeof(struct load_op);
			break;
		}

		case FILTER_OP_LOAD_FIELD_DOUBLE:
		{
			/* Pop 1, push 1 */
			vstack_ax(stack)->type = REG_DOUBLE;
			next_pc += sizeof(struct load_op);
			break;
		}

		case FILTER_OP_GET_SYMBOL:
		{
			struct load_op *insn = (struct load_op *) pc;

			dbg_printf("op get symbol\n");
			switch (vstack_ax(stack)->load.type) {
			case LOAD_OBJECT:
				ERR("Nested fields not implemented yet.");
				ret = -EINVAL;
				goto end;
			case LOAD_ROOT_CONTEXT:
				/* Lookup context field. */
				ret = specialize_context_lookup(session,
					bytecode, insn,
					&vstack_ax(stack)->load);
				if (ret)
					goto end;
				break;
			case LOAD_ROOT_APP_CONTEXT:
				/* Lookup app context field. */
				ret = specialize_app_context_lookup(session,
					bytecode, insn,
					&vstack_ax(stack)->load);
				if (ret)
					goto end;
				break;
			case LOAD_ROOT_PAYLOAD:
				/* Lookup event payload field. */
				ret = specialize_event_payload_lookup(event,
					bytecode, insn,
					&vstack_ax(stack)->load);
				if (ret)
					goto end;
				break;
			}
			next_pc += sizeof(struct load_op) + sizeof(struct get_symbol);
			break;
		}

		case FILTER_OP_GET_SYMBOL_FIELD:
		{
			/* Always generated by specialize phase. */
			ret = -EINVAL;
			goto end;
		}

		case FILTER_OP_GET_INDEX_U16:
		{
			struct load_op *insn = (struct load_op *) pc;
			struct get_index_u16 *index = (struct get_index_u16 *) insn->data;

			dbg_printf("op get index u16\n");
			/* Pop 1, push 1 */
			ret = specialize_get_index(bytecode, insn, index->index,
					vstack_ax(stack), sizeof(*index));
			if (ret)
				goto end;
			next_pc += sizeof(struct load_op) + sizeof(struct get_index_u16);
			break;
		}

		case FILTER_OP_GET_INDEX_U64:
		{
			struct load_op *insn = (struct load_op *) pc;
			struct get_index_u64 *index = (struct get_index_u64 *) insn->data;

			dbg_printf("op get index u64\n");
			/* Pop 1, push 1 */
			ret = specialize_get_index(bytecode, insn, index->index,
					vstack_ax(stack), sizeof(*index));
			if (ret)
				goto end;
			next_pc += sizeof(struct load_op) + sizeof(struct get_index_u64);
			break;
		}

		}
	}
end:
	return ret;
}
