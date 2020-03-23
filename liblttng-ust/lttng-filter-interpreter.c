/*
 * lttng-filter-interpreter.c
 *
 * LTTng UST filter interpreter.
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
#include <urcu-pointer.h>
#include <lttng/ust-endian.h>
#include "lttng-filter.h"
#include "string-utils.h"

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

/*
 * Returns SIZE_MAX if the string is null-terminated, or the number of
 * characters if not.
 */
static
size_t get_str_or_seq_len(const struct estack_entry *entry)
{
	return entry->u.s.seq_len;
}

static
int stack_star_glob_match(struct estack *stack, int top, const char *cmp_type)
{
	const char *pattern;
	const char *candidate;
	size_t pattern_len;
	size_t candidate_len;

	/* Find out which side is the pattern vs. the candidate. */
	if (estack_ax(stack, top)->u.s.literal_type == ESTACK_STRING_LITERAL_TYPE_STAR_GLOB) {
		pattern = estack_ax(stack, top)->u.s.str;
		pattern_len = get_str_or_seq_len(estack_ax(stack, top));
		candidate = estack_bx(stack, top)->u.s.str;
		candidate_len = get_str_or_seq_len(estack_bx(stack, top));
	} else {
		pattern = estack_bx(stack, top)->u.s.str;
		pattern_len = get_str_or_seq_len(estack_bx(stack, top));
		candidate = estack_ax(stack, top)->u.s.str;
		candidate_len = get_str_or_seq_len(estack_ax(stack, top));
	}

	/* Perform the match. Returns 0 when the result is true. */
	return !strutils_star_glob_match(pattern, pattern_len, candidate,
		candidate_len);
}

static
int stack_strcmp(struct estack *stack, int top, const char *cmp_type)
{
	const char *p = estack_bx(stack, top)->u.s.str, *q = estack_ax(stack, top)->u.s.str;
	int ret;
	int diff;

	for (;;) {
		int escaped_r0 = 0;

		if (unlikely(p - estack_bx(stack, top)->u.s.str >= estack_bx(stack, top)->u.s.seq_len || *p == '\0')) {
			if (q - estack_ax(stack, top)->u.s.str >= estack_ax(stack, top)->u.s.seq_len || *q == '\0') {
				return 0;
			} else {
				if (estack_ax(stack, top)->u.s.literal_type ==
						ESTACK_STRING_LITERAL_TYPE_PLAIN) {
					ret = parse_char(&q);
					if (ret == -1)
						return 0;
				}
				return -1;
			}
		}
		if (unlikely(q - estack_ax(stack, top)->u.s.str >= estack_ax(stack, top)->u.s.seq_len || *q == '\0')) {
			if (estack_bx(stack, top)->u.s.literal_type ==
					ESTACK_STRING_LITERAL_TYPE_PLAIN) {
				ret = parse_char(&p);
				if (ret == -1)
					return 0;
			}
			return 1;
		}
		if (estack_bx(stack, top)->u.s.literal_type ==
				ESTACK_STRING_LITERAL_TYPE_PLAIN) {
			ret = parse_char(&p);
			if (ret == -1) {
				return 0;
			} else if (ret == -2) {
				escaped_r0 = 1;
			}
			/* else compare both char */
		}
		if (estack_ax(stack, top)->u.s.literal_type ==
				ESTACK_STRING_LITERAL_TYPE_PLAIN) {
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
	return LTTNG_FILTER_DISCARD;
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

#define OP(name)	jump_target_##name: __attribute__((unused));	\
			case name

#define PO		break

#define END_OP		}						\
	}

#define JUMP_TO(name)							\
			goto jump_target_##name

#else

/*
 * Dispatch-table based interpreter.
 */

#define START_OP							\
	start_pc = &bytecode->code[0];					\
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

#define JUMP_TO(name)							\
		goto LABEL_##name

#endif

#define IS_INTEGER_REGISTER(reg_type) \
		(reg_type == REG_U64 || reg_type == REG_S64)

static int context_get_index(struct lttng_ctx *ctx,
		struct load_ptr *ptr,
		uint32_t idx)
{

	struct lttng_ctx_field *ctx_field;
	struct lttng_event_field *field;
	struct lttng_ctx_value v;

	ctx_field = &ctx->fields[idx];
	field = &ctx_field->event_field;
	ptr->type = LOAD_OBJECT;
	/* field is only used for types nested within variants. */
	ptr->field = NULL;

	switch (field->type.atype) {
	case atype_integer:
		ctx_field->get_value(ctx_field, &v);
		if (field->type.u.integer.signedness) {
			ptr->object_type = OBJECT_TYPE_S64;
			ptr->u.s64 = v.u.s64;
			ptr->ptr = &ptr->u.s64;
		} else {
			ptr->object_type = OBJECT_TYPE_U64;
			ptr->u.u64 = v.u.s64;	/* Cast. */
			ptr->ptr = &ptr->u.u64;
		}
		break;
	case atype_enum:	/* Fall-through */
	case atype_enum_nestable:
	{
		const struct lttng_integer_type *itype;

		if (field->type.atype == atype_enum) {
			itype = &field->type.u.legacy.basic.enumeration.container_type;
		} else {
			itype = &field->type.u.enum_nestable.container_type->u.integer;
		}
		ctx_field->get_value(ctx_field, &v);
		if (itype->signedness) {
			ptr->object_type = OBJECT_TYPE_S64;
			ptr->u.s64 = v.u.s64;
			ptr->ptr = &ptr->u.s64;
		} else {
			ptr->object_type = OBJECT_TYPE_U64;
			ptr->u.u64 = v.u.s64;	/* Cast. */
			ptr->ptr = &ptr->u.u64;
		}
		break;
	}
	case atype_array:
		if (field->type.u.legacy.array.elem_type.atype != atype_integer) {
			ERR("Array nesting only supports integer types.");
			return -EINVAL;
		}
		if (field->type.u.legacy.array.elem_type.u.basic.integer.encoding == lttng_encode_none) {
			ERR("Only string arrays are supported for contexts.");
			return -EINVAL;
		}
		ptr->object_type = OBJECT_TYPE_STRING;
		ctx_field->get_value(ctx_field, &v);
		ptr->ptr = v.u.str;
		break;
	case atype_array_nestable:
		if (field->type.u.array_nestable.elem_type->atype != atype_integer) {
			ERR("Array nesting only supports integer types.");
			return -EINVAL;
		}
		if (field->type.u.array_nestable.elem_type->u.integer.encoding == lttng_encode_none) {
			ERR("Only string arrays are supported for contexts.");
			return -EINVAL;
		}
		ptr->object_type = OBJECT_TYPE_STRING;
		ctx_field->get_value(ctx_field, &v);
		ptr->ptr = v.u.str;
		break;
	case atype_sequence:
		if (field->type.u.legacy.sequence.elem_type.atype != atype_integer) {
			ERR("Sequence nesting only supports integer types.");
			return -EINVAL;
		}
		if (field->type.u.legacy.sequence.elem_type.u.basic.integer.encoding == lttng_encode_none) {
			ERR("Only string sequences are supported for contexts.");
			return -EINVAL;
		}
		ptr->object_type = OBJECT_TYPE_STRING;
		ctx_field->get_value(ctx_field, &v);
		ptr->ptr = v.u.str;
		break;
	case atype_sequence_nestable:
		if (field->type.u.sequence_nestable.elem_type->atype != atype_integer) {
			ERR("Sequence nesting only supports integer types.");
			return -EINVAL;
		}
		if (field->type.u.sequence_nestable.elem_type->u.integer.encoding == lttng_encode_none) {
			ERR("Only string sequences are supported for contexts.");
			return -EINVAL;
		}
		ptr->object_type = OBJECT_TYPE_STRING;
		ctx_field->get_value(ctx_field, &v);
		ptr->ptr = v.u.str;
		break;
	case atype_string:
		ptr->object_type = OBJECT_TYPE_STRING;
		ctx_field->get_value(ctx_field, &v);
		ptr->ptr = v.u.str;
		break;
	case atype_float:
		ptr->object_type = OBJECT_TYPE_DOUBLE;
		ctx_field->get_value(ctx_field, &v);
		ptr->u.d = v.u.d;
		ptr->ptr = &ptr->u.d;
		break;
	case atype_dynamic:
		ctx_field->get_value(ctx_field, &v);
		switch (v.sel) {
		case LTTNG_UST_DYNAMIC_TYPE_NONE:
			return -EINVAL;
		case LTTNG_UST_DYNAMIC_TYPE_S64:
			ptr->object_type = OBJECT_TYPE_S64;
			ptr->u.s64 = v.u.s64;
			ptr->ptr = &ptr->u.s64;
			dbg_printf("context get index dynamic s64 %" PRIi64 "\n", ptr->u.s64);
			break;
		case LTTNG_UST_DYNAMIC_TYPE_DOUBLE:
			ptr->object_type = OBJECT_TYPE_DOUBLE;
			ptr->u.d = v.u.d;
			ptr->ptr = &ptr->u.d;
			dbg_printf("context get index dynamic double %g\n", ptr->u.d);
			break;
		case LTTNG_UST_DYNAMIC_TYPE_STRING:
			ptr->object_type = OBJECT_TYPE_STRING;
			ptr->ptr = v.u.str;
			dbg_printf("context get index dynamic string %s\n", (const char *) ptr->ptr);
			break;
		default:
			dbg_printf("Filter warning: unknown dynamic type (%d).\n", (int) v.sel);
			return -EINVAL;
		}
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

static int dynamic_get_index(struct lttng_ctx *ctx,
		struct bytecode_runtime *runtime,
		uint64_t index, struct estack_entry *stack_top)
{
	int ret;
	const struct filter_get_index_data *gid;

	/*
	 * Types nested within variants need to perform dynamic lookup
	 * based on the field descriptions. LTTng-UST does not implement
	 * variants for now.
	 */
	if (stack_top->u.ptr.field)
		return -EINVAL;
	gid = (const struct filter_get_index_data *) &runtime->data[index];
	switch (stack_top->u.ptr.type) {
	case LOAD_OBJECT:
		switch (stack_top->u.ptr.object_type) {
		case OBJECT_TYPE_ARRAY:
		{
			const char *ptr;

			assert(gid->offset < gid->array_len);
			/* Skip count (unsigned long) */
			ptr = *(const char **) (stack_top->u.ptr.ptr + sizeof(unsigned long));
			ptr = ptr + gid->offset;
			stack_top->u.ptr.ptr = ptr;
			stack_top->u.ptr.object_type = gid->elem.type;
			stack_top->u.ptr.rev_bo = gid->elem.rev_bo;
			/* field is only used for types nested within variants. */
			stack_top->u.ptr.field = NULL;
			break;
		}
		case OBJECT_TYPE_SEQUENCE:
		{
			const char *ptr;
			size_t ptr_seq_len;

			ptr = *(const char **) (stack_top->u.ptr.ptr + sizeof(unsigned long));
			ptr_seq_len = *(unsigned long *) stack_top->u.ptr.ptr;
			if (gid->offset >= gid->elem.len * ptr_seq_len) {
				ret = -EINVAL;
				goto end;
			}
			ptr = ptr + gid->offset;
			stack_top->u.ptr.ptr = ptr;
			stack_top->u.ptr.object_type = gid->elem.type;
			stack_top->u.ptr.rev_bo = gid->elem.rev_bo;
			/* field is only used for types nested within variants. */
			stack_top->u.ptr.field = NULL;
			break;
		}
		case OBJECT_TYPE_STRUCT:
			ERR("Nested structures are not supported yet.");
			ret = -EINVAL;
			goto end;
		case OBJECT_TYPE_VARIANT:
		default:
			ERR("Unexpected get index type %d",
				(int) stack_top->u.ptr.object_type);
			ret = -EINVAL;
			goto end;
		}
		break;
	case LOAD_ROOT_CONTEXT:
	case LOAD_ROOT_APP_CONTEXT:	/* Fall-through */
	{
		ret = context_get_index(ctx,
				&stack_top->u.ptr,
				gid->ctx_index);
		if (ret) {
			goto end;
		}
		break;
	}
	case LOAD_ROOT_PAYLOAD:
		stack_top->u.ptr.ptr += gid->offset;
		if (gid->elem.type == OBJECT_TYPE_STRING)
			stack_top->u.ptr.ptr = *(const char * const *) stack_top->u.ptr.ptr;
		stack_top->u.ptr.object_type = gid->elem.type;
		stack_top->u.ptr.type = LOAD_OBJECT;
		/* field is only used for types nested within variants. */
		stack_top->u.ptr.field = NULL;
		break;
	}
	return 0;

end:
	return ret;
}

static int dynamic_load_field(struct estack_entry *stack_top)
{
	int ret;

	switch (stack_top->u.ptr.type) {
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
	switch (stack_top->u.ptr.object_type) {
	case OBJECT_TYPE_S8:
		dbg_printf("op load field s8\n");
		stack_top->u.v = *(int8_t *) stack_top->u.ptr.ptr;
		stack_top->type = REG_S64;
		break;
	case OBJECT_TYPE_S16:
	{
		int16_t tmp;

		dbg_printf("op load field s16\n");
		tmp = *(int16_t *) stack_top->u.ptr.ptr;
		if (stack_top->u.ptr.rev_bo)
			tmp = bswap_16(tmp);
		stack_top->u.v = tmp;
		stack_top->type = REG_S64;
		break;
	}
	case OBJECT_TYPE_S32:
	{
		int32_t tmp;

		dbg_printf("op load field s32\n");
		tmp = *(int32_t *) stack_top->u.ptr.ptr;
		if (stack_top->u.ptr.rev_bo)
			tmp = bswap_32(tmp);
		stack_top->u.v = tmp;
		stack_top->type = REG_S64;
		break;
	}
	case OBJECT_TYPE_S64:
	{
		int64_t tmp;

		dbg_printf("op load field s64\n");
		tmp = *(int64_t *) stack_top->u.ptr.ptr;
		if (stack_top->u.ptr.rev_bo)
			tmp = bswap_64(tmp);
		stack_top->u.v = tmp;
		stack_top->type = REG_S64;
		break;
	}
	case OBJECT_TYPE_U8:
		dbg_printf("op load field u8\n");
		stack_top->u.v = *(uint8_t *) stack_top->u.ptr.ptr;
		stack_top->type = REG_U64;
		break;
	case OBJECT_TYPE_U16:
	{
		uint16_t tmp;

		dbg_printf("op load field u16\n");
		tmp = *(uint16_t *) stack_top->u.ptr.ptr;
		if (stack_top->u.ptr.rev_bo)
			tmp = bswap_16(tmp);
		stack_top->u.v = tmp;
		stack_top->type = REG_U64;
		break;
	}
	case OBJECT_TYPE_U32:
	{
		uint32_t tmp;

		dbg_printf("op load field u32\n");
		tmp = *(uint32_t *) stack_top->u.ptr.ptr;
		if (stack_top->u.ptr.rev_bo)
			tmp = bswap_32(tmp);
		stack_top->u.v = tmp;
		stack_top->type = REG_U64;
		break;
	}
	case OBJECT_TYPE_U64:
	{
		uint64_t tmp;

		dbg_printf("op load field u64\n");
		tmp = *(uint64_t *) stack_top->u.ptr.ptr;
		if (stack_top->u.ptr.rev_bo)
			tmp = bswap_64(tmp);
		stack_top->u.v = tmp;
		stack_top->type = REG_U64;
		break;
	}
	case OBJECT_TYPE_DOUBLE:
		memcpy(&stack_top->u.d,
			stack_top->u.ptr.ptr,
			sizeof(struct literal_double));
		stack_top->type = REG_DOUBLE;
		break;
	case OBJECT_TYPE_STRING:
	{
		const char *str;

		dbg_printf("op load field string\n");
		str = (const char *) stack_top->u.ptr.ptr;
		stack_top->u.s.str = str;
		if (unlikely(!stack_top->u.s.str)) {
			dbg_printf("Filter warning: loading a NULL string.\n");
			ret = -EINVAL;
			goto end;
		}
		stack_top->u.s.seq_len = SIZE_MAX;
		stack_top->u.s.literal_type =
			ESTACK_STRING_LITERAL_TYPE_NONE;
		stack_top->type = REG_STRING;
		break;
	}
	case OBJECT_TYPE_STRING_SEQUENCE:
	{
		const char *ptr;

		dbg_printf("op load field string sequence\n");
		ptr = stack_top->u.ptr.ptr;
		stack_top->u.s.seq_len = *(unsigned long *) ptr;
		stack_top->u.s.str = *(const char **) (ptr + sizeof(unsigned long));
		stack_top->type = REG_STRING;
		if (unlikely(!stack_top->u.s.str)) {
			dbg_printf("Filter warning: loading a NULL sequence.\n");
			ret = -EINVAL;
			goto end;
		}
		stack_top->u.s.literal_type =
			ESTACK_STRING_LITERAL_TYPE_NONE;
		break;
	}
	case OBJECT_TYPE_DYNAMIC:
		/*
		 * Dynamic types in context are looked up
		 * by context get index.
		 */
		ret = -EINVAL;
		goto end;
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

/*
 * Return 0 (discard), or raise the 0x1 flag (log event).
 * Currently, other flags are kept for future extensions and have no
 * effect.
 */
uint64_t lttng_filter_interpret_bytecode(void *filter_data,
		const char *filter_stack_data)
{
	struct bytecode_runtime *bytecode = filter_data;
	struct lttng_ctx *ctx = rcu_dereference(*bytecode->p.pctx);
	void *pc, *next_pc, *start_pc;
	int ret = -EINVAL;
	uint64_t retval = 0;
	struct estack _stack;
	struct estack *stack = &_stack;
	register int64_t ax = 0, bx = 0;
	register enum entry_type ax_t = REG_UNKNOWN, bx_t = REG_UNKNOWN;
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
		[ FILTER_OP_BIT_RSHIFT ] = &&LABEL_FILTER_OP_BIT_RSHIFT,
		[ FILTER_OP_BIT_LSHIFT ] = &&LABEL_FILTER_OP_BIT_LSHIFT,
		[ FILTER_OP_BIT_AND ] = &&LABEL_FILTER_OP_BIT_AND,
		[ FILTER_OP_BIT_OR ] = &&LABEL_FILTER_OP_BIT_OR,
		[ FILTER_OP_BIT_XOR ] = &&LABEL_FILTER_OP_BIT_XOR,

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

		/* globbing pattern binary comparator */
		[ FILTER_OP_EQ_STAR_GLOB_STRING ] = &&LABEL_FILTER_OP_EQ_STAR_GLOB_STRING,
		[ FILTER_OP_NE_STAR_GLOB_STRING ] = &&LABEL_FILTER_OP_NE_STAR_GLOB_STRING,

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
		[ FILTER_OP_LOAD_STAR_GLOB_STRING ] = &&LABEL_FILTER_OP_LOAD_STAR_GLOB_STRING,
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

		/* Instructions for recursive traversal through composed types. */
		[ FILTER_OP_GET_CONTEXT_ROOT ] = &&LABEL_FILTER_OP_GET_CONTEXT_ROOT,
		[ FILTER_OP_GET_APP_CONTEXT_ROOT ] = &&LABEL_FILTER_OP_GET_APP_CONTEXT_ROOT,
		[ FILTER_OP_GET_PAYLOAD_ROOT ] = &&LABEL_FILTER_OP_GET_PAYLOAD_ROOT,

		[ FILTER_OP_GET_SYMBOL ] = &&LABEL_FILTER_OP_GET_SYMBOL,
		[ FILTER_OP_GET_SYMBOL_FIELD ] = &&LABEL_FILTER_OP_GET_SYMBOL_FIELD,
		[ FILTER_OP_GET_INDEX_U16 ] = &&LABEL_FILTER_OP_GET_INDEX_U16,
		[ FILTER_OP_GET_INDEX_U64 ] = &&LABEL_FILTER_OP_GET_INDEX_U64,

		[ FILTER_OP_LOAD_FIELD ] = &&LABEL_FILTER_OP_LOAD_FIELD,
		[ FILTER_OP_LOAD_FIELD_S8	 ] = &&LABEL_FILTER_OP_LOAD_FIELD_S8,
		[ FILTER_OP_LOAD_FIELD_S16 ] = &&LABEL_FILTER_OP_LOAD_FIELD_S16,
		[ FILTER_OP_LOAD_FIELD_S32 ] = &&LABEL_FILTER_OP_LOAD_FIELD_S32,
		[ FILTER_OP_LOAD_FIELD_S64 ] = &&LABEL_FILTER_OP_LOAD_FIELD_S64,
		[ FILTER_OP_LOAD_FIELD_U8 ] = &&LABEL_FILTER_OP_LOAD_FIELD_U8,
		[ FILTER_OP_LOAD_FIELD_U16 ] = &&LABEL_FILTER_OP_LOAD_FIELD_U16,
		[ FILTER_OP_LOAD_FIELD_U32 ] = &&LABEL_FILTER_OP_LOAD_FIELD_U32,
		[ FILTER_OP_LOAD_FIELD_U64 ] = &&LABEL_FILTER_OP_LOAD_FIELD_U64,
		[ FILTER_OP_LOAD_FIELD_STRING ] = &&LABEL_FILTER_OP_LOAD_FIELD_STRING,
		[ FILTER_OP_LOAD_FIELD_SEQUENCE ] = &&LABEL_FILTER_OP_LOAD_FIELD_SEQUENCE,
		[ FILTER_OP_LOAD_FIELD_DOUBLE ] = &&LABEL_FILTER_OP_LOAD_FIELD_DOUBLE,

		[ FILTER_OP_UNARY_BIT_NOT ] = &&LABEL_FILTER_OP_UNARY_BIT_NOT,

		[ FILTER_OP_RETURN_S64 ] = &&LABEL_FILTER_OP_RETURN_S64,
	};
#endif /* #ifndef INTERPRETER_USE_SWITCH */

	START_OP

		OP(FILTER_OP_UNKNOWN):
		OP(FILTER_OP_LOAD_FIELD_REF):
#ifdef INTERPRETER_USE_SWITCH
		default:
#endif /* INTERPRETER_USE_SWITCH */
			ERR("unknown bytecode op %u",
				(unsigned int) *(filter_opcode_t *) pc);
			ret = -EINVAL;
			goto end;

		OP(FILTER_OP_RETURN):
			/* LTTNG_FILTER_DISCARD or LTTNG_FILTER_RECORD_FLAG */
			/* Handle dynamic typing. */
			switch (estack_ax_t) {
			case REG_S64:
			case REG_U64:
				retval = !!estack_ax_v;
				break;
			case REG_DOUBLE:
			case REG_STRING:
			case REG_STAR_GLOB_STRING:
			default:
				ret = -EINVAL;
				goto end;
			}
			ret = 0;
			goto end;

		OP(FILTER_OP_RETURN_S64):
			/* LTTNG_FILTER_DISCARD or LTTNG_FILTER_RECORD_FLAG */
			retval = !!estack_ax_v;
			ret = 0;
			goto end;

		/* binary */
		OP(FILTER_OP_MUL):
		OP(FILTER_OP_DIV):
		OP(FILTER_OP_MOD):
		OP(FILTER_OP_PLUS):
		OP(FILTER_OP_MINUS):
			ERR("unsupported bytecode op %u",
				(unsigned int) *(filter_opcode_t *) pc);
			ret = -EINVAL;
			goto end;

		OP(FILTER_OP_EQ):
		{
			/* Dynamic typing. */
			switch (estack_ax_t) {
			case REG_S64:	/* Fall-through */
			case REG_U64:
				switch (estack_bx_t) {
				case REG_S64:	/* Fall-through */
				case REG_U64:
					JUMP_TO(FILTER_OP_EQ_S64);
				case REG_DOUBLE:
					JUMP_TO(FILTER_OP_EQ_DOUBLE_S64);
				case REG_STRING: /* Fall-through */
				case REG_STAR_GLOB_STRING:
					ret = -EINVAL;
					goto end;
				default:
					ERR("Unknown filter register type (%d)",
						(int) estack_bx_t);
					ret = -EINVAL;
					goto end;
				}
				break;
			case REG_DOUBLE:
				switch (estack_bx_t) {
				case REG_S64:	/* Fall-through */
				case REG_U64:
					JUMP_TO(FILTER_OP_EQ_S64_DOUBLE);
				case REG_DOUBLE:
					JUMP_TO(FILTER_OP_EQ_DOUBLE);
				case REG_STRING: /* Fall-through */
				case REG_STAR_GLOB_STRING:
					ret = -EINVAL;
					goto end;
				default:
					ERR("Unknown filter register type (%d)",
						(int) estack_bx_t);
					ret = -EINVAL;
					goto end;
				}
				break;
			case REG_STRING:
				switch (estack_bx_t) {
				case REG_S64:	/* Fall-through */
				case REG_U64:	/* Fall-through */
				case REG_DOUBLE:
					ret = -EINVAL;
					goto end;
				case REG_STRING:
					JUMP_TO(FILTER_OP_EQ_STRING);
				case REG_STAR_GLOB_STRING:
					JUMP_TO(FILTER_OP_EQ_STAR_GLOB_STRING);
				default:
					ERR("Unknown filter register type (%d)",
						(int) estack_bx_t);
					ret = -EINVAL;
					goto end;
				}
				break;
			case REG_STAR_GLOB_STRING:
				switch (estack_bx_t) {
				case REG_S64:	/* Fall-through */
				case REG_U64:	/* Fall-through */
				case REG_DOUBLE:
					ret = -EINVAL;
					goto end;
				case REG_STRING:
					JUMP_TO(FILTER_OP_EQ_STAR_GLOB_STRING);
				case REG_STAR_GLOB_STRING:
					ret = -EINVAL;
					goto end;
				default:
					ERR("Unknown filter register type (%d)",
						(int) estack_bx_t);
					ret = -EINVAL;
					goto end;
				}
				break;
			default:
				ERR("Unknown filter register type (%d)",
					(int) estack_ax_t);
				ret = -EINVAL;
				goto end;
			}
		}
		OP(FILTER_OP_NE):
		{
			/* Dynamic typing. */
			switch (estack_ax_t) {
			case REG_S64:	/* Fall-through */
			case REG_U64:
				switch (estack_bx_t) {
				case REG_S64:	/* Fall-through */
				case REG_U64:
					JUMP_TO(FILTER_OP_NE_S64);
				case REG_DOUBLE:
					JUMP_TO(FILTER_OP_NE_DOUBLE_S64);
				case REG_STRING: /* Fall-through */
				case REG_STAR_GLOB_STRING:
					ret = -EINVAL;
					goto end;
				default:
					ERR("Unknown filter register type (%d)",
						(int) estack_bx_t);
					ret = -EINVAL;
					goto end;
				}
				break;
			case REG_DOUBLE:
				switch (estack_bx_t) {
				case REG_S64:	/* Fall-through */
				case REG_U64:
					JUMP_TO(FILTER_OP_NE_S64_DOUBLE);
				case REG_DOUBLE:
					JUMP_TO(FILTER_OP_NE_DOUBLE);
				case REG_STRING: /* Fall-through */
				case REG_STAR_GLOB_STRING:
					ret = -EINVAL;
					goto end;
				default:
					ERR("Unknown filter register type (%d)",
						(int) estack_bx_t);
					ret = -EINVAL;
					goto end;
				}
				break;
			case REG_STRING:
				switch (estack_bx_t) {
				case REG_S64:	/* Fall-through */
				case REG_U64:
				case REG_DOUBLE:
					ret = -EINVAL;
					goto end;
				case REG_STRING:
					JUMP_TO(FILTER_OP_NE_STRING);
				case REG_STAR_GLOB_STRING:
					JUMP_TO(FILTER_OP_NE_STAR_GLOB_STRING);
				default:
					ERR("Unknown filter register type (%d)",
						(int) estack_bx_t);
					ret = -EINVAL;
					goto end;
				}
				break;
			case REG_STAR_GLOB_STRING:
				switch (estack_bx_t) {
				case REG_S64:	/* Fall-through */
				case REG_U64:
				case REG_DOUBLE:
					ret = -EINVAL;
					goto end;
				case REG_STRING:
					JUMP_TO(FILTER_OP_NE_STAR_GLOB_STRING);
				case REG_STAR_GLOB_STRING:
					ret = -EINVAL;
					goto end;
				default:
					ERR("Unknown filter register type (%d)",
						(int) estack_bx_t);
					ret = -EINVAL;
					goto end;
				}
				break;
			default:
				ERR("Unknown filter register type (%d)",
					(int) estack_ax_t);
				ret = -EINVAL;
				goto end;
			}
		}
		OP(FILTER_OP_GT):
		{
			/* Dynamic typing. */
			switch (estack_ax_t) {
			case REG_S64:	/* Fall-through */
			case REG_U64:
				switch (estack_bx_t) {
				case REG_S64:	/* Fall-through */
				case REG_U64:
					JUMP_TO(FILTER_OP_GT_S64);
				case REG_DOUBLE:
					JUMP_TO(FILTER_OP_GT_DOUBLE_S64);
				case REG_STRING: /* Fall-through */
				case REG_STAR_GLOB_STRING:
					ret = -EINVAL;
					goto end;
				default:
					ERR("Unknown filter register type (%d)",
						(int) estack_bx_t);
					ret = -EINVAL;
					goto end;
				}
				break;
			case REG_DOUBLE:
				switch (estack_bx_t) {
				case REG_S64:	/* Fall-through */
				case REG_U64:
					JUMP_TO(FILTER_OP_GT_S64_DOUBLE);
				case REG_DOUBLE:
					JUMP_TO(FILTER_OP_GT_DOUBLE);
				case REG_STRING: /* Fall-through */
				case REG_STAR_GLOB_STRING:
					ret = -EINVAL;
					goto end;
				default:
					ERR("Unknown filter register type (%d)",
						(int) estack_bx_t);
					ret = -EINVAL;
					goto end;
				}
				break;
			case REG_STRING:
				switch (estack_bx_t) {
				case REG_S64:	/* Fall-through */
				case REG_U64:	/* Fall-through */
				case REG_DOUBLE: /* Fall-through */
				case REG_STAR_GLOB_STRING:
					ret = -EINVAL;
					goto end;
				case REG_STRING:
					JUMP_TO(FILTER_OP_GT_STRING);
				default:
					ERR("Unknown filter register type (%d)",
						(int) estack_bx_t);
					ret = -EINVAL;
					goto end;
				}
				break;
			default:
				ERR("Unknown filter register type (%d)",
					(int) estack_ax_t);
				ret = -EINVAL;
				goto end;
			}
		}
		OP(FILTER_OP_LT):
		{
			/* Dynamic typing. */
			switch (estack_ax_t) {
			case REG_S64:	/* Fall-through */
			case REG_U64:
				switch (estack_bx_t) {
				case REG_S64:	/* Fall-through */
				case REG_U64:
					JUMP_TO(FILTER_OP_LT_S64);
				case REG_DOUBLE:
					JUMP_TO(FILTER_OP_LT_DOUBLE_S64);
				case REG_STRING: /* Fall-through */
				case REG_STAR_GLOB_STRING:
					ret = -EINVAL;
					goto end;
				default:
					ERR("Unknown filter register type (%d)",
						(int) estack_bx_t);
					ret = -EINVAL;
					goto end;
				}
				break;
			case REG_DOUBLE:
				switch (estack_bx_t) {
				case REG_S64:	/* Fall-through */
				case REG_U64:
					JUMP_TO(FILTER_OP_LT_S64_DOUBLE);
				case REG_DOUBLE:
					JUMP_TO(FILTER_OP_LT_DOUBLE);
				case REG_STRING: /* Fall-through */
				case REG_STAR_GLOB_STRING:
					ret = -EINVAL;
					goto end;
				default:
					ERR("Unknown filter register type (%d)",
						(int) estack_bx_t);
					ret = -EINVAL;
					goto end;
				}
				break;
			case REG_STRING:
				switch (estack_bx_t) {
				case REG_S64:	/* Fall-through */
				case REG_U64:	/* Fall-through */
				case REG_DOUBLE: /* Fall-through */
				case REG_STAR_GLOB_STRING:
					ret = -EINVAL;
					goto end;
				case REG_STRING:
					JUMP_TO(FILTER_OP_LT_STRING);
				default:
					ERR("Unknown filter register type (%d)",
						(int) estack_bx_t);
					ret = -EINVAL;
					goto end;
				}
				break;
			default:
				ERR("Unknown filter register type (%d)",
					(int) estack_ax_t);
				ret = -EINVAL;
				goto end;
			}
		}
		OP(FILTER_OP_GE):
		{
			/* Dynamic typing. */
			switch (estack_ax_t) {
			case REG_S64:	/* Fall-through */
			case REG_U64:
				switch (estack_bx_t) {
				case REG_S64:	/* Fall-through */
				case REG_U64:
					JUMP_TO(FILTER_OP_GE_S64);
				case REG_DOUBLE:
					JUMP_TO(FILTER_OP_GE_DOUBLE_S64);
				case REG_STRING: /* Fall-through */
				case REG_STAR_GLOB_STRING:
					ret = -EINVAL;
					goto end;
				default:
					ERR("Unknown filter register type (%d)",
						(int) estack_bx_t);
					ret = -EINVAL;
					goto end;
				}
				break;
			case REG_DOUBLE:
				switch (estack_bx_t) {
				case REG_S64:	/* Fall-through */
				case REG_U64:
					JUMP_TO(FILTER_OP_GE_S64_DOUBLE);
				case REG_DOUBLE:
					JUMP_TO(FILTER_OP_GE_DOUBLE);
				case REG_STRING: /* Fall-through */
				case REG_STAR_GLOB_STRING:
					ret = -EINVAL;
					goto end;
				default:
					ERR("Unknown filter register type (%d)",
						(int) estack_bx_t);
					ret = -EINVAL;
					goto end;
				}
				break;
			case REG_STRING:
				switch (estack_bx_t) {
				case REG_S64:	/* Fall-through */
				case REG_U64:	/* Fall-through */
				case REG_DOUBLE: /* Fall-through */
				case REG_STAR_GLOB_STRING:
					ret = -EINVAL;
					goto end;
				case REG_STRING:
					JUMP_TO(FILTER_OP_GE_STRING);
				default:
					ERR("Unknown filter register type (%d)",
						(int) estack_bx_t);
					ret = -EINVAL;
					goto end;
				}
				break;
			default:
				ERR("Unknown filter register type (%d)",
					(int) estack_ax_t);
				ret = -EINVAL;
				goto end;
			}
		}
		OP(FILTER_OP_LE):
		{
			/* Dynamic typing. */
			switch (estack_ax_t) {
			case REG_S64:	/* Fall-through */
			case REG_U64:
				switch (estack_bx_t) {
				case REG_S64:	/* Fall-through */
				case REG_U64:
					JUMP_TO(FILTER_OP_LE_S64);
				case REG_DOUBLE:
					JUMP_TO(FILTER_OP_LE_DOUBLE_S64);
				case REG_STRING: /* Fall-through */
				case REG_STAR_GLOB_STRING:
					ret = -EINVAL;
					goto end;
				default:
					ERR("Unknown filter register type (%d)",
						(int) estack_bx_t);
					ret = -EINVAL;
					goto end;
				}
				break;
			case REG_DOUBLE:
				switch (estack_bx_t) {
				case REG_S64:	/* Fall-through */
				case REG_U64:
					JUMP_TO(FILTER_OP_LE_S64_DOUBLE);
				case REG_DOUBLE:
					JUMP_TO(FILTER_OP_LE_DOUBLE);
				case REG_STRING: /* Fall-through */
				case REG_STAR_GLOB_STRING:
					ret = -EINVAL;
					goto end;
				default:
					ERR("Unknown filter register type (%d)",
						(int) estack_bx_t);
					ret = -EINVAL;
					goto end;
				}
				break;
			case REG_STRING:
				switch (estack_bx_t) {
				case REG_S64:	/* Fall-through */
				case REG_U64:	/* Fall-through */
				case REG_DOUBLE: /* Fall-through */
				case REG_STAR_GLOB_STRING:
					ret = -EINVAL;
					goto end;
				case REG_STRING:
					JUMP_TO(FILTER_OP_LE_STRING);
				default:
					ERR("Unknown filter register type (%d)",
						(int) estack_bx_t);
					ret = -EINVAL;
					goto end;
				}
				break;
			default:
				ERR("Unknown filter register type (%d)",
					(int) estack_ax_t);
				ret = -EINVAL;
				goto end;
			}
		}

		OP(FILTER_OP_EQ_STRING):
		{
			int res;

			res = (stack_strcmp(stack, top, "==") == 0);
			estack_pop(stack, top, ax, bx, ax_t, bx_t);
			estack_ax_v = res;
			estack_ax_t = REG_S64;
			next_pc += sizeof(struct binary_op);
			PO;
		}
		OP(FILTER_OP_NE_STRING):
		{
			int res;

			res = (stack_strcmp(stack, top, "!=") != 0);
			estack_pop(stack, top, ax, bx, ax_t, bx_t);
			estack_ax_v = res;
			estack_ax_t = REG_S64;
			next_pc += sizeof(struct binary_op);
			PO;
		}
		OP(FILTER_OP_GT_STRING):
		{
			int res;

			res = (stack_strcmp(stack, top, ">") > 0);
			estack_pop(stack, top, ax, bx, ax_t, bx_t);
			estack_ax_v = res;
			estack_ax_t = REG_S64;
			next_pc += sizeof(struct binary_op);
			PO;
		}
		OP(FILTER_OP_LT_STRING):
		{
			int res;

			res = (stack_strcmp(stack, top, "<") < 0);
			estack_pop(stack, top, ax, bx, ax_t, bx_t);
			estack_ax_v = res;
			estack_ax_t = REG_S64;
			next_pc += sizeof(struct binary_op);
			PO;
		}
		OP(FILTER_OP_GE_STRING):
		{
			int res;

			res = (stack_strcmp(stack, top, ">=") >= 0);
			estack_pop(stack, top, ax, bx, ax_t, bx_t);
			estack_ax_v = res;
			estack_ax_t = REG_S64;
			next_pc += sizeof(struct binary_op);
			PO;
		}
		OP(FILTER_OP_LE_STRING):
		{
			int res;

			res = (stack_strcmp(stack, top, "<=") <= 0);
			estack_pop(stack, top, ax, bx, ax_t, bx_t);
			estack_ax_v = res;
			estack_ax_t = REG_S64;
			next_pc += sizeof(struct binary_op);
			PO;
		}

		OP(FILTER_OP_EQ_STAR_GLOB_STRING):
		{
			int res;

			res = (stack_star_glob_match(stack, top, "==") == 0);
			estack_pop(stack, top, ax, bx, ax_t, bx_t);
			estack_ax_v = res;
			estack_ax_t = REG_S64;
			next_pc += sizeof(struct binary_op);
			PO;
		}
		OP(FILTER_OP_NE_STAR_GLOB_STRING):
		{
			int res;

			res = (stack_star_glob_match(stack, top, "!=") != 0);
			estack_pop(stack, top, ax, bx, ax_t, bx_t);
			estack_ax_v = res;
			estack_ax_t = REG_S64;
			next_pc += sizeof(struct binary_op);
			PO;
		}

		OP(FILTER_OP_EQ_S64):
		{
			int res;

			res = (estack_bx_v == estack_ax_v);
			estack_pop(stack, top, ax, bx, ax_t, bx_t);
			estack_ax_v = res;
			estack_ax_t = REG_S64;
			next_pc += sizeof(struct binary_op);
			PO;
		}
		OP(FILTER_OP_NE_S64):
		{
			int res;

			res = (estack_bx_v != estack_ax_v);
			estack_pop(stack, top, ax, bx, ax_t, bx_t);
			estack_ax_v = res;
			estack_ax_t = REG_S64;
			next_pc += sizeof(struct binary_op);
			PO;
		}
		OP(FILTER_OP_GT_S64):
		{
			int res;

			res = (estack_bx_v > estack_ax_v);
			estack_pop(stack, top, ax, bx, ax_t, bx_t);
			estack_ax_v = res;
			estack_ax_t = REG_S64;
			next_pc += sizeof(struct binary_op);
			PO;
		}
		OP(FILTER_OP_LT_S64):
		{
			int res;

			res = (estack_bx_v < estack_ax_v);
			estack_pop(stack, top, ax, bx, ax_t, bx_t);
			estack_ax_v = res;
			estack_ax_t = REG_S64;
			next_pc += sizeof(struct binary_op);
			PO;
		}
		OP(FILTER_OP_GE_S64):
		{
			int res;

			res = (estack_bx_v >= estack_ax_v);
			estack_pop(stack, top, ax, bx, ax_t, bx_t);
			estack_ax_v = res;
			estack_ax_t = REG_S64;
			next_pc += sizeof(struct binary_op);
			PO;
		}
		OP(FILTER_OP_LE_S64):
		{
			int res;

			res = (estack_bx_v <= estack_ax_v);
			estack_pop(stack, top, ax, bx, ax_t, bx_t);
			estack_ax_v = res;
			estack_ax_t = REG_S64;
			next_pc += sizeof(struct binary_op);
			PO;
		}

		OP(FILTER_OP_EQ_DOUBLE):
		{
			int res;

			res = (estack_bx(stack, top)->u.d == estack_ax(stack, top)->u.d);
			estack_pop(stack, top, ax, bx, ax_t, bx_t);
			estack_ax_v = res;
			estack_ax_t = REG_S64;
			next_pc += sizeof(struct binary_op);
			PO;
		}
		OP(FILTER_OP_NE_DOUBLE):
		{
			int res;

			res = (estack_bx(stack, top)->u.d != estack_ax(stack, top)->u.d);
			estack_pop(stack, top, ax, bx, ax_t, bx_t);
			estack_ax_v = res;
			estack_ax_t = REG_S64;
			next_pc += sizeof(struct binary_op);
			PO;
		}
		OP(FILTER_OP_GT_DOUBLE):
		{
			int res;

			res = (estack_bx(stack, top)->u.d > estack_ax(stack, top)->u.d);
			estack_pop(stack, top, ax, bx, ax_t, bx_t);
			estack_ax_v = res;
			estack_ax_t = REG_S64;
			next_pc += sizeof(struct binary_op);
			PO;
		}
		OP(FILTER_OP_LT_DOUBLE):
		{
			int res;

			res = (estack_bx(stack, top)->u.d < estack_ax(stack, top)->u.d);
			estack_pop(stack, top, ax, bx, ax_t, bx_t);
			estack_ax_v = res;
			estack_ax_t = REG_S64;
			next_pc += sizeof(struct binary_op);
			PO;
		}
		OP(FILTER_OP_GE_DOUBLE):
		{
			int res;

			res = (estack_bx(stack, top)->u.d >= estack_ax(stack, top)->u.d);
			estack_pop(stack, top, ax, bx, ax_t, bx_t);
			estack_ax_v = res;
			estack_ax_t = REG_S64;
			next_pc += sizeof(struct binary_op);
			PO;
		}
		OP(FILTER_OP_LE_DOUBLE):
		{
			int res;

			res = (estack_bx(stack, top)->u.d <= estack_ax(stack, top)->u.d);
			estack_pop(stack, top, ax, bx, ax_t, bx_t);
			estack_ax_v = res;
			estack_ax_t = REG_S64;
			next_pc += sizeof(struct binary_op);
			PO;
		}

		/* Mixed S64-double binary comparators */
		OP(FILTER_OP_EQ_DOUBLE_S64):
		{
			int res;

			res = (estack_bx(stack, top)->u.d == estack_ax_v);
			estack_pop(stack, top, ax, bx, ax_t, bx_t);
			estack_ax_v = res;
			estack_ax_t = REG_S64;
			next_pc += sizeof(struct binary_op);
			PO;
		}
		OP(FILTER_OP_NE_DOUBLE_S64):
		{
			int res;

			res = (estack_bx(stack, top)->u.d != estack_ax_v);
			estack_pop(stack, top, ax, bx, ax_t, bx_t);
			estack_ax_v = res;
			estack_ax_t = REG_S64;
			next_pc += sizeof(struct binary_op);
			PO;
		}
		OP(FILTER_OP_GT_DOUBLE_S64):
		{
			int res;

			res = (estack_bx(stack, top)->u.d > estack_ax_v);
			estack_pop(stack, top, ax, bx, ax_t, bx_t);
			estack_ax_v = res;
			estack_ax_t = REG_S64;
			next_pc += sizeof(struct binary_op);
			PO;
		}
		OP(FILTER_OP_LT_DOUBLE_S64):
		{
			int res;

			res = (estack_bx(stack, top)->u.d < estack_ax_v);
			estack_pop(stack, top, ax, bx, ax_t, bx_t);
			estack_ax_v = res;
			estack_ax_t = REG_S64;
			next_pc += sizeof(struct binary_op);
			PO;
		}
		OP(FILTER_OP_GE_DOUBLE_S64):
		{
			int res;

			res = (estack_bx(stack, top)->u.d >= estack_ax_v);
			estack_pop(stack, top, ax, bx, ax_t, bx_t);
			estack_ax_v = res;
			estack_ax_t = REG_S64;
			next_pc += sizeof(struct binary_op);
			PO;
		}
		OP(FILTER_OP_LE_DOUBLE_S64):
		{
			int res;

			res = (estack_bx(stack, top)->u.d <= estack_ax_v);
			estack_pop(stack, top, ax, bx, ax_t, bx_t);
			estack_ax_v = res;
			estack_ax_t = REG_S64;
			next_pc += sizeof(struct binary_op);
			PO;
		}

		OP(FILTER_OP_EQ_S64_DOUBLE):
		{
			int res;

			res = (estack_bx_v == estack_ax(stack, top)->u.d);
			estack_pop(stack, top, ax, bx, ax_t, bx_t);
			estack_ax_v = res;
			estack_ax_t = REG_S64;
			next_pc += sizeof(struct binary_op);
			PO;
		}
		OP(FILTER_OP_NE_S64_DOUBLE):
		{
			int res;

			res = (estack_bx_v != estack_ax(stack, top)->u.d);
			estack_pop(stack, top, ax, bx, ax_t, bx_t);
			estack_ax_v = res;
			estack_ax_t = REG_S64;
			next_pc += sizeof(struct binary_op);
			PO;
		}
		OP(FILTER_OP_GT_S64_DOUBLE):
		{
			int res;

			res = (estack_bx_v > estack_ax(stack, top)->u.d);
			estack_pop(stack, top, ax, bx, ax_t, bx_t);
			estack_ax_v = res;
			estack_ax_t = REG_S64;
			next_pc += sizeof(struct binary_op);
			PO;
		}
		OP(FILTER_OP_LT_S64_DOUBLE):
		{
			int res;

			res = (estack_bx_v < estack_ax(stack, top)->u.d);
			estack_pop(stack, top, ax, bx, ax_t, bx_t);
			estack_ax_v = res;
			estack_ax_t = REG_S64;
			next_pc += sizeof(struct binary_op);
			PO;
		}
		OP(FILTER_OP_GE_S64_DOUBLE):
		{
			int res;

			res = (estack_bx_v >= estack_ax(stack, top)->u.d);
			estack_pop(stack, top, ax, bx, ax_t, bx_t);
			estack_ax_v = res;
			estack_ax_t = REG_S64;
			next_pc += sizeof(struct binary_op);
			PO;
		}
		OP(FILTER_OP_LE_S64_DOUBLE):
		{
			int res;

			res = (estack_bx_v <= estack_ax(stack, top)->u.d);
			estack_pop(stack, top, ax, bx, ax_t, bx_t);
			estack_ax_v = res;
			estack_ax_t = REG_S64;
			next_pc += sizeof(struct binary_op);
			PO;
		}
		OP(FILTER_OP_BIT_RSHIFT):
		{
			int64_t res;

			if (!IS_INTEGER_REGISTER(estack_ax_t) || !IS_INTEGER_REGISTER(estack_bx_t)) {
				ret = -EINVAL;
				goto end;
			}

			/* Catch undefined behavior. */
			if (caa_unlikely(estack_ax_v < 0 || estack_ax_v >= 64)) {
				ret = -EINVAL;
				goto end;
			}
			res = ((uint64_t) estack_bx_v >> (uint32_t) estack_ax_v);
			estack_pop(stack, top, ax, bx, ax_t, bx_t);
			estack_ax_v = res;
			estack_ax_t = REG_U64;
			next_pc += sizeof(struct binary_op);
			PO;
		}
		OP(FILTER_OP_BIT_LSHIFT):
		{
			int64_t res;

			if (!IS_INTEGER_REGISTER(estack_ax_t) || !IS_INTEGER_REGISTER(estack_bx_t)) {
				ret = -EINVAL;
				goto end;
			}

			/* Catch undefined behavior. */
			if (caa_unlikely(estack_ax_v < 0 || estack_ax_v >= 64)) {
				ret = -EINVAL;
				goto end;
			}
			res = ((uint64_t) estack_bx_v << (uint32_t) estack_ax_v);
			estack_pop(stack, top, ax, bx, ax_t, bx_t);
			estack_ax_v = res;
			estack_ax_t = REG_U64;
			next_pc += sizeof(struct binary_op);
			PO;
		}
		OP(FILTER_OP_BIT_AND):
		{
			int64_t res;

			if (!IS_INTEGER_REGISTER(estack_ax_t) || !IS_INTEGER_REGISTER(estack_bx_t)) {
				ret = -EINVAL;
				goto end;
			}

			res = ((uint64_t) estack_bx_v & (uint64_t) estack_ax_v);
			estack_pop(stack, top, ax, bx, ax_t, bx_t);
			estack_ax_v = res;
			estack_ax_t = REG_U64;
			next_pc += sizeof(struct binary_op);
			PO;
		}
		OP(FILTER_OP_BIT_OR):
		{
			int64_t res;

			if (!IS_INTEGER_REGISTER(estack_ax_t) || !IS_INTEGER_REGISTER(estack_bx_t)) {
				ret = -EINVAL;
				goto end;
			}

			res = ((uint64_t) estack_bx_v | (uint64_t) estack_ax_v);
			estack_pop(stack, top, ax, bx, ax_t, bx_t);
			estack_ax_v = res;
			estack_ax_t = REG_U64;
			next_pc += sizeof(struct binary_op);
			PO;
		}
		OP(FILTER_OP_BIT_XOR):
		{
			int64_t res;

			if (!IS_INTEGER_REGISTER(estack_ax_t) || !IS_INTEGER_REGISTER(estack_bx_t)) {
				ret = -EINVAL;
				goto end;
			}

			res = ((uint64_t) estack_bx_v ^ (uint64_t) estack_ax_v);
			estack_pop(stack, top, ax, bx, ax_t, bx_t);
			estack_ax_v = res;
			estack_ax_t = REG_U64;
			next_pc += sizeof(struct binary_op);
			PO;
		}

		/* unary */
		OP(FILTER_OP_UNARY_PLUS):
		{
			/* Dynamic typing. */
			switch (estack_ax_t) {
			case REG_S64:	/* Fall-through. */
			case REG_U64:
				JUMP_TO(FILTER_OP_UNARY_PLUS_S64);
			case REG_DOUBLE:
				JUMP_TO(FILTER_OP_UNARY_PLUS_DOUBLE);
			case REG_STRING: /* Fall-through */
			case REG_STAR_GLOB_STRING:
				ret = -EINVAL;
				goto end;
			default:
				ERR("Unknown filter register type (%d)",
					(int) estack_ax_t);
				ret = -EINVAL;
				goto end;
			}
		}
		OP(FILTER_OP_UNARY_MINUS):
		{
			/* Dynamic typing. */
			switch (estack_ax_t) {
			case REG_S64:	/* Fall-through. */
			case REG_U64:
				JUMP_TO(FILTER_OP_UNARY_MINUS_S64);
			case REG_DOUBLE:
				JUMP_TO(FILTER_OP_UNARY_MINUS_DOUBLE);
			case REG_STRING: /* Fall-through */
			case REG_STAR_GLOB_STRING:
				ret = -EINVAL;
				goto end;
			default:
				ERR("Unknown filter register type (%d)",
					(int) estack_ax_t);
				ret = -EINVAL;
				goto end;
			}
		}
		OP(FILTER_OP_UNARY_NOT):
		{
			/* Dynamic typing. */
			switch (estack_ax_t) {
			case REG_S64:	/* Fall-through. */
			case REG_U64:
				JUMP_TO(FILTER_OP_UNARY_NOT_S64);
			case REG_DOUBLE:
				JUMP_TO(FILTER_OP_UNARY_NOT_DOUBLE);
			case REG_STRING: /* Fall-through */
			case REG_STAR_GLOB_STRING:
				ret = -EINVAL;
				goto end;
			default:
				ERR("Unknown filter register type (%d)",
					(int) estack_ax_t);
				ret = -EINVAL;
				goto end;
			}
			next_pc += sizeof(struct unary_op);
			PO;
		}

		OP(FILTER_OP_UNARY_BIT_NOT):
		{
			/* Dynamic typing. */
			if (!IS_INTEGER_REGISTER(estack_ax_t)) {
				ret = -EINVAL;
				goto end;
			}

			estack_ax_v = ~(uint64_t) estack_ax_v;
			estack_ax_t = REG_U64;
			next_pc += sizeof(struct unary_op);
			PO;
		}

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
			estack_ax_t = REG_S64;
			next_pc += sizeof(struct unary_op);
			PO;
		}
		OP(FILTER_OP_UNARY_NOT_DOUBLE):
		{
			estack_ax_v = !estack_ax(stack, top)->u.d;
			estack_ax_t = REG_S64;
			next_pc += sizeof(struct unary_op);
			PO;
		}

		/* logical */
		OP(FILTER_OP_AND):
		{
			struct logical_op *insn = (struct logical_op *) pc;

			if (estack_ax_t != REG_S64 && estack_ax_t != REG_U64) {
				ret = -EINVAL;
				goto end;
			}
			/* If AX is 0, skip and evaluate to 0 */
			if (unlikely(estack_ax_v == 0)) {
				dbg_printf("Jumping to bytecode offset %u\n",
					(unsigned int) insn->skip_offset);
				next_pc = start_pc + insn->skip_offset;
			} else {
				/* Pop 1 when jump not taken */
				estack_pop(stack, top, ax, bx, ax_t, bx_t);
				next_pc += sizeof(struct logical_op);
			}
			PO;
		}
		OP(FILTER_OP_OR):
		{
			struct logical_op *insn = (struct logical_op *) pc;

			if (estack_ax_t != REG_S64 && estack_ax_t != REG_U64) {
				ret = -EINVAL;
				goto end;
			}
			/* If AX is nonzero, skip and evaluate to 1 */
			if (unlikely(estack_ax_v != 0)) {
				estack_ax_v = 1;
				dbg_printf("Jumping to bytecode offset %u\n",
					(unsigned int) insn->skip_offset);
				next_pc = start_pc + insn->skip_offset;
			} else {
				/* Pop 1 when jump not taken */
				estack_pop(stack, top, ax, bx, ax_t, bx_t);
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
			estack_push(stack, top, ax, bx, ax_t, bx_t);
			estack_ax(stack, top)->u.s.str =
				*(const char * const *) &filter_stack_data[ref->offset];
			if (unlikely(!estack_ax(stack, top)->u.s.str)) {
				dbg_printf("Filter warning: loading a NULL string.\n");
				ret = -EINVAL;
				goto end;
			}
			estack_ax(stack, top)->u.s.seq_len = SIZE_MAX;
			estack_ax(stack, top)->u.s.literal_type =
				ESTACK_STRING_LITERAL_TYPE_NONE;
			estack_ax_t = REG_STRING;
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
			estack_push(stack, top, ax, bx, ax_t, bx_t);
			estack_ax(stack, top)->u.s.seq_len =
				*(unsigned long *) &filter_stack_data[ref->offset];
			estack_ax(stack, top)->u.s.str =
				*(const char **) (&filter_stack_data[ref->offset
								+ sizeof(unsigned long)]);
			estack_ax_t = REG_STRING;
			if (unlikely(!estack_ax(stack, top)->u.s.str)) {
				dbg_printf("Filter warning: loading a NULL sequence.\n");
				ret = -EINVAL;
				goto end;
			}
			estack_ax(stack, top)->u.s.literal_type =
				ESTACK_STRING_LITERAL_TYPE_NONE;
			next_pc += sizeof(struct load_op) + sizeof(struct field_ref);
			PO;
		}

		OP(FILTER_OP_LOAD_FIELD_REF_S64):
		{
			struct load_op *insn = (struct load_op *) pc;
			struct field_ref *ref = (struct field_ref *) insn->data;

			dbg_printf("load field ref offset %u type s64\n",
				ref->offset);
			estack_push(stack, top, ax, bx, ax_t, bx_t);
			estack_ax_v =
				((struct literal_numeric *) &filter_stack_data[ref->offset])->v;
			estack_ax_t = REG_S64;
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
			estack_push(stack, top, ax, bx, ax_t, bx_t);
			memcpy(&estack_ax(stack, top)->u.d, &filter_stack_data[ref->offset],
				sizeof(struct literal_double));
			estack_ax_t = REG_DOUBLE;
			dbg_printf("ref load double %g\n", estack_ax(stack, top)->u.d);
			next_pc += sizeof(struct load_op) + sizeof(struct field_ref);
			PO;
		}

		/* load from immediate operand */
		OP(FILTER_OP_LOAD_STRING):
		{
			struct load_op *insn = (struct load_op *) pc;

			dbg_printf("load string %s\n", insn->data);
			estack_push(stack, top, ax, bx, ax_t, bx_t);
			estack_ax(stack, top)->u.s.str = insn->data;
			estack_ax(stack, top)->u.s.seq_len = SIZE_MAX;
			estack_ax(stack, top)->u.s.literal_type =
				ESTACK_STRING_LITERAL_TYPE_PLAIN;
			estack_ax_t = REG_STRING;
			next_pc += sizeof(struct load_op) + strlen(insn->data) + 1;
			PO;
		}

		OP(FILTER_OP_LOAD_STAR_GLOB_STRING):
		{
			struct load_op *insn = (struct load_op *) pc;

			dbg_printf("load globbing pattern %s\n", insn->data);
			estack_push(stack, top, ax, bx, ax_t, bx_t);
			estack_ax(stack, top)->u.s.str = insn->data;
			estack_ax(stack, top)->u.s.seq_len = SIZE_MAX;
			estack_ax(stack, top)->u.s.literal_type =
				ESTACK_STRING_LITERAL_TYPE_STAR_GLOB;
			estack_ax_t = REG_STAR_GLOB_STRING;
			next_pc += sizeof(struct load_op) + strlen(insn->data) + 1;
			PO;
		}

		OP(FILTER_OP_LOAD_S64):
		{
			struct load_op *insn = (struct load_op *) pc;

			estack_push(stack, top, ax, bx, ax_t, bx_t);
			estack_ax_v = ((struct literal_numeric *) insn->data)->v;
			estack_ax_t = REG_S64;
			dbg_printf("load s64 %" PRIi64 "\n", estack_ax_v);
			next_pc += sizeof(struct load_op)
					+ sizeof(struct literal_numeric);
			PO;
		}

		OP(FILTER_OP_LOAD_DOUBLE):
		{
			struct load_op *insn = (struct load_op *) pc;

			estack_push(stack, top, ax, bx, ax_t, bx_t);
			memcpy(&estack_ax(stack, top)->u.d, insn->data,
				sizeof(struct literal_double));
			estack_ax_t = REG_DOUBLE;
			dbg_printf("load double %g\n", estack_ax(stack, top)->u.d);
			next_pc += sizeof(struct load_op)
					+ sizeof(struct literal_double);
			PO;
		}

		/* cast */
		OP(FILTER_OP_CAST_TO_S64):
		{
			/* Dynamic typing. */
			switch (estack_ax_t) {
			case REG_S64:
				JUMP_TO(FILTER_OP_CAST_NOP);
			case REG_DOUBLE:
				JUMP_TO(FILTER_OP_CAST_DOUBLE_TO_S64);
			case REG_U64:
				estack_ax_t = REG_S64;
				next_pc += sizeof(struct cast_op);
			case REG_STRING: /* Fall-through */
			case REG_STAR_GLOB_STRING:
				ret = -EINVAL;
				goto end;
			default:
				ERR("Unknown filter register type (%d)",
					(int) estack_ax_t);
				ret = -EINVAL;
				goto end;
			}
		}

		OP(FILTER_OP_CAST_DOUBLE_TO_S64):
		{
			estack_ax_v = (int64_t) estack_ax(stack, top)->u.d;
			estack_ax_t = REG_S64;
			next_pc += sizeof(struct cast_op);
			PO;
		}

		OP(FILTER_OP_CAST_NOP):
		{
			next_pc += sizeof(struct cast_op);
			PO;
		}

		/* get context ref */
		OP(FILTER_OP_GET_CONTEXT_REF):
		{
			struct load_op *insn = (struct load_op *) pc;
			struct field_ref *ref = (struct field_ref *) insn->data;
			struct lttng_ctx_field *ctx_field;
			struct lttng_ctx_value v;

			dbg_printf("get context ref offset %u type dynamic\n",
				ref->offset);
			ctx_field = &ctx->fields[ref->offset];
			ctx_field->get_value(ctx_field, &v);
			estack_push(stack, top, ax, bx, ax_t, bx_t);
			switch (v.sel) {
			case LTTNG_UST_DYNAMIC_TYPE_NONE:
				ret = -EINVAL;
				goto end;
			case LTTNG_UST_DYNAMIC_TYPE_S64:
				estack_ax_v = v.u.s64;
				estack_ax_t = REG_S64;
				dbg_printf("ref get context dynamic s64 %" PRIi64 "\n", estack_ax_v);
				break;
			case LTTNG_UST_DYNAMIC_TYPE_DOUBLE:
				estack_ax(stack, top)->u.d = v.u.d;
				estack_ax_t = REG_DOUBLE;
				dbg_printf("ref get context dynamic double %g\n", estack_ax(stack, top)->u.d);
				break;
			case LTTNG_UST_DYNAMIC_TYPE_STRING:
				estack_ax(stack, top)->u.s.str = v.u.str;
				if (unlikely(!estack_ax(stack, top)->u.s.str)) {
					dbg_printf("Filter warning: loading a NULL string.\n");
					ret = -EINVAL;
					goto end;
				}
				estack_ax(stack, top)->u.s.seq_len = SIZE_MAX;
				estack_ax(stack, top)->u.s.literal_type =
					ESTACK_STRING_LITERAL_TYPE_NONE;
				dbg_printf("ref get context dynamic string %s\n", estack_ax(stack, top)->u.s.str);
				estack_ax_t = REG_STRING;
				break;
			default:
				dbg_printf("Filter warning: unknown dynamic type (%d).\n", (int) v.sel);
				ret = -EINVAL;
				goto end;
			}
			next_pc += sizeof(struct load_op) + sizeof(struct field_ref);
			PO;
		}

		OP(FILTER_OP_GET_CONTEXT_REF_STRING):
		{
			struct load_op *insn = (struct load_op *) pc;
			struct field_ref *ref = (struct field_ref *) insn->data;
			struct lttng_ctx_field *ctx_field;
			struct lttng_ctx_value v;

			dbg_printf("get context ref offset %u type string\n",
				ref->offset);
			ctx_field = &ctx->fields[ref->offset];
			ctx_field->get_value(ctx_field, &v);
			estack_push(stack, top, ax, bx, ax_t, bx_t);
			estack_ax(stack, top)->u.s.str = v.u.str;
			if (unlikely(!estack_ax(stack, top)->u.s.str)) {
				dbg_printf("Filter warning: loading a NULL string.\n");
				ret = -EINVAL;
				goto end;
			}
			estack_ax(stack, top)->u.s.seq_len = SIZE_MAX;
			estack_ax(stack, top)->u.s.literal_type =
				ESTACK_STRING_LITERAL_TYPE_NONE;
			estack_ax_t = REG_STRING;
			dbg_printf("ref get context string %s\n", estack_ax(stack, top)->u.s.str);
			next_pc += sizeof(struct load_op) + sizeof(struct field_ref);
			PO;
		}

		OP(FILTER_OP_GET_CONTEXT_REF_S64):
		{
			struct load_op *insn = (struct load_op *) pc;
			struct field_ref *ref = (struct field_ref *) insn->data;
			struct lttng_ctx_field *ctx_field;
			struct lttng_ctx_value v;

			dbg_printf("get context ref offset %u type s64\n",
				ref->offset);
			ctx_field = &ctx->fields[ref->offset];
			ctx_field->get_value(ctx_field, &v);
			estack_push(stack, top, ax, bx, ax_t, bx_t);
			estack_ax_v = v.u.s64;
			estack_ax_t = REG_S64;
			dbg_printf("ref get context s64 %" PRIi64 "\n", estack_ax_v);
			next_pc += sizeof(struct load_op) + sizeof(struct field_ref);
			PO;
		}

		OP(FILTER_OP_GET_CONTEXT_REF_DOUBLE):
		{
			struct load_op *insn = (struct load_op *) pc;
			struct field_ref *ref = (struct field_ref *) insn->data;
			struct lttng_ctx_field *ctx_field;
			struct lttng_ctx_value v;

			dbg_printf("get context ref offset %u type double\n",
				ref->offset);
			ctx_field = &ctx->fields[ref->offset];
			ctx_field->get_value(ctx_field, &v);
			estack_push(stack, top, ax, bx, ax_t, bx_t);
			memcpy(&estack_ax(stack, top)->u.d, &v.u.d, sizeof(struct literal_double));
			estack_ax_t = REG_DOUBLE;
			dbg_printf("ref get context double %g\n", estack_ax(stack, top)->u.d);
			next_pc += sizeof(struct load_op) + sizeof(struct field_ref);
			PO;
		}

		OP(FILTER_OP_GET_CONTEXT_ROOT):
		{
			dbg_printf("op get context root\n");
			estack_push(stack, top, ax, bx, ax_t, bx_t);
			estack_ax(stack, top)->u.ptr.type = LOAD_ROOT_CONTEXT;
			/* "field" only needed for variants. */
			estack_ax(stack, top)->u.ptr.field = NULL;
			estack_ax_t = REG_PTR;
			next_pc += sizeof(struct load_op);
			PO;
		}

		OP(FILTER_OP_GET_APP_CONTEXT_ROOT):
		{
			dbg_printf("op get app context root\n");
			estack_push(stack, top, ax, bx, ax_t, bx_t);
			estack_ax(stack, top)->u.ptr.type = LOAD_ROOT_APP_CONTEXT;
			/* "field" only needed for variants. */
			estack_ax(stack, top)->u.ptr.field = NULL;
			estack_ax_t = REG_PTR;
			next_pc += sizeof(struct load_op);
			PO;
		}

		OP(FILTER_OP_GET_PAYLOAD_ROOT):
		{
			dbg_printf("op get app payload root\n");
			estack_push(stack, top, ax, bx, ax_t, bx_t);
			estack_ax(stack, top)->u.ptr.type = LOAD_ROOT_PAYLOAD;
			estack_ax(stack, top)->u.ptr.ptr = filter_stack_data;
			/* "field" only needed for variants. */
			estack_ax(stack, top)->u.ptr.field = NULL;
			estack_ax_t = REG_PTR;
			next_pc += sizeof(struct load_op);
			PO;
		}

		OP(FILTER_OP_GET_SYMBOL):
		{
			dbg_printf("op get symbol\n");
			switch (estack_ax(stack, top)->u.ptr.type) {
			case LOAD_OBJECT:
				ERR("Nested fields not implemented yet.");
				ret = -EINVAL;
				goto end;
			case LOAD_ROOT_CONTEXT:
			case LOAD_ROOT_APP_CONTEXT:
			case LOAD_ROOT_PAYLOAD:
				/*
				 * symbol lookup is performed by
				 * specialization.
				 */
				ret = -EINVAL;
				goto end;
			}
			next_pc += sizeof(struct load_op) + sizeof(struct get_symbol);
			PO;
		}

		OP(FILTER_OP_GET_SYMBOL_FIELD):
		{
			/*
			 * Used for first variant encountered in a
			 * traversal. Variants are not implemented yet.
			 */
			ret = -EINVAL;
			goto end;
		}

		OP(FILTER_OP_GET_INDEX_U16):
		{
			struct load_op *insn = (struct load_op *) pc;
			struct get_index_u16 *index = (struct get_index_u16 *) insn->data;

			dbg_printf("op get index u16\n");
			ret = dynamic_get_index(ctx, bytecode, index->index, estack_ax(stack, top));
			if (ret)
				goto end;
			estack_ax_v = estack_ax(stack, top)->u.v;
			estack_ax_t = estack_ax(stack, top)->type;
			next_pc += sizeof(struct load_op) + sizeof(struct get_index_u16);
			PO;
		}

		OP(FILTER_OP_GET_INDEX_U64):
		{
			struct load_op *insn = (struct load_op *) pc;
			struct get_index_u64 *index = (struct get_index_u64 *) insn->data;

			dbg_printf("op get index u64\n");
			ret = dynamic_get_index(ctx, bytecode, index->index, estack_ax(stack, top));
			if (ret)
				goto end;
			estack_ax_v = estack_ax(stack, top)->u.v;
			estack_ax_t = estack_ax(stack, top)->type;
			next_pc += sizeof(struct load_op) + sizeof(struct get_index_u64);
			PO;
		}

		OP(FILTER_OP_LOAD_FIELD):
		{
			dbg_printf("op load field\n");
			ret = dynamic_load_field(estack_ax(stack, top));
			if (ret)
				goto end;
			estack_ax_v = estack_ax(stack, top)->u.v;
			estack_ax_t = estack_ax(stack, top)->type;
			next_pc += sizeof(struct load_op);
			PO;
		}

		OP(FILTER_OP_LOAD_FIELD_S8):
		{
			dbg_printf("op load field s8\n");

			estack_ax_v = *(int8_t *) estack_ax(stack, top)->u.ptr.ptr;
			estack_ax_t = REG_S64;
			next_pc += sizeof(struct load_op);
			PO;
		}
		OP(FILTER_OP_LOAD_FIELD_S16):
		{
			dbg_printf("op load field s16\n");

			estack_ax_v = *(int16_t *) estack_ax(stack, top)->u.ptr.ptr;
			estack_ax_t = REG_S64;
			next_pc += sizeof(struct load_op);
			PO;
		}
		OP(FILTER_OP_LOAD_FIELD_S32):
		{
			dbg_printf("op load field s32\n");

			estack_ax_v = *(int32_t *) estack_ax(stack, top)->u.ptr.ptr;
			estack_ax_t = REG_S64;
			next_pc += sizeof(struct load_op);
			PO;
		}
		OP(FILTER_OP_LOAD_FIELD_S64):
		{
			dbg_printf("op load field s64\n");

			estack_ax_v = *(int64_t *) estack_ax(stack, top)->u.ptr.ptr;
			estack_ax_t = REG_S64;
			next_pc += sizeof(struct load_op);
			PO;
		}
		OP(FILTER_OP_LOAD_FIELD_U8):
		{
			dbg_printf("op load field u8\n");

			estack_ax_v = *(uint8_t *) estack_ax(stack, top)->u.ptr.ptr;
			estack_ax_t = REG_U64;
			next_pc += sizeof(struct load_op);
			PO;
		}
		OP(FILTER_OP_LOAD_FIELD_U16):
		{
			dbg_printf("op load field u16\n");

			estack_ax_v = *(uint16_t *) estack_ax(stack, top)->u.ptr.ptr;
			estack_ax_t = REG_U64;
			next_pc += sizeof(struct load_op);
			PO;
		}
		OP(FILTER_OP_LOAD_FIELD_U32):
		{
			dbg_printf("op load field u32\n");

			estack_ax_v = *(uint32_t *) estack_ax(stack, top)->u.ptr.ptr;
			estack_ax_t = REG_U64;
			next_pc += sizeof(struct load_op);
			PO;
		}
		OP(FILTER_OP_LOAD_FIELD_U64):
		{
			dbg_printf("op load field u64\n");

			estack_ax_v = *(uint64_t *) estack_ax(stack, top)->u.ptr.ptr;
			estack_ax_t = REG_U64;
			next_pc += sizeof(struct load_op);
			PO;
		}
		OP(FILTER_OP_LOAD_FIELD_DOUBLE):
		{
			dbg_printf("op load field double\n");

			memcpy(&estack_ax(stack, top)->u.d,
				estack_ax(stack, top)->u.ptr.ptr,
				sizeof(struct literal_double));
			estack_ax(stack, top)->type = REG_DOUBLE;
			next_pc += sizeof(struct load_op);
			PO;
		}

		OP(FILTER_OP_LOAD_FIELD_STRING):
		{
			const char *str;

			dbg_printf("op load field string\n");
			str = (const char *) estack_ax(stack, top)->u.ptr.ptr;
			estack_ax(stack, top)->u.s.str = str;
			if (unlikely(!estack_ax(stack, top)->u.s.str)) {
				dbg_printf("Filter warning: loading a NULL string.\n");
				ret = -EINVAL;
				goto end;
			}
			estack_ax(stack, top)->u.s.seq_len = SIZE_MAX;
			estack_ax(stack, top)->u.s.literal_type =
				ESTACK_STRING_LITERAL_TYPE_NONE;
			estack_ax(stack, top)->type = REG_STRING;
			next_pc += sizeof(struct load_op);
			PO;
		}

		OP(FILTER_OP_LOAD_FIELD_SEQUENCE):
		{
			const char *ptr;

			dbg_printf("op load field string sequence\n");
			ptr = estack_ax(stack, top)->u.ptr.ptr;
			estack_ax(stack, top)->u.s.seq_len = *(unsigned long *) ptr;
			estack_ax(stack, top)->u.s.str = *(const char **) (ptr + sizeof(unsigned long));
			estack_ax(stack, top)->type = REG_STRING;
			if (unlikely(!estack_ax(stack, top)->u.s.str)) {
				dbg_printf("Filter warning: loading a NULL sequence.\n");
				ret = -EINVAL;
				goto end;
			}
			estack_ax(stack, top)->u.s.literal_type =
				ESTACK_STRING_LITERAL_TYPE_NONE;
			next_pc += sizeof(struct load_op);
			PO;
		}

	END_OP
end:
	/* Return _DISCARD on error. */
	if (ret)
		return LTTNG_FILTER_DISCARD;
	return retval;
}

#undef START_OP
#undef OP
#undef PO
#undef END_OP
