/*
 * SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2010-2016 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 *
 * LTTng UST bytecode code.
 */

#define _LGPL_SOURCE
#include <stddef.h>
#include <stdint.h>

#include <urcu/rculist.h>

#include "context-internal.h"
#include "lttng-bytecode.h"
#include "lib/lttng-ust/events.h"
#include "common/macros.h"
#include "common/tracer.h"

static const char *opnames[] = {
	[ BYTECODE_OP_UNKNOWN ] = "UNKNOWN",

	[ BYTECODE_OP_RETURN ] = "RETURN",

	/* binary */
	[ BYTECODE_OP_MUL ] = "MUL",
	[ BYTECODE_OP_DIV ] = "DIV",
	[ BYTECODE_OP_MOD ] = "MOD",
	[ BYTECODE_OP_PLUS ] = "PLUS",
	[ BYTECODE_OP_MINUS ] = "MINUS",
	[ BYTECODE_OP_BIT_RSHIFT ] = "BIT_RSHIFT",
	[ BYTECODE_OP_BIT_LSHIFT ] = "BIT_LSHIFT",
	[ BYTECODE_OP_BIT_AND ] = "BIT_AND",
	[ BYTECODE_OP_BIT_OR ] = "BIT_OR",
	[ BYTECODE_OP_BIT_XOR ] = "BIT_XOR",

	/* binary comparators */
	[ BYTECODE_OP_EQ ] = "EQ",
	[ BYTECODE_OP_NE ] = "NE",
	[ BYTECODE_OP_GT ] = "GT",
	[ BYTECODE_OP_LT ] = "LT",
	[ BYTECODE_OP_GE ] = "GE",
	[ BYTECODE_OP_LE ] = "LE",

	/* string binary comparators */
	[ BYTECODE_OP_EQ_STRING ] = "EQ_STRING",
	[ BYTECODE_OP_NE_STRING ] = "NE_STRING",
	[ BYTECODE_OP_GT_STRING ] = "GT_STRING",
	[ BYTECODE_OP_LT_STRING ] = "LT_STRING",
	[ BYTECODE_OP_GE_STRING ] = "GE_STRING",
	[ BYTECODE_OP_LE_STRING ] = "LE_STRING",

	/* s64 binary comparators */
	[ BYTECODE_OP_EQ_S64 ] = "EQ_S64",
	[ BYTECODE_OP_NE_S64 ] = "NE_S64",
	[ BYTECODE_OP_GT_S64 ] = "GT_S64",
	[ BYTECODE_OP_LT_S64 ] = "LT_S64",
	[ BYTECODE_OP_GE_S64 ] = "GE_S64",
	[ BYTECODE_OP_LE_S64 ] = "LE_S64",

	/* double binary comparators */
	[ BYTECODE_OP_EQ_DOUBLE ] = "EQ_DOUBLE",
	[ BYTECODE_OP_NE_DOUBLE ] = "NE_DOUBLE",
	[ BYTECODE_OP_GT_DOUBLE ] = "GT_DOUBLE",
	[ BYTECODE_OP_LT_DOUBLE ] = "LT_DOUBLE",
	[ BYTECODE_OP_GE_DOUBLE ] = "GE_DOUBLE",
	[ BYTECODE_OP_LE_DOUBLE ] = "LE_DOUBLE",

	/* Mixed S64-double binary comparators */
	[ BYTECODE_OP_EQ_DOUBLE_S64 ] = "EQ_DOUBLE_S64",
	[ BYTECODE_OP_NE_DOUBLE_S64 ] = "NE_DOUBLE_S64",
	[ BYTECODE_OP_GT_DOUBLE_S64 ] = "GT_DOUBLE_S64",
	[ BYTECODE_OP_LT_DOUBLE_S64 ] = "LT_DOUBLE_S64",
	[ BYTECODE_OP_GE_DOUBLE_S64 ] = "GE_DOUBLE_S64",
	[ BYTECODE_OP_LE_DOUBLE_S64 ] = "LE_DOUBLE_S64",

	[ BYTECODE_OP_EQ_S64_DOUBLE ] = "EQ_S64_DOUBLE",
	[ BYTECODE_OP_NE_S64_DOUBLE ] = "NE_S64_DOUBLE",
	[ BYTECODE_OP_GT_S64_DOUBLE ] = "GT_S64_DOUBLE",
	[ BYTECODE_OP_LT_S64_DOUBLE ] = "LT_S64_DOUBLE",
	[ BYTECODE_OP_GE_S64_DOUBLE ] = "GE_S64_DOUBLE",
	[ BYTECODE_OP_LE_S64_DOUBLE ] = "LE_S64_DOUBLE",

	/* unary */
	[ BYTECODE_OP_UNARY_PLUS ] = "UNARY_PLUS",
	[ BYTECODE_OP_UNARY_MINUS ] = "UNARY_MINUS",
	[ BYTECODE_OP_UNARY_NOT ] = "UNARY_NOT",
	[ BYTECODE_OP_UNARY_PLUS_S64 ] = "UNARY_PLUS_S64",
	[ BYTECODE_OP_UNARY_MINUS_S64 ] = "UNARY_MINUS_S64",
	[ BYTECODE_OP_UNARY_NOT_S64 ] = "UNARY_NOT_S64",
	[ BYTECODE_OP_UNARY_PLUS_DOUBLE ] = "UNARY_PLUS_DOUBLE",
	[ BYTECODE_OP_UNARY_MINUS_DOUBLE ] = "UNARY_MINUS_DOUBLE",
	[ BYTECODE_OP_UNARY_NOT_DOUBLE ] = "UNARY_NOT_DOUBLE",

	/* logical */
	[ BYTECODE_OP_AND ] = "AND",
	[ BYTECODE_OP_OR ] = "OR",

	/* load field ref */
	[ BYTECODE_OP_LOAD_FIELD_REF ] = "LOAD_FIELD_REF",
	[ BYTECODE_OP_LOAD_FIELD_REF_STRING ] = "LOAD_FIELD_REF_STRING",
	[ BYTECODE_OP_LOAD_FIELD_REF_SEQUENCE ] = "LOAD_FIELD_REF_SEQUENCE",
	[ BYTECODE_OP_LOAD_FIELD_REF_S64 ] = "LOAD_FIELD_REF_S64",
	[ BYTECODE_OP_LOAD_FIELD_REF_DOUBLE ] = "LOAD_FIELD_REF_DOUBLE",

	/* load from immediate operand */
	[ BYTECODE_OP_LOAD_STRING ] = "LOAD_STRING",
	[ BYTECODE_OP_LOAD_S64 ] = "LOAD_S64",
	[ BYTECODE_OP_LOAD_DOUBLE ] = "LOAD_DOUBLE",

	/* cast */
	[ BYTECODE_OP_CAST_TO_S64 ] = "CAST_TO_S64",
	[ BYTECODE_OP_CAST_DOUBLE_TO_S64 ] = "CAST_DOUBLE_TO_S64",
	[ BYTECODE_OP_CAST_NOP ] = "CAST_NOP",

	/* get context ref */
	[ BYTECODE_OP_GET_CONTEXT_REF ] = "GET_CONTEXT_REF",
	[ BYTECODE_OP_GET_CONTEXT_REF_STRING ] = "GET_CONTEXT_REF_STRING",
	[ BYTECODE_OP_GET_CONTEXT_REF_S64 ] = "GET_CONTEXT_REF_S64",
	[ BYTECODE_OP_GET_CONTEXT_REF_DOUBLE ] = "GET_CONTEXT_REF_DOUBLE",

	/* load userspace field ref */
	[ BYTECODE_OP_LOAD_FIELD_REF_USER_STRING ] = "LOAD_FIELD_REF_USER_STRING",
	[ BYTECODE_OP_LOAD_FIELD_REF_USER_SEQUENCE ] = "LOAD_FIELD_REF_USER_SEQUENCE",

	/*
	 * load immediate star globbing pattern (literal string)
	 * from immediate.
	 */
	[ BYTECODE_OP_LOAD_STAR_GLOB_STRING ] = "LOAD_STAR_GLOB_STRING",

	/* globbing pattern binary operator: apply to */
	[ BYTECODE_OP_EQ_STAR_GLOB_STRING ] = "EQ_STAR_GLOB_STRING",
	[ BYTECODE_OP_NE_STAR_GLOB_STRING ] = "NE_STAR_GLOB_STRING",

	/*
	 * Instructions for recursive traversal through composed types.
	 */
	[ BYTECODE_OP_GET_CONTEXT_ROOT ] = "GET_CONTEXT_ROOT",
	[ BYTECODE_OP_GET_APP_CONTEXT_ROOT ] = "GET_APP_CONTEXT_ROOT",
	[ BYTECODE_OP_GET_PAYLOAD_ROOT ] = "GET_PAYLOAD_ROOT",

	[ BYTECODE_OP_GET_SYMBOL ] = "GET_SYMBOL",
	[ BYTECODE_OP_GET_SYMBOL_FIELD ] = "GET_SYMBOL_FIELD",
	[ BYTECODE_OP_GET_INDEX_U16 ] = "GET_INDEX_U16",
	[ BYTECODE_OP_GET_INDEX_U64 ] = "GET_INDEX_U64",

	[ BYTECODE_OP_LOAD_FIELD ] = "LOAD_FIELD",
	[ BYTECODE_OP_LOAD_FIELD_S8 ] = "LOAD_FIELD_S8",
	[ BYTECODE_OP_LOAD_FIELD_S16 ] = "LOAD_FIELD_S16",
	[ BYTECODE_OP_LOAD_FIELD_S32 ] = "LOAD_FIELD_S32",
	[ BYTECODE_OP_LOAD_FIELD_S64 ] = "LOAD_FIELD_S64",
	[ BYTECODE_OP_LOAD_FIELD_U8 ] = "LOAD_FIELD_U8",
	[ BYTECODE_OP_LOAD_FIELD_U16 ] = "LOAD_FIELD_U16",
	[ BYTECODE_OP_LOAD_FIELD_U32 ] = "LOAD_FIELD_U32",
	[ BYTECODE_OP_LOAD_FIELD_U64 ] = "LOAD_FIELD_U64",
	[ BYTECODE_OP_LOAD_FIELD_STRING ] = "LOAD_FIELD_STRING",
	[ BYTECODE_OP_LOAD_FIELD_SEQUENCE ] = "LOAD_FIELD_SEQUENCE",
	[ BYTECODE_OP_LOAD_FIELD_DOUBLE ] = "LOAD_FIELD_DOUBLE",

	[ BYTECODE_OP_UNARY_BIT_NOT ] = "UNARY_BIT_NOT",

	[ BYTECODE_OP_RETURN_S64 ] = "RETURN_S64",
};

const char *lttng_bytecode_print_op(enum bytecode_op op)
{
	if (op >= NR_BYTECODE_OPS)
		return "UNKNOWN";
	else
		return opnames[op];
}

static
int apply_field_reloc(const struct lttng_ust_event_desc *event_desc,
		struct bytecode_runtime *runtime,
		uint32_t runtime_len __attribute__((unused)),
		uint32_t reloc_offset,
		const char *field_name,
		enum bytecode_op bytecode_op)
{
	const struct lttng_ust_event_field * const *fields, *field = NULL;
	unsigned int nr_fields, i;
	struct load_op *op;
	uint32_t field_offset = 0;

	dbg_printf("Apply field reloc: %u %s\n", reloc_offset, field_name);

	/* Lookup event by name */
	if (!event_desc)
		return -EINVAL;
	fields = event_desc->tp_class->fields;
	if (!fields)
		return -EINVAL;
	nr_fields = event_desc->tp_class->nr_fields;
	for (i = 0; i < nr_fields; i++) {
		if (fields[i]->nofilter) {
			continue;
		}
		if (!strcmp(fields[i]->name, field_name)) {
			field = fields[i];
			break;
		}
		/* compute field offset */
		switch (fields[i]->type->type) {
		case lttng_ust_type_integer:
		case lttng_ust_type_enum:
			field_offset += sizeof(int64_t);
			break;
		case lttng_ust_type_array:
		case lttng_ust_type_sequence:
			field_offset += sizeof(unsigned long);
			field_offset += sizeof(void *);
			break;
		case lttng_ust_type_string:
			field_offset += sizeof(void *);
			break;
		case lttng_ust_type_float:
			field_offset += sizeof(double);
			break;
		default:
			return -EINVAL;
		}
	}
	if (!field)
		return -EINVAL;

	/* Check if field offset is too large for 16-bit offset */
	if (field_offset > LTTNG_UST_ABI_FILTER_BYTECODE_MAX_LEN - 1)
		return -EINVAL;

	/* set type */
	op = (struct load_op *) &runtime->code[reloc_offset];

	switch (bytecode_op) {
	case BYTECODE_OP_LOAD_FIELD_REF:
	{
		struct field_ref *field_ref;

		field_ref = (struct field_ref *) op->data;
		switch (field->type->type) {
		case lttng_ust_type_integer:
		case lttng_ust_type_enum:
			op->op = BYTECODE_OP_LOAD_FIELD_REF_S64;
			break;
		case lttng_ust_type_array:
		{
			struct lttng_ust_type_array *array = (struct lttng_ust_type_array *) field->type;

			if (array->encoding == lttng_ust_string_encoding_none)
				return -EINVAL;
			op->op = BYTECODE_OP_LOAD_FIELD_REF_SEQUENCE;
			break;
		}
		case lttng_ust_type_sequence:
		{
			struct lttng_ust_type_sequence *sequence = (struct lttng_ust_type_sequence *) field->type;

			if (sequence->encoding == lttng_ust_string_encoding_none)
				return -EINVAL;
			op->op = BYTECODE_OP_LOAD_FIELD_REF_SEQUENCE;
			break;
		}
		case lttng_ust_type_string:
			op->op = BYTECODE_OP_LOAD_FIELD_REF_STRING;
			break;
		case lttng_ust_type_float:
			op->op = BYTECODE_OP_LOAD_FIELD_REF_DOUBLE;
			break;
		default:
			return -EINVAL;
		}
		/* set offset */
		field_ref->offset = (uint16_t) field_offset;
		break;
	}
	default:
		return -EINVAL;
	}
	return 0;
}

static
int apply_context_reloc(struct bytecode_runtime *runtime,
		uint32_t runtime_len __attribute__((unused)),
		uint32_t reloc_offset,
		const char *context_name,
		enum bytecode_op bytecode_op)
{
	struct load_op *op;
	const struct lttng_ust_ctx_field *ctx_field;
	int idx;
	struct lttng_ust_ctx **pctx = runtime->p.pctx;

	dbg_printf("Apply context reloc: %u %s\n", reloc_offset, context_name);

	/* Get context index */
	idx = lttng_get_context_index(*pctx, context_name);
	if (idx < 0) {
		if (lttng_context_is_app(context_name)) {
			int ret;

			ret = lttng_ust_add_app_context_to_ctx_rcu(context_name,
					pctx);
			if (ret)
				return ret;
			idx = lttng_get_context_index(*pctx, context_name);
			if (idx < 0)
				return -ENOENT;
		} else {
			return -ENOENT;
		}
	}
	/* Check if idx is too large for 16-bit offset */
	if (idx > LTTNG_UST_ABI_FILTER_BYTECODE_MAX_LEN - 1)
		return -EINVAL;

	/* Get context return type */
	ctx_field = &(*pctx)->fields[idx];
	op = (struct load_op *) &runtime->code[reloc_offset];

	switch (bytecode_op) {
	case BYTECODE_OP_GET_CONTEXT_REF:
	{
		struct field_ref *field_ref;

		field_ref = (struct field_ref *) op->data;
		switch (ctx_field->event_field->type->type) {
		case lttng_ust_type_integer:
		case lttng_ust_type_enum:
			op->op = BYTECODE_OP_GET_CONTEXT_REF_S64;
			break;
			/* Sequence and array supported only as string */
		case lttng_ust_type_array:
		{
			struct lttng_ust_type_array *array = (struct lttng_ust_type_array *) ctx_field->event_field->type;

			if (array->encoding == lttng_ust_string_encoding_none)
				return -EINVAL;
			op->op = BYTECODE_OP_GET_CONTEXT_REF_STRING;
			break;
		}
		case lttng_ust_type_sequence:
		{
			struct lttng_ust_type_sequence *sequence = (struct lttng_ust_type_sequence *) ctx_field->event_field->type;

			if (sequence->encoding == lttng_ust_string_encoding_none)
				return -EINVAL;
			op->op = BYTECODE_OP_GET_CONTEXT_REF_STRING;
			break;
		}
		case lttng_ust_type_string:
			op->op = BYTECODE_OP_GET_CONTEXT_REF_STRING;
			break;
		case lttng_ust_type_float:
			op->op = BYTECODE_OP_GET_CONTEXT_REF_DOUBLE;
			break;
		case lttng_ust_type_dynamic:
			op->op = BYTECODE_OP_GET_CONTEXT_REF;
			break;
		default:
			return -EINVAL;
		}
		/* set offset to context index within channel contexts */
		field_ref->offset = (uint16_t) idx;
		break;
	}
	default:
		return -EINVAL;
	}
	return 0;
}

static
int apply_reloc(const struct lttng_ust_event_desc *event_desc,
		struct bytecode_runtime *runtime,
		uint32_t runtime_len,
		uint32_t reloc_offset,
		const char *name)
{
	struct load_op *op;

	dbg_printf("Apply reloc: %u %s\n", reloc_offset, name);

	/* Ensure that the reloc is within the code */
	if (runtime_len - reloc_offset < sizeof(uint16_t))
		return -EINVAL;

	op = (struct load_op *) &runtime->code[reloc_offset];
	switch (op->op) {
	case BYTECODE_OP_LOAD_FIELD_REF:
		return apply_field_reloc(event_desc, runtime, runtime_len,
			reloc_offset, name, op->op);
	case BYTECODE_OP_GET_CONTEXT_REF:
		return apply_context_reloc(runtime, runtime_len,
			reloc_offset, name, op->op);
	case BYTECODE_OP_GET_SYMBOL:
	case BYTECODE_OP_GET_SYMBOL_FIELD:
		/*
		 * Will be handled by load specialize phase or
		 * dynamically by interpreter.
		 */
		return 0;
	default:
		ERR("Unknown reloc op type %u\n", op->op);
		return -EINVAL;
	}
	return 0;
}

static
int bytecode_is_linked(struct lttng_ust_bytecode_node *bytecode,
		struct cds_list_head *bytecode_runtime_head)
{
	struct lttng_ust_bytecode_runtime *bc_runtime;

	cds_list_for_each_entry(bc_runtime, bytecode_runtime_head, node) {
		if (bc_runtime->bc == bytecode)
			return 1;
	}
	return 0;
}

/*
 * Take a bytecode with reloc table and link it to an event to create a
 * bytecode runtime.
 */
static
int link_bytecode(const struct lttng_ust_event_desc *event_desc,
		struct lttng_ust_ctx **ctx,
		struct lttng_ust_bytecode_node *bytecode,
		struct cds_list_head *bytecode_runtime_head,
		struct cds_list_head *insert_loc)
{
	int ret, offset, next_offset;
	struct bytecode_runtime *runtime = NULL;
	size_t runtime_alloc_len;

	if (!bytecode)
		return 0;
	/* Bytecode already linked */
	if (bytecode_is_linked(bytecode, bytecode_runtime_head))
		return 0;

	dbg_printf("Linking...\n");

	/* We don't need the reloc table in the runtime */
	runtime_alloc_len = sizeof(*runtime) + bytecode->bc.reloc_offset;
	runtime = zmalloc(runtime_alloc_len);
	if (!runtime) {
		ret = -ENOMEM;
		goto alloc_error;
	}
	runtime->p.type = bytecode->type;
	runtime->p.bc = bytecode;
	runtime->p.pctx = ctx;
	runtime->len = bytecode->bc.reloc_offset;
	/* copy original bytecode */
	memcpy(runtime->code, bytecode->bc.data, runtime->len);
	/* Validate bytecode load instructions before relocs. */
	ret = lttng_bytecode_validate_load(runtime);
	if (ret) {
		goto link_error;
	}
	/*
	 * apply relocs. Those are a uint16_t (offset in bytecode)
	 * followed by a string (field name).
	 */
	for (offset = bytecode->bc.reloc_offset;
			offset < bytecode->bc.len;
			offset = next_offset) {
		uint16_t reloc_offset =
			*(uint16_t *) &bytecode->bc.data[offset];
		const char *name =
			(const char *) &bytecode->bc.data[offset + sizeof(uint16_t)];

		ret = apply_reloc(event_desc, runtime, runtime->len, reloc_offset, name);
		if (ret) {
			goto link_error;
		}
		next_offset = offset + sizeof(uint16_t) + strlen(name) + 1;
	}
	/* Validate bytecode */
	ret = lttng_bytecode_validate(runtime);
	if (ret) {
		goto link_error;
	}
	/* Specialize bytecode */
	ret = lttng_bytecode_specialize(event_desc, runtime);
	if (ret) {
		goto link_error;
	}

	runtime->p.interpreter_func = lttng_bytecode_interpret;
	runtime->p.link_failed = 0;
	cds_list_add_rcu(&runtime->p.node, insert_loc);
	dbg_printf("Linking successful.\n");
	return 0;

link_error:
	runtime->p.interpreter_func = lttng_bytecode_interpret_error;
	runtime->p.link_failed = 1;
	cds_list_add_rcu(&runtime->p.node, insert_loc);
alloc_error:
	dbg_printf("Linking failed.\n");
	return ret;
}

void lttng_bytecode_sync_state(struct lttng_ust_bytecode_runtime *runtime)
{
	struct lttng_ust_bytecode_node *bc = runtime->bc;

	if (!bc->enabler->enabled || runtime->link_failed)
		runtime->interpreter_func = lttng_bytecode_interpret_error;
	else
		runtime->interpreter_func = lttng_bytecode_interpret;
}

/*
 * Given the lists of bytecode programs of an instance (trigger or event) and
 * of a matching enabler, try to link all the enabler's bytecode programs with
 * the instance.
 *
 * This function is called after we confirmed that name enabler and the
 * instance are name matching (or glob pattern matching).
 */
void lttng_enabler_link_bytecode(const struct lttng_ust_event_desc *event_desc,
		struct lttng_ust_ctx **ctx,
		struct cds_list_head *instance_bytecode_head,
		struct cds_list_head *enabler_bytecode_head)
{
	struct lttng_ust_bytecode_node *enabler_bc;
	struct lttng_ust_bytecode_runtime *runtime;

	assert(event_desc);

	/* Go over all the bytecode programs of the enabler. */
	cds_list_for_each_entry(enabler_bc, enabler_bytecode_head, node) {
		int found = 0, ret;
		struct cds_list_head *insert_loc;

		/*
		 * Check if the current enabler bytecode program is already
		 * linked with the instance.
		 */
		cds_list_for_each_entry(runtime, instance_bytecode_head, node) {
			if (runtime->bc == enabler_bc) {
				found = 1;
				break;
			}
		}

		/*
		 * Skip bytecode already linked, go to the next enabler
		 * bytecode program.
		 */
		if (found)
			continue;

		/*
		 * Insert at specified priority (seqnum) in increasing
		 * order. If there already is a bytecode of the same priority,
		 * insert the new bytecode right after it.
		 */
		cds_list_for_each_entry_reverse(runtime,
				instance_bytecode_head, node) {
			if (runtime->bc->bc.seqnum <= enabler_bc->bc.seqnum) {
				/* insert here */
				insert_loc = &runtime->node;
				goto add_within;
			}
		}

		/* Add to head to list */
		insert_loc = instance_bytecode_head;
	add_within:
		dbg_printf("linking bytecode\n");
		ret = link_bytecode(event_desc, ctx, enabler_bc, instance_bytecode_head, insert_loc);
		if (ret) {
			dbg_printf("[lttng filter] warning: cannot link event bytecode\n");
		}
	}
}

static
void free_filter_runtime(struct cds_list_head *bytecode_runtime_head)
{
	struct bytecode_runtime *runtime, *tmp;

	cds_list_for_each_entry_safe(runtime, tmp, bytecode_runtime_head,
			p.node) {
		free(runtime->data);
		free(runtime);
	}
}

void lttng_free_event_filter_runtime(struct lttng_ust_event_common *event)
{
	free_filter_runtime(&event->priv->filter_bytecode_runtime_head);
}
