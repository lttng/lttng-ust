/*
 * SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2010-2016 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 *
 * LTTng UST bytecode validator.
 */

#define _LGPL_SOURCE
#include <stddef.h>
#include <stdint.h>
#include <time.h>

#include "rculfhash.h"

#include "lttng-bytecode.h"
#include "common/hash.h"
#include "common/strutils.h"
#include "lib/lttng-ust/events.h"
#include "common/macros.h"

/*
 * Number of merge points for hash table size. Hash table initialized to
 * that size, and we do not resize, because we do not want to trigger
 * RCU worker thread execution: fall-back on linear traversal if number
 * of merge points exceeds this value.
 */
#define DEFAULT_NR_MERGE_POINTS		128
#define MIN_NR_BUCKETS			128
#define MAX_NR_BUCKETS			128

/* merge point table node */
struct lfht_mp_node {
	struct lttng_ust_lfht_node node;

	/* Context at merge point */
	struct vstack stack;
	unsigned long target_pc;
};

static unsigned long lttng_hash_seed;
static unsigned int lttng_hash_seed_ready;

static
int lttng_hash_match(struct lttng_ust_lfht_node *node, const void *key)
{
	struct lfht_mp_node *mp_node =
		caa_container_of(node, struct lfht_mp_node, node);
	unsigned long key_pc = (unsigned long) key;

	if (mp_node->target_pc == key_pc)
		return 1;
	else
		return 0;
}

static
int merge_points_compare(const struct vstack *stacka,
			const struct vstack *stackb)
{
	int i, len;

	if (stacka->top != stackb->top)
		return 1;
	len = stacka->top + 1;
	assert(len >= 0);
	for (i = 0; i < len; i++) {
		if (stacka->e[i].type != REG_UNKNOWN
				&& stackb->e[i].type != REG_UNKNOWN
				&& stacka->e[i].type != stackb->e[i].type)
			return 1;
	}
	return 0;
}

static
int merge_point_add_check(struct lttng_ust_lfht *ht, unsigned long target_pc,
		const struct vstack *stack)
{
	struct lfht_mp_node *node;
	unsigned long hash = lttng_hash_mix((const char *) target_pc,
				sizeof(target_pc),
				lttng_hash_seed);
	struct lttng_ust_lfht_node *ret;

	dbg_printf("Bytecode: adding merge point at offset %lu, hash %lu\n",
			target_pc, hash);
	node = zmalloc(sizeof(struct lfht_mp_node));
	if (!node)
		return -ENOMEM;
	node->target_pc = target_pc;
	memcpy(&node->stack, stack, sizeof(node->stack));
	ret = lttng_ust_lfht_add_unique(ht, hash, lttng_hash_match,
		(const char *) target_pc, &node->node);
	if (ret != &node->node) {
		struct lfht_mp_node *ret_mp =
			caa_container_of(ret, struct lfht_mp_node, node);

		/* Key already present */
		dbg_printf("Bytecode: compare merge points for offset %lu, hash %lu\n",
				target_pc, hash);
		free(node);
		if (merge_points_compare(stack, &ret_mp->stack)) {
			ERR("Merge points differ for offset %lu\n",
				target_pc);
			return -EINVAL;
		}
	}
	return 0;
}

/*
 * Binary comparators use top of stack and top of stack -1.
 * Return 0 if typing is known to match, 1 if typing is dynamic
 * (unknown), negative error value on error.
 */
static
int bin_op_compare_check(struct vstack *stack, bytecode_opcode_t opcode,
		const char *str)
{
	if (unlikely(!vstack_ax(stack) || !vstack_bx(stack)))
		goto error_empty;

	switch (vstack_ax(stack)->type) {
	default:
		goto error_type;

	case REG_UNKNOWN:
		goto unknown;
	case REG_STRING:
		switch (vstack_bx(stack)->type) {
		default:
			goto error_type;

		case REG_UNKNOWN:
			goto unknown;
		case REG_STRING:
			break;
		case REG_STAR_GLOB_STRING:
			if (opcode != BYTECODE_OP_EQ && opcode != BYTECODE_OP_NE) {
				goto error_mismatch;
			}
			break;
		case REG_S64:
		case REG_U64:
		case REG_DOUBLE:
			goto error_mismatch;
		}
		break;
	case REG_STAR_GLOB_STRING:
		switch (vstack_bx(stack)->type) {
		default:
			goto error_type;

		case REG_UNKNOWN:
			goto unknown;
		case REG_STRING:
			if (opcode != BYTECODE_OP_EQ && opcode != BYTECODE_OP_NE) {
				goto error_mismatch;
			}
			break;
		case REG_STAR_GLOB_STRING:
		case REG_S64:
		case REG_U64:
		case REG_DOUBLE:
			goto error_mismatch;
		}
		break;
	case REG_S64:
	case REG_U64:
	case REG_DOUBLE:
		switch (vstack_bx(stack)->type) {
		default:
			goto error_type;

		case REG_UNKNOWN:
			goto unknown;
		case REG_STRING:
		case REG_STAR_GLOB_STRING:
			goto error_mismatch;
		case REG_S64:
		case REG_U64:
		case REG_DOUBLE:
			break;
		}
		break;
	}
	return 0;

unknown:
	return 1;

error_mismatch:
	ERR("type mismatch for '%s' binary operator\n", str);
	return -EINVAL;

error_empty:
	ERR("empty stack for '%s' binary operator\n", str);
	return -EINVAL;

error_type:
	ERR("unknown type for '%s' binary operator\n", str);
	return -EINVAL;
}

/*
 * Binary bitwise operators use top of stack and top of stack -1.
 * Return 0 if typing is known to match, 1 if typing is dynamic
 * (unknown), negative error value on error.
 */
static
int bin_op_bitwise_check(struct vstack *stack,
		bytecode_opcode_t opcode __attribute__((unused)),
		const char *str)
{
	if (unlikely(!vstack_ax(stack) || !vstack_bx(stack)))
		goto error_empty;

	switch (vstack_ax(stack)->type) {
	default:
		goto error_type;

	case REG_UNKNOWN:
		goto unknown;
	case REG_S64:
	case REG_U64:
		switch (vstack_bx(stack)->type) {
		default:
			goto error_type;

		case REG_UNKNOWN:
			goto unknown;
		case REG_S64:
		case REG_U64:
			break;
		}
		break;
	}
	return 0;

unknown:
	return 1;

error_empty:
	ERR("empty stack for '%s' binary operator\n", str);
	return -EINVAL;

error_type:
	ERR("unknown type for '%s' binary operator\n", str);
	return -EINVAL;
}

static
int validate_get_symbol(struct bytecode_runtime *bytecode,
		const struct get_symbol *sym)
{
	const char *str, *str_limit;
	size_t len_limit;

	if (sym->offset >= bytecode->p.bc->bc.len - bytecode->p.bc->bc.reloc_offset)
		return -EINVAL;

	str = bytecode->p.bc->bc.data + bytecode->p.bc->bc.reloc_offset + sym->offset;
	str_limit = bytecode->p.bc->bc.data + bytecode->p.bc->bc.len;
	len_limit = str_limit - str;
	if (strnlen(str, len_limit) == len_limit)
		return -EINVAL;
	return 0;
}

/*
 * Validate bytecode range overflow within the validation pass.
 * Called for each instruction encountered.
 */
static
int bytecode_validate_overflow(struct bytecode_runtime *bytecode,
		char *start_pc, char *pc)
{
	int ret = 0;

	switch (*(bytecode_opcode_t *) pc) {
	case BYTECODE_OP_UNKNOWN:
	default:
	{
		ERR("unknown bytecode op %u\n",
			(unsigned int) *(bytecode_opcode_t *) pc);
		ret = -EINVAL;
		break;
	}

	case BYTECODE_OP_RETURN:
	case BYTECODE_OP_RETURN_S64:
	{
		if (unlikely(pc + sizeof(struct return_op)
				> start_pc + bytecode->len)) {
			ret = -ERANGE;
		}
		break;
	}

	/* binary */
	case BYTECODE_OP_MUL:
	case BYTECODE_OP_DIV:
	case BYTECODE_OP_MOD:
	case BYTECODE_OP_PLUS:
	case BYTECODE_OP_MINUS:
	{
		ERR("unsupported bytecode op %u\n",
			(unsigned int) *(bytecode_opcode_t *) pc);
		ret = -EINVAL;
		break;
	}

	case BYTECODE_OP_EQ:
	case BYTECODE_OP_NE:
	case BYTECODE_OP_GT:
	case BYTECODE_OP_LT:
	case BYTECODE_OP_GE:
	case BYTECODE_OP_LE:
	case BYTECODE_OP_EQ_STRING:
	case BYTECODE_OP_NE_STRING:
	case BYTECODE_OP_GT_STRING:
	case BYTECODE_OP_LT_STRING:
	case BYTECODE_OP_GE_STRING:
	case BYTECODE_OP_LE_STRING:
	case BYTECODE_OP_EQ_STAR_GLOB_STRING:
	case BYTECODE_OP_NE_STAR_GLOB_STRING:
	case BYTECODE_OP_EQ_S64:
	case BYTECODE_OP_NE_S64:
	case BYTECODE_OP_GT_S64:
	case BYTECODE_OP_LT_S64:
	case BYTECODE_OP_GE_S64:
	case BYTECODE_OP_LE_S64:
	case BYTECODE_OP_EQ_DOUBLE:
	case BYTECODE_OP_NE_DOUBLE:
	case BYTECODE_OP_GT_DOUBLE:
	case BYTECODE_OP_LT_DOUBLE:
	case BYTECODE_OP_GE_DOUBLE:
	case BYTECODE_OP_LE_DOUBLE:
	case BYTECODE_OP_EQ_DOUBLE_S64:
	case BYTECODE_OP_NE_DOUBLE_S64:
	case BYTECODE_OP_GT_DOUBLE_S64:
	case BYTECODE_OP_LT_DOUBLE_S64:
	case BYTECODE_OP_GE_DOUBLE_S64:
	case BYTECODE_OP_LE_DOUBLE_S64:
	case BYTECODE_OP_EQ_S64_DOUBLE:
	case BYTECODE_OP_NE_S64_DOUBLE:
	case BYTECODE_OP_GT_S64_DOUBLE:
	case BYTECODE_OP_LT_S64_DOUBLE:
	case BYTECODE_OP_GE_S64_DOUBLE:
	case BYTECODE_OP_LE_S64_DOUBLE:
	case BYTECODE_OP_BIT_RSHIFT:
	case BYTECODE_OP_BIT_LSHIFT:
	case BYTECODE_OP_BIT_AND:
	case BYTECODE_OP_BIT_OR:
	case BYTECODE_OP_BIT_XOR:
	{
		if (unlikely(pc + sizeof(struct binary_op)
				> start_pc + bytecode->len)) {
			ret = -ERANGE;
		}
		break;
	}

	/* unary */
	case BYTECODE_OP_UNARY_PLUS:
	case BYTECODE_OP_UNARY_MINUS:
	case BYTECODE_OP_UNARY_NOT:
	case BYTECODE_OP_UNARY_PLUS_S64:
	case BYTECODE_OP_UNARY_MINUS_S64:
	case BYTECODE_OP_UNARY_NOT_S64:
	case BYTECODE_OP_UNARY_PLUS_DOUBLE:
	case BYTECODE_OP_UNARY_MINUS_DOUBLE:
	case BYTECODE_OP_UNARY_NOT_DOUBLE:
	case BYTECODE_OP_UNARY_BIT_NOT:
	{
		if (unlikely(pc + sizeof(struct unary_op)
				> start_pc + bytecode->len)) {
			ret = -ERANGE;
		}
		break;
	}

	/* logical */
	case BYTECODE_OP_AND:
	case BYTECODE_OP_OR:
	{
		if (unlikely(pc + sizeof(struct logical_op)
				> start_pc + bytecode->len)) {
			ret = -ERANGE;
		}
		break;
	}

	/* load field and get context ref */
	case BYTECODE_OP_LOAD_FIELD_REF:
	case BYTECODE_OP_GET_CONTEXT_REF:
	case BYTECODE_OP_LOAD_FIELD_REF_STRING:
	case BYTECODE_OP_LOAD_FIELD_REF_SEQUENCE:
	case BYTECODE_OP_LOAD_FIELD_REF_S64:
	case BYTECODE_OP_LOAD_FIELD_REF_DOUBLE:
	case BYTECODE_OP_GET_CONTEXT_REF_STRING:
	case BYTECODE_OP_GET_CONTEXT_REF_S64:
	case BYTECODE_OP_GET_CONTEXT_REF_DOUBLE:
	{
		if (unlikely(pc + sizeof(struct load_op) + sizeof(struct field_ref)
				> start_pc + bytecode->len)) {
			ret = -ERANGE;
		}
		break;
	}

	/* load from immediate operand */
	case BYTECODE_OP_LOAD_STRING:
	case BYTECODE_OP_LOAD_STAR_GLOB_STRING:
	{
		struct load_op *insn = (struct load_op *) pc;
		uint32_t str_len, maxlen;

		if (unlikely(pc + sizeof(struct load_op)
				> start_pc + bytecode->len)) {
			ret = -ERANGE;
			break;
		}

		maxlen = start_pc + bytecode->len - pc - sizeof(struct load_op);
		str_len = strnlen(insn->data, maxlen);
		if (unlikely(str_len >= maxlen)) {
			/* Final '\0' not found within range */
			ret = -ERANGE;
		}
		break;
	}

	case BYTECODE_OP_LOAD_S64:
	{
		if (unlikely(pc + sizeof(struct load_op) + sizeof(struct literal_numeric)
				> start_pc + bytecode->len)) {
			ret = -ERANGE;
		}
		break;
	}

	case BYTECODE_OP_LOAD_DOUBLE:
	{
		if (unlikely(pc + sizeof(struct load_op) + sizeof(struct literal_double)
				> start_pc + bytecode->len)) {
			ret = -ERANGE;
		}
		break;
	}

	case BYTECODE_OP_CAST_TO_S64:
	case BYTECODE_OP_CAST_DOUBLE_TO_S64:
	case BYTECODE_OP_CAST_NOP:
	{
		if (unlikely(pc + sizeof(struct cast_op)
				> start_pc + bytecode->len)) {
			ret = -ERANGE;
		}
		break;
	}

	/*
	 * Instructions for recursive traversal through composed types.
	 */
	case BYTECODE_OP_GET_CONTEXT_ROOT:
	case BYTECODE_OP_GET_APP_CONTEXT_ROOT:
	case BYTECODE_OP_GET_PAYLOAD_ROOT:
	case BYTECODE_OP_LOAD_FIELD:
	case BYTECODE_OP_LOAD_FIELD_S8:
	case BYTECODE_OP_LOAD_FIELD_S16:
	case BYTECODE_OP_LOAD_FIELD_S32:
	case BYTECODE_OP_LOAD_FIELD_S64:
	case BYTECODE_OP_LOAD_FIELD_U8:
	case BYTECODE_OP_LOAD_FIELD_U16:
	case BYTECODE_OP_LOAD_FIELD_U32:
	case BYTECODE_OP_LOAD_FIELD_U64:
	case BYTECODE_OP_LOAD_FIELD_STRING:
	case BYTECODE_OP_LOAD_FIELD_SEQUENCE:
	case BYTECODE_OP_LOAD_FIELD_DOUBLE:
		if (unlikely(pc + sizeof(struct load_op)
				> start_pc + bytecode->len)) {
			ret = -ERANGE;
		}
		break;

	case BYTECODE_OP_GET_SYMBOL:
	{
		struct load_op *insn = (struct load_op *) pc;
		struct get_symbol *sym = (struct get_symbol *) insn->data;

		if (unlikely(pc + sizeof(struct load_op) + sizeof(struct get_symbol)
				> start_pc + bytecode->len)) {
			ret = -ERANGE;
			break;
		}
		ret = validate_get_symbol(bytecode, sym);
		break;
	}

	case BYTECODE_OP_GET_SYMBOL_FIELD:
		ERR("Unexpected get symbol field");
		ret = -EINVAL;
		break;

	case BYTECODE_OP_GET_INDEX_U16:
		if (unlikely(pc + sizeof(struct load_op) + sizeof(struct get_index_u16)
				> start_pc + bytecode->len)) {
			ret = -ERANGE;
		}
		break;

	case BYTECODE_OP_GET_INDEX_U64:
		if (unlikely(pc + sizeof(struct load_op) + sizeof(struct get_index_u64)
				> start_pc + bytecode->len)) {
			ret = -ERANGE;
		}
		break;
	}

	return ret;
}

static
unsigned long delete_all_nodes(struct lttng_ust_lfht *ht)
{
	struct lttng_ust_lfht_iter iter;
	struct lfht_mp_node *node;
	unsigned long nr_nodes = 0;

	lttng_ust_lfht_for_each_entry(ht, &iter, node, node) {
		int ret;

		ret = lttng_ust_lfht_del(ht, lttng_ust_lfht_iter_get_node(&iter));
		assert(!ret);
		/* note: this hash table is never used concurrently */
		free(node);
		nr_nodes++;
	}
	return nr_nodes;
}

/*
 * Return value:
 * >=0: success
 * <0: error
 */
static
int validate_instruction_context(
		struct bytecode_runtime *bytecode __attribute__((unused)),
		struct vstack *stack,
		char *start_pc,
		char *pc)
{
	int ret = 0;
	const bytecode_opcode_t opcode = *(bytecode_opcode_t *) pc;

	switch (opcode) {
	case BYTECODE_OP_UNKNOWN:
	default:
	{
		ERR("unknown bytecode op %u\n",
			(unsigned int) *(bytecode_opcode_t *) pc);
		ret = -EINVAL;
		goto end;
	}

	case BYTECODE_OP_RETURN:
	case BYTECODE_OP_RETURN_S64:
	{
		goto end;
	}

	/* binary */
	case BYTECODE_OP_MUL:
	case BYTECODE_OP_DIV:
	case BYTECODE_OP_MOD:
	case BYTECODE_OP_PLUS:
	case BYTECODE_OP_MINUS:
	{
		ERR("unsupported bytecode op %u\n",
			(unsigned int) opcode);
		ret = -EINVAL;
		goto end;
	}

	case BYTECODE_OP_EQ:
	{
		ret = bin_op_compare_check(stack, opcode, "==");
		if (ret < 0)
			goto end;
		break;
	}
	case BYTECODE_OP_NE:
	{
		ret = bin_op_compare_check(stack, opcode, "!=");
		if (ret < 0)
			goto end;
		break;
	}
	case BYTECODE_OP_GT:
	{
		ret = bin_op_compare_check(stack, opcode, ">");
		if (ret < 0)
			goto end;
		break;
	}
	case BYTECODE_OP_LT:
	{
		ret = bin_op_compare_check(stack, opcode, "<");
		if (ret < 0)
			goto end;
		break;
	}
	case BYTECODE_OP_GE:
	{
		ret = bin_op_compare_check(stack, opcode, ">=");
		if (ret < 0)
			goto end;
		break;
	}
	case BYTECODE_OP_LE:
	{
		ret = bin_op_compare_check(stack, opcode, "<=");
		if (ret < 0)
			goto end;
		break;
	}

	case BYTECODE_OP_EQ_STRING:
	case BYTECODE_OP_NE_STRING:
	case BYTECODE_OP_GT_STRING:
	case BYTECODE_OP_LT_STRING:
	case BYTECODE_OP_GE_STRING:
	case BYTECODE_OP_LE_STRING:
	{
		if (!vstack_ax(stack) || !vstack_bx(stack)) {
			ERR("Empty stack\n");
			ret = -EINVAL;
			goto end;
		}
		if (vstack_ax(stack)->type != REG_STRING
				|| vstack_bx(stack)->type != REG_STRING) {
			ERR("Unexpected register type for string comparator\n");
			ret = -EINVAL;
			goto end;
		}
		break;
	}

	case BYTECODE_OP_EQ_STAR_GLOB_STRING:
	case BYTECODE_OP_NE_STAR_GLOB_STRING:
	{
		if (!vstack_ax(stack) || !vstack_bx(stack)) {
			ERR("Empty stack\n");
			ret = -EINVAL;
			goto end;
		}
		if (vstack_ax(stack)->type != REG_STAR_GLOB_STRING
				&& vstack_bx(stack)->type != REG_STAR_GLOB_STRING) {
			ERR("Unexpected register type for globbing pattern comparator\n");
			ret = -EINVAL;
			goto end;
		}
		break;
	}

	case BYTECODE_OP_EQ_S64:
	case BYTECODE_OP_NE_S64:
	case BYTECODE_OP_GT_S64:
	case BYTECODE_OP_LT_S64:
	case BYTECODE_OP_GE_S64:
	case BYTECODE_OP_LE_S64:
	{
		if (!vstack_ax(stack) || !vstack_bx(stack)) {
			ERR("Empty stack\n");
			ret = -EINVAL;
			goto end;
		}
		switch (vstack_ax(stack)->type) {
		case REG_S64:
		case REG_U64:
			break;
		default:
			ERR("Unexpected register type for s64 comparator\n");
			ret = -EINVAL;
			goto end;
		}
		switch (vstack_bx(stack)->type) {
		case REG_S64:
		case REG_U64:
			break;
		default:
			ERR("Unexpected register type for s64 comparator\n");
			ret = -EINVAL;
			goto end;
		}
		break;
	}

	case BYTECODE_OP_EQ_DOUBLE:
	case BYTECODE_OP_NE_DOUBLE:
	case BYTECODE_OP_GT_DOUBLE:
	case BYTECODE_OP_LT_DOUBLE:
	case BYTECODE_OP_GE_DOUBLE:
	case BYTECODE_OP_LE_DOUBLE:
	{
		if (!vstack_ax(stack) || !vstack_bx(stack)) {
			ERR("Empty stack\n");
			ret = -EINVAL;
			goto end;
		}
		if (vstack_ax(stack)->type != REG_DOUBLE && vstack_bx(stack)->type != REG_DOUBLE) {
			ERR("Double operator should have two double registers\n");
			ret = -EINVAL;
			goto end;
		}
		break;
	}

	case BYTECODE_OP_EQ_DOUBLE_S64:
	case BYTECODE_OP_NE_DOUBLE_S64:
	case BYTECODE_OP_GT_DOUBLE_S64:
	case BYTECODE_OP_LT_DOUBLE_S64:
	case BYTECODE_OP_GE_DOUBLE_S64:
	case BYTECODE_OP_LE_DOUBLE_S64:
	{
		if (!vstack_ax(stack) || !vstack_bx(stack)) {
			ERR("Empty stack\n");
			ret = -EINVAL;
			goto end;
		}
		switch (vstack_ax(stack)->type) {
		case REG_S64:
		case REG_U64:
			break;
		default:
			ERR("Double-S64 operator has unexpected register types\n");
			ret = -EINVAL;
			goto end;
		}
		switch (vstack_bx(stack)->type) {
		case REG_DOUBLE:
			break;
		default:
			ERR("Double-S64 operator has unexpected register types\n");
			ret = -EINVAL;
			goto end;
		}
		break;
	}

	case BYTECODE_OP_EQ_S64_DOUBLE:
	case BYTECODE_OP_NE_S64_DOUBLE:
	case BYTECODE_OP_GT_S64_DOUBLE:
	case BYTECODE_OP_LT_S64_DOUBLE:
	case BYTECODE_OP_GE_S64_DOUBLE:
	case BYTECODE_OP_LE_S64_DOUBLE:
	{
		if (!vstack_ax(stack) || !vstack_bx(stack)) {
			ERR("Empty stack\n");
			ret = -EINVAL;
			goto end;
		}
		switch (vstack_ax(stack)->type) {
		case REG_DOUBLE:
			break;
		default:
			ERR("S64-Double operator has unexpected register types\n");
			ret = -EINVAL;
			goto end;
		}
		switch (vstack_bx(stack)->type) {
		case REG_S64:
		case REG_U64:
			break;
		default:
			ERR("S64-Double operator has unexpected register types\n");
			ret = -EINVAL;
			goto end;
		}
		break;
	}

	case BYTECODE_OP_BIT_RSHIFT:
		ret = bin_op_bitwise_check(stack, opcode, ">>");
		if (ret < 0)
			goto end;
		break;
	case BYTECODE_OP_BIT_LSHIFT:
		ret = bin_op_bitwise_check(stack, opcode, "<<");
		if (ret < 0)
			goto end;
		break;
	case BYTECODE_OP_BIT_AND:
		ret = bin_op_bitwise_check(stack, opcode, "&");
		if (ret < 0)
			goto end;
		break;
	case BYTECODE_OP_BIT_OR:
		ret = bin_op_bitwise_check(stack, opcode, "|");
		if (ret < 0)
			goto end;
		break;
	case BYTECODE_OP_BIT_XOR:
		ret = bin_op_bitwise_check(stack, opcode, "^");
		if (ret < 0)
			goto end;
		break;

	/* unary */
	case BYTECODE_OP_UNARY_PLUS:
	case BYTECODE_OP_UNARY_MINUS:
	case BYTECODE_OP_UNARY_NOT:
	{
		if (!vstack_ax(stack)) {
			ERR("Empty stack\n");
			ret = -EINVAL;
			goto end;
		}
		switch (vstack_ax(stack)->type) {
		default:
			ERR("unknown register type\n");
			ret = -EINVAL;
			goto end;

		case REG_STRING:
		case REG_STAR_GLOB_STRING:
			ERR("Unary op can only be applied to numeric or floating point registers\n");
			ret = -EINVAL;
			goto end;
		case REG_S64:
			break;
		case REG_U64:
			break;
		case REG_DOUBLE:
			break;
		case REG_UNKNOWN:
			break;
		}
		break;
	}
	case BYTECODE_OP_UNARY_BIT_NOT:
	{
		if (!vstack_ax(stack)) {
			ERR("Empty stack\n");
			ret = -EINVAL;
			goto end;
		}
		switch (vstack_ax(stack)->type) {
		default:
			ERR("unknown register type\n");
			ret = -EINVAL;
			goto end;

		case REG_STRING:
		case REG_STAR_GLOB_STRING:
		case REG_DOUBLE:
			ERR("Unary bitwise op can only be applied to numeric registers\n");
			ret = -EINVAL;
			goto end;
		case REG_S64:
			break;
		case REG_U64:
			break;
		case REG_UNKNOWN:
			break;
		}
		break;
	}

	case BYTECODE_OP_UNARY_PLUS_S64:
	case BYTECODE_OP_UNARY_MINUS_S64:
	case BYTECODE_OP_UNARY_NOT_S64:
	{
		if (!vstack_ax(stack)) {
			ERR("Empty stack\n");
			ret = -EINVAL;
			goto end;
		}
		if (vstack_ax(stack)->type != REG_S64 &&
				vstack_ax(stack)->type != REG_U64) {
			ERR("Invalid register type\n");
			ret = -EINVAL;
			goto end;
		}
		break;
	}

	case BYTECODE_OP_UNARY_PLUS_DOUBLE:
	case BYTECODE_OP_UNARY_MINUS_DOUBLE:
	case BYTECODE_OP_UNARY_NOT_DOUBLE:
	{
		if (!vstack_ax(stack)) {
			ERR("Empty stack\n");
			ret = -EINVAL;
			goto end;
		}
		if (vstack_ax(stack)->type != REG_DOUBLE) {
			ERR("Invalid register type\n");
			ret = -EINVAL;
			goto end;
		}
		break;
	}

	/* logical */
	case BYTECODE_OP_AND:
	case BYTECODE_OP_OR:
	{
		struct logical_op *insn = (struct logical_op *) pc;

		if (!vstack_ax(stack)) {
			ERR("Empty stack\n");
			ret = -EINVAL;
			goto end;
		}
		if (vstack_ax(stack)->type != REG_S64
				&& vstack_ax(stack)->type != REG_U64
				&& vstack_ax(stack)->type != REG_UNKNOWN) {
			ERR("Logical comparator expects S64, U64 or dynamic register\n");
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
		break;
	}

	/* load field ref */
	case BYTECODE_OP_LOAD_FIELD_REF:
	{
		ERR("Unknown field ref type\n");
		ret = -EINVAL;
		goto end;
	}
	case BYTECODE_OP_LOAD_FIELD_REF_STRING:
	case BYTECODE_OP_LOAD_FIELD_REF_SEQUENCE:
	{
		struct load_op *insn = (struct load_op *) pc;
		struct field_ref *ref = (struct field_ref *) insn->data;

		dbg_printf("Validate load field ref offset %u type string\n",
			ref->offset);
		break;
	}
	case BYTECODE_OP_LOAD_FIELD_REF_S64:
	{
		struct load_op *insn = (struct load_op *) pc;
		struct field_ref *ref = (struct field_ref *) insn->data;

		dbg_printf("Validate load field ref offset %u type s64\n",
			ref->offset);
		break;
	}
	case BYTECODE_OP_LOAD_FIELD_REF_DOUBLE:
	{
		struct load_op *insn = (struct load_op *) pc;
		struct field_ref *ref = (struct field_ref *) insn->data;

		dbg_printf("Validate load field ref offset %u type double\n",
			ref->offset);
		break;
	}

	/* load from immediate operand */
	case BYTECODE_OP_LOAD_STRING:
	case BYTECODE_OP_LOAD_STAR_GLOB_STRING:
	{
		break;
	}

	case BYTECODE_OP_LOAD_S64:
	{
		break;
	}

	case BYTECODE_OP_LOAD_DOUBLE:
	{
		break;
	}

	case BYTECODE_OP_CAST_TO_S64:
	case BYTECODE_OP_CAST_DOUBLE_TO_S64:
	{
		struct cast_op *insn = (struct cast_op *) pc;

		if (!vstack_ax(stack)) {
			ERR("Empty stack\n");
			ret = -EINVAL;
			goto end;
		}
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
			break;
		case REG_U64:
			break;
		case REG_DOUBLE:
			break;
		case REG_UNKNOWN:
			break;
		}
		if (insn->op == BYTECODE_OP_CAST_DOUBLE_TO_S64) {
			if (vstack_ax(stack)->type != REG_DOUBLE) {
				ERR("Cast expects double\n");
				ret = -EINVAL;
				goto end;
			}
		}
		break;
	}
	case BYTECODE_OP_CAST_NOP:
	{
		break;
	}

	/* get context ref */
	case BYTECODE_OP_GET_CONTEXT_REF:
	{
		struct load_op *insn = (struct load_op *) pc;
		struct field_ref *ref = (struct field_ref *) insn->data;

		dbg_printf("Validate get context ref offset %u type dynamic\n",
			ref->offset);
		break;
	}
	case BYTECODE_OP_GET_CONTEXT_REF_STRING:
	{
		struct load_op *insn = (struct load_op *) pc;
		struct field_ref *ref = (struct field_ref *) insn->data;

		dbg_printf("Validate get context ref offset %u type string\n",
			ref->offset);
		break;
	}
	case BYTECODE_OP_GET_CONTEXT_REF_S64:
	{
		struct load_op *insn = (struct load_op *) pc;
		struct field_ref *ref = (struct field_ref *) insn->data;

		dbg_printf("Validate get context ref offset %u type s64\n",
			ref->offset);
		break;
	}
	case BYTECODE_OP_GET_CONTEXT_REF_DOUBLE:
	{
		struct load_op *insn = (struct load_op *) pc;
		struct field_ref *ref = (struct field_ref *) insn->data;

		dbg_printf("Validate get context ref offset %u type double\n",
			ref->offset);
		break;
	}

	/*
	 * Instructions for recursive traversal through composed types.
	 */
	case BYTECODE_OP_GET_CONTEXT_ROOT:
	{
		dbg_printf("Validate get context root\n");
		break;
	}
	case BYTECODE_OP_GET_APP_CONTEXT_ROOT:
	{
		dbg_printf("Validate get app context root\n");
		break;
	}
	case BYTECODE_OP_GET_PAYLOAD_ROOT:
	{
		dbg_printf("Validate get payload root\n");
		break;
	}
	case BYTECODE_OP_LOAD_FIELD:
	{
		/*
		 * We tolerate that field type is unknown at validation,
		 * because we are performing the load specialization in
		 * a phase after validation.
		 */
		dbg_printf("Validate load field\n");
		break;
	}

	/*
	 * Disallow already specialized bytecode op load field instructions to
	 * ensure that the received bytecode does not read a memory area larger
	 * than the memory targeted by the instrumentation.
	 */
	case BYTECODE_OP_LOAD_FIELD_S8:
	case BYTECODE_OP_LOAD_FIELD_S16:
	case BYTECODE_OP_LOAD_FIELD_S32:
	case BYTECODE_OP_LOAD_FIELD_S64:
	case BYTECODE_OP_LOAD_FIELD_U8:
	case BYTECODE_OP_LOAD_FIELD_U16:
	case BYTECODE_OP_LOAD_FIELD_U32:
	case BYTECODE_OP_LOAD_FIELD_U64:
	case BYTECODE_OP_LOAD_FIELD_STRING:
	case BYTECODE_OP_LOAD_FIELD_SEQUENCE:
	case BYTECODE_OP_LOAD_FIELD_DOUBLE:
	{
		dbg_printf("Validate load field, reject specialized load instruction (%d)\n",
				(int) opcode);
		ret = -EINVAL;
		goto end;
	}

	case BYTECODE_OP_GET_SYMBOL:
	{
		struct load_op *insn = (struct load_op *) pc;
		struct get_symbol *sym = (struct get_symbol *) insn->data;

		dbg_printf("Validate get symbol offset %u\n", sym->offset);
		break;
	}

	case BYTECODE_OP_GET_SYMBOL_FIELD:
	{
		struct load_op *insn = (struct load_op *) pc;
		struct get_symbol *sym = (struct get_symbol *) insn->data;

		dbg_printf("Validate get symbol field offset %u\n", sym->offset);
		break;
	}

	case BYTECODE_OP_GET_INDEX_U16:
	{
		struct load_op *insn = (struct load_op *) pc;
		struct get_index_u16 *get_index = (struct get_index_u16 *) insn->data;

		dbg_printf("Validate get index u16 index %u\n", get_index->index);
		break;
	}

	case BYTECODE_OP_GET_INDEX_U64:
	{
		struct load_op *insn = (struct load_op *) pc;
		struct get_index_u64 *get_index = (struct get_index_u64 *) insn->data;

		dbg_printf("Validate get index u64 index %" PRIu64 "\n", get_index->index);
		break;
	}
	}
end:
	return ret;
}

/*
 * Return value:
 * 0: success
 * <0: error
 */
static
int validate_instruction_all_contexts(struct bytecode_runtime *bytecode,
		struct lttng_ust_lfht *merge_points,
		struct vstack *stack,
		char *start_pc,
		char *pc)
{
	int ret;
	unsigned long target_pc = pc - start_pc;
	struct lttng_ust_lfht_iter iter;
	struct lttng_ust_lfht_node *node;
	struct lfht_mp_node *mp_node;
	unsigned long hash;

	/* Validate the context resulting from the previous instruction */
	ret = validate_instruction_context(bytecode, stack, start_pc, pc);
	if (ret < 0)
		return ret;

	/* Validate merge points */
	hash = lttng_hash_mix((const char *) target_pc, sizeof(target_pc),
			lttng_hash_seed);
	lttng_ust_lfht_lookup(merge_points, hash, lttng_hash_match,
			(const char *) target_pc, &iter);
	node = lttng_ust_lfht_iter_get_node(&iter);
	if (node) {
		mp_node = caa_container_of(node, struct lfht_mp_node, node);

		dbg_printf("Bytecode: validate merge point at offset %lu\n",
				target_pc);
		if (merge_points_compare(stack, &mp_node->stack)) {
			ERR("Merge points differ for offset %lu\n",
				target_pc);
			return -EINVAL;
		}
		/* Once validated, we can remove the merge point */
		dbg_printf("Bytecode: remove merge point at offset %lu\n",
				target_pc);
		ret = lttng_ust_lfht_del(merge_points, node);
		assert(!ret);
	}
	return 0;
}

/*
 * Validate load instructions: specialized instructions not accepted as input.
 *
 * Return value:
 * >0: going to next insn.
 * 0: success, stop iteration.
 * <0: error
 */
static
int validate_load(char **_next_pc,
		char *pc)
{
	int ret = 0;
	char *next_pc = *_next_pc;

	switch (*(bytecode_opcode_t *) pc) {
	case BYTECODE_OP_UNKNOWN:
	default:
	{
		ERR("Unknown bytecode op %u\n",
			(unsigned int) *(bytecode_opcode_t *) pc);
		ret = -EINVAL;
		goto end;
	}

	case BYTECODE_OP_RETURN:
	{
		next_pc += sizeof(struct return_op);
		break;
	}

	case BYTECODE_OP_RETURN_S64:
	{
		next_pc += sizeof(struct return_op);
		break;
	}

	/* binary */
	case BYTECODE_OP_MUL:
	case BYTECODE_OP_DIV:
	case BYTECODE_OP_MOD:
	case BYTECODE_OP_PLUS:
	case BYTECODE_OP_MINUS:
	{
		ERR("Unsupported bytecode op %u\n",
			(unsigned int) *(bytecode_opcode_t *) pc);
		ret = -EINVAL;
		goto end;
	}

	case BYTECODE_OP_EQ:
	case BYTECODE_OP_NE:
	case BYTECODE_OP_GT:
	case BYTECODE_OP_LT:
	case BYTECODE_OP_GE:
	case BYTECODE_OP_LE:
	case BYTECODE_OP_EQ_STRING:
	case BYTECODE_OP_NE_STRING:
	case BYTECODE_OP_GT_STRING:
	case BYTECODE_OP_LT_STRING:
	case BYTECODE_OP_GE_STRING:
	case BYTECODE_OP_LE_STRING:
	case BYTECODE_OP_EQ_STAR_GLOB_STRING:
	case BYTECODE_OP_NE_STAR_GLOB_STRING:
	case BYTECODE_OP_EQ_S64:
	case BYTECODE_OP_NE_S64:
	case BYTECODE_OP_GT_S64:
	case BYTECODE_OP_LT_S64:
	case BYTECODE_OP_GE_S64:
	case BYTECODE_OP_LE_S64:
	case BYTECODE_OP_EQ_DOUBLE:
	case BYTECODE_OP_NE_DOUBLE:
	case BYTECODE_OP_GT_DOUBLE:
	case BYTECODE_OP_LT_DOUBLE:
	case BYTECODE_OP_GE_DOUBLE:
	case BYTECODE_OP_LE_DOUBLE:
	case BYTECODE_OP_EQ_DOUBLE_S64:
	case BYTECODE_OP_NE_DOUBLE_S64:
	case BYTECODE_OP_GT_DOUBLE_S64:
	case BYTECODE_OP_LT_DOUBLE_S64:
	case BYTECODE_OP_GE_DOUBLE_S64:
	case BYTECODE_OP_LE_DOUBLE_S64:
	case BYTECODE_OP_EQ_S64_DOUBLE:
	case BYTECODE_OP_NE_S64_DOUBLE:
	case BYTECODE_OP_GT_S64_DOUBLE:
	case BYTECODE_OP_LT_S64_DOUBLE:
	case BYTECODE_OP_GE_S64_DOUBLE:
	case BYTECODE_OP_LE_S64_DOUBLE:
	case BYTECODE_OP_BIT_RSHIFT:
	case BYTECODE_OP_BIT_LSHIFT:
	case BYTECODE_OP_BIT_AND:
	case BYTECODE_OP_BIT_OR:
	case BYTECODE_OP_BIT_XOR:
	{
		next_pc += sizeof(struct binary_op);
		break;
	}

	/* unary */
	case BYTECODE_OP_UNARY_PLUS:
	case BYTECODE_OP_UNARY_MINUS:
	case BYTECODE_OP_UNARY_PLUS_S64:
	case BYTECODE_OP_UNARY_MINUS_S64:
	case BYTECODE_OP_UNARY_NOT_S64:
	case BYTECODE_OP_UNARY_NOT:
	case BYTECODE_OP_UNARY_BIT_NOT:
	case BYTECODE_OP_UNARY_PLUS_DOUBLE:
	case BYTECODE_OP_UNARY_MINUS_DOUBLE:
	case BYTECODE_OP_UNARY_NOT_DOUBLE:
	{
		next_pc += sizeof(struct unary_op);
		break;
	}

	/* logical */
	case BYTECODE_OP_AND:
	case BYTECODE_OP_OR:
	{
		next_pc += sizeof(struct logical_op);
		break;
	}

	/* load field ref */
	case BYTECODE_OP_LOAD_FIELD_REF:
	/* get context ref */
	case BYTECODE_OP_GET_CONTEXT_REF:
	{
		next_pc += sizeof(struct load_op) + sizeof(struct field_ref);
		break;
	}
	case BYTECODE_OP_LOAD_FIELD_REF_STRING:
	case BYTECODE_OP_LOAD_FIELD_REF_SEQUENCE:
	case BYTECODE_OP_GET_CONTEXT_REF_STRING:
	case BYTECODE_OP_LOAD_FIELD_REF_S64:
	case BYTECODE_OP_GET_CONTEXT_REF_S64:
	case BYTECODE_OP_LOAD_FIELD_REF_DOUBLE:
	case BYTECODE_OP_GET_CONTEXT_REF_DOUBLE:
	{
		/*
		 * Reject specialized load field ref instructions.
		 */
		ret = -EINVAL;
		goto end;
	}

	/* load from immediate operand */
	case BYTECODE_OP_LOAD_STRING:
	case BYTECODE_OP_LOAD_STAR_GLOB_STRING:
	{
		struct load_op *insn = (struct load_op *) pc;

		next_pc += sizeof(struct load_op) + strlen(insn->data) + 1;
		break;
	}

	case BYTECODE_OP_LOAD_S64:
	{
		next_pc += sizeof(struct load_op) + sizeof(struct literal_numeric);
		break;
	}
	case BYTECODE_OP_LOAD_DOUBLE:
	{
		next_pc += sizeof(struct load_op) + sizeof(struct literal_double);
		break;
	}

	case BYTECODE_OP_CAST_DOUBLE_TO_S64:
	case BYTECODE_OP_CAST_TO_S64:
	case BYTECODE_OP_CAST_NOP:
	{
		next_pc += sizeof(struct cast_op);
		break;
	}

	/*
	 * Instructions for recursive traversal through composed types.
	 */
	case BYTECODE_OP_GET_CONTEXT_ROOT:
	case BYTECODE_OP_GET_APP_CONTEXT_ROOT:
	case BYTECODE_OP_GET_PAYLOAD_ROOT:
	case BYTECODE_OP_LOAD_FIELD:
	{
		next_pc += sizeof(struct load_op);
		break;
	}

	case BYTECODE_OP_LOAD_FIELD_S8:
	case BYTECODE_OP_LOAD_FIELD_S16:
	case BYTECODE_OP_LOAD_FIELD_S32:
	case BYTECODE_OP_LOAD_FIELD_S64:
	case BYTECODE_OP_LOAD_FIELD_U8:
	case BYTECODE_OP_LOAD_FIELD_U16:
	case BYTECODE_OP_LOAD_FIELD_U32:
	case BYTECODE_OP_LOAD_FIELD_U64:
	case BYTECODE_OP_LOAD_FIELD_STRING:
	case BYTECODE_OP_LOAD_FIELD_SEQUENCE:
	case BYTECODE_OP_LOAD_FIELD_DOUBLE:
	{
		/*
		 * Reject specialized load field instructions.
		 */
		ret = -EINVAL;
		goto end;
	}

	case BYTECODE_OP_GET_SYMBOL:
	case BYTECODE_OP_GET_SYMBOL_FIELD:
	{
		next_pc += sizeof(struct load_op) + sizeof(struct get_symbol);
		break;
	}

	case BYTECODE_OP_GET_INDEX_U16:
	{
		next_pc += sizeof(struct load_op) + sizeof(struct get_index_u16);
		break;
	}

	case BYTECODE_OP_GET_INDEX_U64:
	{
		next_pc += sizeof(struct load_op) + sizeof(struct get_index_u64);
		break;
	}

	}
end:
	*_next_pc = next_pc;
	return ret;
}

/*
 * Return value:
 * >0: going to next insn.
 * 0: success, stop iteration.
 * <0: error
 */
static
int exec_insn(struct bytecode_runtime *bytecode __attribute__((unused)),
		struct lttng_ust_lfht *merge_points,
		struct vstack *stack,
		char **_next_pc,
		char *pc)
{
	int ret = 1;
	char *next_pc = *_next_pc;

	switch (*(bytecode_opcode_t *) pc) {
	case BYTECODE_OP_UNKNOWN:
	default:
	{
		ERR("unknown bytecode op %u\n",
			(unsigned int) *(bytecode_opcode_t *) pc);
		ret = -EINVAL;
		goto end;
	}

	case BYTECODE_OP_RETURN:
	{
		if (!vstack_ax(stack)) {
			ERR("Empty stack\n");
			ret = -EINVAL;
			goto end;
		}
		switch (vstack_ax(stack)->type) {
		case REG_S64:
		case REG_U64:
		case REG_DOUBLE:
		case REG_STRING:
		case REG_PTR:
		case REG_UNKNOWN:
			break;
		default:
			ERR("Unexpected register type %d at end of bytecode\n",
				(int) vstack_ax(stack)->type);
			ret = -EINVAL;
			goto end;
		}

		ret = 0;
		goto end;
	}
	case BYTECODE_OP_RETURN_S64:
	{
		if (!vstack_ax(stack)) {
			ERR("Empty stack\n");
			ret = -EINVAL;
			goto end;
		}
		switch (vstack_ax(stack)->type) {
		case REG_S64:
		case REG_U64:
			break;
		default:
		case REG_UNKNOWN:
			ERR("Unexpected register type %d at end of bytecode\n",
				(int) vstack_ax(stack)->type);
			ret = -EINVAL;
			goto end;
		}

		ret = 0;
		goto end;
	}

	/* binary */
	case BYTECODE_OP_MUL:
	case BYTECODE_OP_DIV:
	case BYTECODE_OP_MOD:
	case BYTECODE_OP_PLUS:
	case BYTECODE_OP_MINUS:
	{
		ERR("unsupported bytecode op %u\n",
			(unsigned int) *(bytecode_opcode_t *) pc);
		ret = -EINVAL;
		goto end;
	}

	case BYTECODE_OP_EQ:
	case BYTECODE_OP_NE:
	case BYTECODE_OP_GT:
	case BYTECODE_OP_LT:
	case BYTECODE_OP_GE:
	case BYTECODE_OP_LE:
	case BYTECODE_OP_EQ_STRING:
	case BYTECODE_OP_NE_STRING:
	case BYTECODE_OP_GT_STRING:
	case BYTECODE_OP_LT_STRING:
	case BYTECODE_OP_GE_STRING:
	case BYTECODE_OP_LE_STRING:
	case BYTECODE_OP_EQ_STAR_GLOB_STRING:
	case BYTECODE_OP_NE_STAR_GLOB_STRING:
	case BYTECODE_OP_EQ_S64:
	case BYTECODE_OP_NE_S64:
	case BYTECODE_OP_GT_S64:
	case BYTECODE_OP_LT_S64:
	case BYTECODE_OP_GE_S64:
	case BYTECODE_OP_LE_S64:
	case BYTECODE_OP_EQ_DOUBLE:
	case BYTECODE_OP_NE_DOUBLE:
	case BYTECODE_OP_GT_DOUBLE:
	case BYTECODE_OP_LT_DOUBLE:
	case BYTECODE_OP_GE_DOUBLE:
	case BYTECODE_OP_LE_DOUBLE:
	case BYTECODE_OP_EQ_DOUBLE_S64:
	case BYTECODE_OP_NE_DOUBLE_S64:
	case BYTECODE_OP_GT_DOUBLE_S64:
	case BYTECODE_OP_LT_DOUBLE_S64:
	case BYTECODE_OP_GE_DOUBLE_S64:
	case BYTECODE_OP_LE_DOUBLE_S64:
	case BYTECODE_OP_EQ_S64_DOUBLE:
	case BYTECODE_OP_NE_S64_DOUBLE:
	case BYTECODE_OP_GT_S64_DOUBLE:
	case BYTECODE_OP_LT_S64_DOUBLE:
	case BYTECODE_OP_GE_S64_DOUBLE:
	case BYTECODE_OP_LE_S64_DOUBLE:
	{
		/* Pop 2, push 1 */
		if (vstack_pop(stack)) {
			ret = -EINVAL;
			goto end;
		}
		if (!vstack_ax(stack)) {
			ERR("Empty stack\n");
			ret = -EINVAL;
			goto end;
		}
		switch (vstack_ax(stack)->type) {
		case REG_S64:
		case REG_U64:
		case REG_DOUBLE:
		case REG_STRING:
		case REG_STAR_GLOB_STRING:
		case REG_UNKNOWN:
			break;
		default:
			ERR("Unexpected register type %d for operation\n",
				(int) vstack_ax(stack)->type);
			ret = -EINVAL;
			goto end;
		}

		vstack_ax(stack)->type = REG_S64;
		next_pc += sizeof(struct binary_op);
		break;
	}

	case BYTECODE_OP_BIT_RSHIFT:
	case BYTECODE_OP_BIT_LSHIFT:
	case BYTECODE_OP_BIT_AND:
	case BYTECODE_OP_BIT_OR:
	case BYTECODE_OP_BIT_XOR:
	{
		/* Pop 2, push 1 */
		if (vstack_pop(stack)) {
			ret = -EINVAL;
			goto end;
		}
		if (!vstack_ax(stack)) {
			ERR("Empty stack\n");
			ret = -EINVAL;
			goto end;
		}
		switch (vstack_ax(stack)->type) {
		case REG_S64:
		case REG_U64:
		case REG_DOUBLE:
		case REG_STRING:
		case REG_STAR_GLOB_STRING:
		case REG_UNKNOWN:
			break;
		default:
			ERR("Unexpected register type %d for operation\n",
				(int) vstack_ax(stack)->type);
			ret = -EINVAL;
			goto end;
		}

		vstack_ax(stack)->type = REG_U64;
		next_pc += sizeof(struct binary_op);
		break;
	}

	/* unary */
	case BYTECODE_OP_UNARY_PLUS:
	case BYTECODE_OP_UNARY_MINUS:
	{
		/* Pop 1, push 1 */
		if (!vstack_ax(stack)) {
			ERR("Empty stack\n");
			ret = -EINVAL;
			goto end;
		}
		switch (vstack_ax(stack)->type) {
		case REG_UNKNOWN:
		case REG_DOUBLE:
		case REG_S64:
		case REG_U64:
			break;
		default:
			ERR("Unexpected register type %d for operation\n",
				(int) vstack_ax(stack)->type);
			ret = -EINVAL;
			goto end;
		}
		vstack_ax(stack)->type = REG_UNKNOWN;
		next_pc += sizeof(struct unary_op);
		break;
	}

	case BYTECODE_OP_UNARY_PLUS_S64:
	case BYTECODE_OP_UNARY_MINUS_S64:
	case BYTECODE_OP_UNARY_NOT_S64:
	{
		/* Pop 1, push 1 */
		if (!vstack_ax(stack)) {
			ERR("Empty stack\n");
			ret = -EINVAL;
			goto end;
		}
		switch (vstack_ax(stack)->type) {
		case REG_S64:
		case REG_U64:
			break;
		default:
			ERR("Unexpected register type %d for operation\n",
				(int) vstack_ax(stack)->type);
			ret = -EINVAL;
			goto end;
		}

		next_pc += sizeof(struct unary_op);
		break;
	}

	case BYTECODE_OP_UNARY_NOT:
	{
		/* Pop 1, push 1 */
		if (!vstack_ax(stack)) {
			ERR("Empty stack\n");
			ret = -EINVAL;
			goto end;
		}
		switch (vstack_ax(stack)->type) {
		case REG_UNKNOWN:
		case REG_DOUBLE:
		case REG_S64:
		case REG_U64:
			break;
		default:
			ERR("Unexpected register type %d for operation\n",
				(int) vstack_ax(stack)->type);
			ret = -EINVAL;
			goto end;
		}

		next_pc += sizeof(struct unary_op);
		break;
	}

	case BYTECODE_OP_UNARY_BIT_NOT:
	{
		/* Pop 1, push 1 */
		if (!vstack_ax(stack)) {
			ERR("Empty stack\n");
			ret = -EINVAL;
			goto end;
		}
		switch (vstack_ax(stack)->type) {
		case REG_UNKNOWN:
		case REG_S64:
		case REG_U64:
			break;
		case REG_DOUBLE:
		default:
			ERR("Unexpected register type %d for operation\n",
				(int) vstack_ax(stack)->type);
			ret = -EINVAL;
			goto end;
		}

		vstack_ax(stack)->type = REG_U64;
		next_pc += sizeof(struct unary_op);
		break;
	}

	case BYTECODE_OP_UNARY_NOT_DOUBLE:
	{
		/* Pop 1, push 1 */
		if (!vstack_ax(stack)) {
			ERR("Empty stack\n");
			ret = -EINVAL;
			goto end;
		}
		switch (vstack_ax(stack)->type) {
		case REG_DOUBLE:
			break;
		default:
			ERR("Incorrect register type %d for operation\n",
				(int) vstack_ax(stack)->type);
			ret = -EINVAL;
			goto end;
		}

		vstack_ax(stack)->type = REG_S64;
		next_pc += sizeof(struct unary_op);
		break;
	}

	case BYTECODE_OP_UNARY_PLUS_DOUBLE:
	case BYTECODE_OP_UNARY_MINUS_DOUBLE:
	{
		/* Pop 1, push 1 */
		if (!vstack_ax(stack)) {
			ERR("Empty stack\n");
			ret = -EINVAL;
			goto end;
		}
		switch (vstack_ax(stack)->type) {
		case REG_DOUBLE:
			break;
		default:
			ERR("Incorrect register type %d for operation\n",
				(int) vstack_ax(stack)->type);
			ret = -EINVAL;
			goto end;
		}

		vstack_ax(stack)->type = REG_DOUBLE;
		next_pc += sizeof(struct unary_op);
		break;
	}

	/* logical */
	case BYTECODE_OP_AND:
	case BYTECODE_OP_OR:
	{
		struct logical_op *insn = (struct logical_op *) pc;
		int merge_ret;

		/* Add merge point to table */
		merge_ret = merge_point_add_check(merge_points,
					insn->skip_offset, stack);
		if (merge_ret) {
			ret = merge_ret;
			goto end;
		}

		if (!vstack_ax(stack)) {
			ERR("Empty stack\n");
			ret = -EINVAL;
			goto end;
		}
		/* There is always a cast-to-s64 operation before a or/and op. */
		switch (vstack_ax(stack)->type) {
		case REG_S64:
		case REG_U64:
			break;
		default:
			ERR("Incorrect register type %d for operation\n",
				(int) vstack_ax(stack)->type);
			ret = -EINVAL;
			goto end;
		}

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
	case BYTECODE_OP_LOAD_FIELD_REF:
	{
		ERR("Unknown field ref type\n");
		ret = -EINVAL;
		goto end;
	}
	/* get context ref */
	case BYTECODE_OP_GET_CONTEXT_REF:
	{
		if (vstack_push(stack)) {
			ret = -EINVAL;
			goto end;
		}
		vstack_ax(stack)->type = REG_UNKNOWN;
		next_pc += sizeof(struct load_op) + sizeof(struct field_ref);
		break;
	}
	case BYTECODE_OP_LOAD_FIELD_REF_STRING:
	case BYTECODE_OP_LOAD_FIELD_REF_SEQUENCE:
	case BYTECODE_OP_GET_CONTEXT_REF_STRING:
	{
		if (vstack_push(stack)) {
			ret = -EINVAL;
			goto end;
		}
		vstack_ax(stack)->type = REG_STRING;
		next_pc += sizeof(struct load_op) + sizeof(struct field_ref);
		break;
	}
	case BYTECODE_OP_LOAD_FIELD_REF_S64:
	case BYTECODE_OP_GET_CONTEXT_REF_S64:
	{
		if (vstack_push(stack)) {
			ret = -EINVAL;
			goto end;
		}
		vstack_ax(stack)->type = REG_S64;
		next_pc += sizeof(struct load_op) + sizeof(struct field_ref);
		break;
	}
	case BYTECODE_OP_LOAD_FIELD_REF_DOUBLE:
	case BYTECODE_OP_GET_CONTEXT_REF_DOUBLE:
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
	case BYTECODE_OP_LOAD_STRING:
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

	case BYTECODE_OP_LOAD_STAR_GLOB_STRING:
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

	case BYTECODE_OP_LOAD_S64:
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

	case BYTECODE_OP_LOAD_DOUBLE:
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

	case BYTECODE_OP_CAST_TO_S64:
	case BYTECODE_OP_CAST_DOUBLE_TO_S64:
	{
		/* Pop 1, push 1 */
		if (!vstack_ax(stack)) {
			ERR("Empty stack\n");
			ret = -EINVAL;
			goto end;
		}
		switch (vstack_ax(stack)->type) {
		case REG_S64:
		case REG_U64:
		case REG_DOUBLE:
		case REG_UNKNOWN:
			break;
		default:
			ERR("Incorrect register type %d for cast\n",
				(int) vstack_ax(stack)->type);
			ret = -EINVAL;
			goto end;
		}
		vstack_ax(stack)->type = REG_S64;
		next_pc += sizeof(struct cast_op);
		break;
	}
	case BYTECODE_OP_CAST_NOP:
	{
		next_pc += sizeof(struct cast_op);
		break;
	}

	/*
	 * Instructions for recursive traversal through composed types.
	 */
	case BYTECODE_OP_GET_CONTEXT_ROOT:
	case BYTECODE_OP_GET_APP_CONTEXT_ROOT:
	case BYTECODE_OP_GET_PAYLOAD_ROOT:
	{
		if (vstack_push(stack)) {
			ret = -EINVAL;
			goto end;
		}
		vstack_ax(stack)->type = REG_PTR;
		next_pc += sizeof(struct load_op);
		break;
	}

	case BYTECODE_OP_LOAD_FIELD:
	{
		/* Pop 1, push 1 */
		if (!vstack_ax(stack)) {
			ERR("Empty stack\n");
			ret = -EINVAL;
			goto end;
		}
		if (vstack_ax(stack)->type != REG_PTR) {
			ERR("Expecting pointer on top of stack\n");
			ret = -EINVAL;
			goto end;
		}
		vstack_ax(stack)->type = REG_UNKNOWN;
		next_pc += sizeof(struct load_op);
		break;
	}

	case BYTECODE_OP_LOAD_FIELD_S8:
	case BYTECODE_OP_LOAD_FIELD_S16:
	case BYTECODE_OP_LOAD_FIELD_S32:
	case BYTECODE_OP_LOAD_FIELD_S64:
	{
		/* Pop 1, push 1 */
		if (!vstack_ax(stack)) {
			ERR("Empty stack\n");
			ret = -EINVAL;
			goto end;
		}
		if (vstack_ax(stack)->type != REG_PTR) {
			ERR("Expecting pointer on top of stack\n");
			ret = -EINVAL;
			goto end;
		}
		vstack_ax(stack)->type = REG_S64;
		next_pc += sizeof(struct load_op);
		break;
	}

	case BYTECODE_OP_LOAD_FIELD_U8:
	case BYTECODE_OP_LOAD_FIELD_U16:
	case BYTECODE_OP_LOAD_FIELD_U32:
	case BYTECODE_OP_LOAD_FIELD_U64:
	{
		/* Pop 1, push 1 */
		if (!vstack_ax(stack)) {
			ERR("Empty stack\n");
			ret = -EINVAL;
			goto end;
		}
		if (vstack_ax(stack)->type != REG_PTR) {
			ERR("Expecting pointer on top of stack\n");
			ret = -EINVAL;
			goto end;
		}
		vstack_ax(stack)->type = REG_U64;
		next_pc += sizeof(struct load_op);
		break;
	}

	case BYTECODE_OP_LOAD_FIELD_STRING:
	case BYTECODE_OP_LOAD_FIELD_SEQUENCE:
	{
		/* Pop 1, push 1 */
		if (!vstack_ax(stack)) {
			ERR("Empty stack\n");
			ret = -EINVAL;
			goto end;
		}
		if (vstack_ax(stack)->type != REG_PTR) {
			ERR("Expecting pointer on top of stack\n");
			ret = -EINVAL;
			goto end;
		}
		vstack_ax(stack)->type = REG_STRING;
		next_pc += sizeof(struct load_op);
		break;
	}

	case BYTECODE_OP_LOAD_FIELD_DOUBLE:
	{
		/* Pop 1, push 1 */
		if (!vstack_ax(stack)) {
			ERR("Empty stack\n");
			ret = -EINVAL;
			goto end;
		}
		if (vstack_ax(stack)->type != REG_PTR) {
			ERR("Expecting pointer on top of stack\n");
			ret = -EINVAL;
			goto end;
		}
		vstack_ax(stack)->type = REG_DOUBLE;
		next_pc += sizeof(struct load_op);
		break;
	}

	case BYTECODE_OP_GET_SYMBOL:
	case BYTECODE_OP_GET_SYMBOL_FIELD:
	{
		/* Pop 1, push 1 */
		if (!vstack_ax(stack)) {
			ERR("Empty stack\n");
			ret = -EINVAL;
			goto end;
		}
		if (vstack_ax(stack)->type != REG_PTR) {
			ERR("Expecting pointer on top of stack\n");
			ret = -EINVAL;
			goto end;
		}
		next_pc += sizeof(struct load_op) + sizeof(struct get_symbol);
		break;
	}

	case BYTECODE_OP_GET_INDEX_U16:
	{
		/* Pop 1, push 1 */
		if (!vstack_ax(stack)) {
			ERR("Empty stack\n");
			ret = -EINVAL;
			goto end;
		}
		if (vstack_ax(stack)->type != REG_PTR) {
			ERR("Expecting pointer on top of stack\n");
			ret = -EINVAL;
			goto end;
		}
		next_pc += sizeof(struct load_op) + sizeof(struct get_index_u16);
		break;
	}

	case BYTECODE_OP_GET_INDEX_U64:
	{
		/* Pop 1, push 1 */
		if (!vstack_ax(stack)) {
			ERR("Empty stack\n");
			ret = -EINVAL;
			goto end;
		}
		if (vstack_ax(stack)->type != REG_PTR) {
			ERR("Expecting pointer on top of stack\n");
			ret = -EINVAL;
			goto end;
		}
		next_pc += sizeof(struct load_op) + sizeof(struct get_index_u64);
		break;
	}

	}
end:
	*_next_pc = next_pc;
	return ret;
}

int lttng_bytecode_validate_load(struct bytecode_runtime *bytecode)
{
	char *pc, *next_pc, *start_pc;
	int ret = -EINVAL;

	start_pc = &bytecode->code[0];
	for (pc = next_pc = start_pc; pc - start_pc < bytecode->len;
			pc = next_pc) {
		ret = bytecode_validate_overflow(bytecode, start_pc, pc);
		if (ret != 0) {
			if (ret == -ERANGE)
				ERR("Bytecode overflow\n");
			goto end;
		}
		dbg_printf("Validating loads: op %s (%u)\n",
			lttng_bytecode_print_op((unsigned int) *(bytecode_opcode_t *) pc),
			(unsigned int) *(bytecode_opcode_t *) pc);

		ret = validate_load(&next_pc, pc);
		if (ret)
			goto end;
	}
end:
	return ret;
}

/*
 * Never called concurrently (hash seed is shared).
 */
int lttng_bytecode_validate(struct bytecode_runtime *bytecode)
{
	struct lttng_ust_lfht *merge_points;
	char *pc, *next_pc, *start_pc;
	int ret = -EINVAL;
	struct vstack stack;

	vstack_init(&stack);

	if (!lttng_hash_seed_ready) {
		lttng_hash_seed = time(NULL);
		lttng_hash_seed_ready = 1;
	}
	/*
	 * Note: merge_points hash table used by single thread, and
	 * never concurrently resized. Therefore, we can use it without
	 * holding RCU read-side lock and free nodes without using
	 * call_rcu.
	 */
	merge_points = lttng_ust_lfht_new(DEFAULT_NR_MERGE_POINTS,
			MIN_NR_BUCKETS, MAX_NR_BUCKETS,
			0, NULL);
	if (!merge_points) {
		ERR("Error allocating hash table for bytecode validation\n");
		return -ENOMEM;
	}
	start_pc = &bytecode->code[0];
	for (pc = next_pc = start_pc; pc - start_pc < bytecode->len;
			pc = next_pc) {
		ret = bytecode_validate_overflow(bytecode, start_pc, pc);
		if (ret != 0) {
			if (ret == -ERANGE)
				ERR("Bytecode overflow\n");
			goto end;
		}
		dbg_printf("Validating op %s (%u)\n",
			lttng_bytecode_print_op((unsigned int) *(bytecode_opcode_t *) pc),
			(unsigned int) *(bytecode_opcode_t *) pc);

		/*
		 * For each instruction, validate the current context
		 * (traversal of entire execution flow), and validate
		 * all merge points targeting this instruction.
		 */
		ret = validate_instruction_all_contexts(bytecode, merge_points,
					&stack, start_pc, pc);
		if (ret)
			goto end;
		ret = exec_insn(bytecode, merge_points, &stack, &next_pc, pc);
		if (ret <= 0)
			goto end;
	}
end:
	if (delete_all_nodes(merge_points)) {
		if (!ret) {
			ERR("Unexpected merge points\n");
			ret = -EINVAL;
		}
	}
	if (lttng_ust_lfht_destroy(merge_points)) {
		ERR("Error destroying hash table\n");
	}
	return ret;
}
