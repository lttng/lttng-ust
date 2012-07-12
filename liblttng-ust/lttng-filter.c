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

struct reg {
	enum {
		REG_S64,
		REG_STRING,	/* NULL-terminated string */
		REG_SEQUENCE,	/* non-null terminated */
	} type;
	int64_t v;

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
	[ FILTER_OP_EQ ] = "EQ",
	[ FILTER_OP_NE ] = "NE",
	[ FILTER_OP_GT ] = "GT",
	[ FILTER_OP_LT ] = "LT",
	[ FILTER_OP_GE ] = "GE",
	[ FILTER_OP_LE ] = "LE",

	/* unary */
	[ FILTER_OP_UNARY_PLUS ] = "UNARY_PLUS",
	[ FILTER_OP_UNARY_MINUS ] = "UNARY_MINUS",
	[ FILTER_OP_UNARY_NOT ] = "UNARY_NOT",

	/* logical */
	[ FILTER_OP_AND ] = "AND",
	[ FILTER_OP_OR ] = "OR",

	/* load */
	[ FILTER_OP_LOAD_FIELD_REF ] = "LOAD_FIELD_REF",
	[ FILTER_OP_LOAD_STRING ] = "LOAD_STRING",
	[ FILTER_OP_LOAD_S64 ] = "LOAD_S64",
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

static
int lttng_filter_interpret_bytecode(void *filter_data,
		const char *filter_stack_data)
{
	struct bytecode_runtime *bytecode = filter_data;
	void *pc, *next_pc, *start_pc;
	int ret = -EINVAL;
	int retval = 0;
	struct reg reg[NR_REG];
	int i;

	for (i = 0; i < NR_REG; i++) {
		reg[i].type = REG_S64;
		reg[i].v = 0;
		reg[i].str = NULL;
		reg[i].seq_len = 0;
		reg[i].literal = 0;
	}

	start_pc = &bytecode->data[0];
	for (pc = next_pc = start_pc; pc - start_pc < bytecode->len;
			pc = next_pc) {
		if (unlikely(pc >= start_pc + bytecode->len)) {
			fprintf(stderr, "[error] filter bytecode overflow\n");
			ret = -EINVAL;
			goto end;
		}
		dbg_printf("Executing op %s (%u)\n",
			print_op((unsigned int) *(filter_opcode_t *) pc),
			(unsigned int) *(filter_opcode_t *) pc);
		switch (*(filter_opcode_t *) pc) {
		case FILTER_OP_UNKNOWN:
		default:
			fprintf(stderr, "[error] unknown bytecode op %u\n",
				(unsigned int) *(filter_opcode_t *) pc);
			ret = -EINVAL;
			goto end;

		case FILTER_OP_RETURN:
			retval = !!reg[0].v;
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
			fprintf(stderr, "[error] unsupported bytecode op %u\n",
				(unsigned int) *(filter_opcode_t *) pc);
			ret = -EINVAL;
			goto end;

		case FILTER_OP_EQ:
		{
			if (unlikely((reg[REG_R0].type == REG_S64 && reg[REG_R1].type != REG_S64)
					|| (reg[REG_R0].type != REG_S64 && reg[REG_R1].type == REG_S64))) {
				fprintf(stderr, "[error] type mismatch for '==' binary operator\n");
				ret = -EINVAL;
				goto end;
			}
			switch (reg[REG_R0].type) {
			default:
				fprintf(stderr, "[error] unknown register type\n");
				ret = -EINVAL;
				goto end;

			case REG_STRING:
			case REG_SEQUENCE:
				reg[REG_R0].v = (reg_strcmp(reg, "==") == 0);
				break;
			case REG_S64:
				reg[REG_R0].v = (reg[REG_R0].v == reg[REG_R1].v);
				break;
			}
			reg[REG_R0].type = REG_S64;
			next_pc += sizeof(struct binary_op);
			break;
		}
		case FILTER_OP_NE:
		{
			if (unlikely((reg[REG_R0].type == REG_S64 && reg[REG_R1].type != REG_S64)
					|| (reg[REG_R0].type != REG_S64 && reg[REG_R1].type == REG_S64))) {
				fprintf(stderr, "[error] type mismatch for '!=' binary operator\n");
				ret = -EINVAL;
				goto end;
			}
			switch (reg[REG_R0].type) {
			default:
				fprintf(stderr, "[error] unknown register type\n");
				ret = -EINVAL;
				goto end;

			case REG_STRING:
			case REG_SEQUENCE:
				reg[REG_R0].v = (reg_strcmp(reg, "!=") != 0);
				break;
			case REG_S64:
				reg[REG_R0].v = (reg[REG_R0].v != reg[REG_R1].v);
				break;
			}
			reg[REG_R0].type = REG_S64;
			next_pc += sizeof(struct binary_op);
			break;
		}
		case FILTER_OP_GT:
		{
			if (unlikely((reg[REG_R0].type == REG_S64 && reg[REG_R1].type != REG_S64)
					|| (reg[REG_R0].type != REG_S64 && reg[REG_R1].type == REG_S64))) {
				fprintf(stderr, "[error] type mismatch for '>' binary operator\n");
				ret = -EINVAL;
				goto end;
			}
			switch (reg[REG_R0].type) {
			default:
				fprintf(stderr, "[error] unknown register type\n");
				ret = -EINVAL;
				goto end;

			case REG_STRING:
			case REG_SEQUENCE:
				reg[REG_R0].v = (reg_strcmp(reg, ">") > 0);
				break;
			case REG_S64:
				reg[REG_R0].v = (reg[REG_R0].v > reg[REG_R1].v);
				break;
			}
			reg[REG_R0].type = REG_S64;
			next_pc += sizeof(struct binary_op);
			break;
		}
		case FILTER_OP_LT:
		{
			if (unlikely((reg[REG_R0].type == REG_S64 && reg[REG_R1].type != REG_S64)
					|| (reg[REG_R0].type != REG_S64 && reg[REG_R1].type == REG_S64))) {
				fprintf(stderr, "[error] type mismatch for '<' binary operator\n");
				ret = -EINVAL;
				goto end;
			}
			switch (reg[REG_R0].type) {
			default:
				fprintf(stderr, "[error] unknown register type\n");
				ret = -EINVAL;
				goto end;

			case REG_STRING:
			case REG_SEQUENCE:
				reg[REG_R0].v = (reg_strcmp(reg, "<") < 0);
				break;
			case REG_S64:
				reg[REG_R0].v = (reg[REG_R0].v < reg[REG_R1].v);
				break;
			}
			reg[REG_R0].type = REG_S64;
			next_pc += sizeof(struct binary_op);
			break;
		}
		case FILTER_OP_GE:
		{
			if (unlikely((reg[REG_R0].type == REG_S64 && reg[REG_R1].type != REG_S64)
					|| (reg[REG_R0].type != REG_S64 && reg[REG_R1].type == REG_S64))) {
				fprintf(stderr, "[error] type mismatch for '>=' binary operator\n");
				ret = -EINVAL;
				goto end;
			}
			switch (reg[REG_R0].type) {
			default:
				fprintf(stderr, "[error] unknown register type\n");
				ret = -EINVAL;
				goto end;

			case REG_STRING:
			case REG_SEQUENCE:
				reg[REG_R0].v = (reg_strcmp(reg, ">=") >= 0);
				break;
			case REG_S64:
				reg[REG_R0].v = (reg[REG_R0].v >= reg[REG_R1].v);
				break;
			}
			reg[REG_R0].type = REG_S64;
			next_pc += sizeof(struct binary_op);
			break;
		}
		case FILTER_OP_LE:
		{
			if (unlikely((reg[REG_R0].type == REG_S64 && reg[REG_R1].type != REG_S64)
					|| (reg[REG_R0].type != REG_S64 && reg[REG_R1].type == REG_S64))) {
				fprintf(stderr, "[error] type mismatch for '<=' binary operator\n");
				ret = -EINVAL;
				goto end;
			}
			switch (reg[REG_R0].type) {
			default:
				fprintf(stderr, "[error] unknown register type\n");
				ret = -EINVAL;
				goto end;

			case REG_STRING:
			case REG_SEQUENCE:
				reg[REG_R0].v = (reg_strcmp(reg, "<=") <= 0);
				break;
			case REG_S64:
				reg[REG_R0].v = (reg[REG_R0].v <= reg[REG_R1].v);
				break;
			}
			reg[REG_R0].type = REG_S64;
			next_pc += sizeof(struct binary_op);
			break;
		}

		/* unary */
		case FILTER_OP_UNARY_PLUS:
		{
			struct unary_op *insn = (struct unary_op *) pc;

			if (unlikely(insn->reg >= REG_ERROR)) {
				fprintf(stderr, "[error] invalid register %u\n",
					(unsigned int) insn->reg);
				ret = -EINVAL;
				goto end;
			}
			if (unlikely(reg[insn->reg].type != REG_S64)) {
				fprintf(stderr, "[error] Unary plus can only be applied to numeric register\n");
				ret = -EINVAL;
				goto end;
			}
			next_pc += sizeof(struct unary_op);
			break;
		}
		case FILTER_OP_UNARY_MINUS:
		{
			struct unary_op *insn = (struct unary_op *) pc;

			if (unlikely(insn->reg >= REG_ERROR)) {
				fprintf(stderr, "[error] invalid register %u\n",
					(unsigned int) insn->reg);
				ret = -EINVAL;
				goto end;
			}
			if (unlikely(reg[insn->reg].type != REG_S64)) {
				fprintf(stderr, "[error] Unary minus can only be applied to numeric register\n");
				ret = -EINVAL;
				goto end;
			}
			reg[insn->reg].v = -reg[insn->reg].v;
			next_pc += sizeof(struct unary_op);
			break;
		}
		case FILTER_OP_UNARY_NOT:
		{
			struct unary_op *insn = (struct unary_op *) pc;

			if (unlikely(insn->reg >= REG_ERROR)) {
				fprintf(stderr, "[error] invalid register %u\n",
					(unsigned int) insn->reg);
				ret = -EINVAL;
				goto end;
			}
			if (unlikely(reg[insn->reg].type != REG_S64)) {
				fprintf(stderr, "[error] Unary not can only be applied to numeric register\n");
				ret = -EINVAL;
				goto end;
			}
			reg[insn->reg].v = !reg[insn->reg].v;
			next_pc += sizeof(struct unary_op);
			break;
		}
		/* logical */
		case FILTER_OP_AND:
		{
			struct logical_op *insn = (struct logical_op *) pc;

			if (unlikely(reg[REG_R0].type != REG_S64)) {
				fprintf(stderr, "[error] Logical operator 'and' can only be applied to numeric register\n");
				ret = -EINVAL;
				goto end;
			}

			/* If REG_R0 is 0, skip and evaluate to 0 */
			if (reg[REG_R0].v == 0) {
				dbg_printf("Jumping to bytecode offset %u\n",
					(unsigned int) insn->skip_offset);
				next_pc = start_pc + insn->skip_offset;
				if (unlikely(next_pc <= pc)) {
					fprintf(stderr, "[error] Loops are not allowed in bytecode\n");
					ret = -EINVAL;
					goto end;
				}
			} else {
				next_pc += sizeof(struct logical_op);
			}
			break;
		}
		case FILTER_OP_OR:
		{
			struct logical_op *insn = (struct logical_op *) pc;

			if (unlikely(reg[REG_R0].type != REG_S64)) {
				fprintf(stderr, "[error] Logical operator 'and' can only be applied to numeric register\n");
				ret = -EINVAL;
				goto end;
			}

			/* If REG_R0 is nonzero, skip and evaluate to 1 */
			if (reg[REG_R0].v != 0) {
				reg[REG_R0].v = 1;
				dbg_printf("Jumping to bytecode offset %u\n",
					(unsigned int) insn->skip_offset);
				next_pc = start_pc + insn->skip_offset;
				if (unlikely(next_pc <= pc)) {
					fprintf(stderr, "[error] Loops are not allowed in bytecode\n");
					ret = -EINVAL;
					goto end;
				}
			} else {
				next_pc += sizeof(struct logical_op);
			}
			break;
		}

		/* load */
		case FILTER_OP_LOAD_FIELD_REF:
		{
			struct load_op *insn = (struct load_op *) pc;
			struct field_ref *ref = (struct field_ref *) insn->data;

			if (unlikely(insn->reg >= REG_ERROR)) {
				fprintf(stderr, "[error] invalid register %u\n",
					(unsigned int) insn->reg);
				ret = -EINVAL;
				goto end;
			}
			dbg_printf("load field ref offset %u type %u\n",
				ref->offset, ref->type);
			switch (ref->type) {
			case FIELD_REF_UNKNOWN:
			default:
				fprintf(stderr, "[error] unknown field ref type\n");
				ret = -EINVAL;
				goto end;

			case FIELD_REF_STRING:
				reg[insn->reg].str =
					*(const char * const *) &filter_stack_data[ref->offset];
				reg[insn->reg].type = REG_STRING;
				reg[insn->reg].seq_len = UINT_MAX;
				reg[insn->reg].literal = 0;
				dbg_printf("ref load string %s\n", reg[insn->reg].str);
				break;
			case FIELD_REF_SEQUENCE:
				reg[insn->reg].seq_len =
					*(unsigned long *) &filter_stack_data[ref->offset];
				reg[insn->reg].str =
					*(const char **) (&filter_stack_data[ref->offset
									+ sizeof(unsigned long)]);
				reg[insn->reg].type = REG_SEQUENCE;
				reg[insn->reg].literal = 0;
				break;
			case FIELD_REF_S64:
				memcpy(&reg[insn->reg].v, &filter_stack_data[ref->offset],
					sizeof(struct literal_numeric));
				reg[insn->reg].type = REG_S64;
				reg[insn->reg].literal = 0;
				dbg_printf("ref load s64 %" PRIi64 "\n", reg[insn->reg].v);
				break;
			}

			next_pc += sizeof(struct load_op) + sizeof(struct field_ref);
			break;
		}

		case FILTER_OP_LOAD_STRING:
		{
			struct load_op *insn = (struct load_op *) pc;

			if (unlikely(insn->reg >= REG_ERROR)) {
				fprintf(stderr, "[error] invalid register %u\n",
					(unsigned int) insn->reg);
				ret = -EINVAL;
				goto end;
			}
			dbg_printf("load string %s\n", insn->data);
			reg[insn->reg].str = insn->data;
			reg[insn->reg].type = REG_STRING;
			reg[insn->reg].seq_len = UINT_MAX;
			reg[insn->reg].literal = 1;
			next_pc += sizeof(struct load_op) + strlen(insn->data) + 1;
			break;
		}

		case FILTER_OP_LOAD_S64:
		{
			struct load_op *insn = (struct load_op *) pc;

			if (unlikely(insn->reg >= REG_ERROR)) {
				fprintf(stderr, "[error] invalid register %u\n",
					(unsigned int) insn->reg);
				ret = -EINVAL;
				goto end;
			}
			memcpy(&reg[insn->reg].v, insn->data,
				sizeof(struct literal_numeric));
			dbg_printf("load s64 %" PRIi64 "\n", reg[insn->reg].v);
			reg[insn->reg].type = REG_S64;
			next_pc += sizeof(struct load_op)
					+ sizeof(struct literal_numeric);
			break;
		}
		}
	}
end:
	/* return 0 (discard) on error */
	if (ret)
		return 0;
	return retval;
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
	uint32_t field_offset = 0;

	fprintf(stderr, "Apply reloc: %u %s\n", reloc_offset, field_name);

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
	field_ref = (struct field_ref *) &runtime->data[reloc_offset];
	switch (field->type.atype) {
	case atype_integer:
	case atype_enum:
		field_ref->type = FIELD_REF_S64;
		field_ref->type = FIELD_REF_S64;
		break;
	case atype_array:
	case atype_sequence:
		field_ref->type = FIELD_REF_SEQUENCE;
		break;
	case atype_string:
		field_ref->type = FIELD_REF_STRING;
		break;
	case atype_float:
		return -EINVAL;
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

	fprintf(stderr, "Linking\n");

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
	fprintf(stderr, "iter for %d %d\n", filter_bytecode->reloc_offset, filter_bytecode->len);
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
