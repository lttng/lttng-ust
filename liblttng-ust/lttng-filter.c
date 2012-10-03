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

#include "lttng-filter.h"

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

	/* Mixed S64-double binary comparators */
	[ FILTER_OP_EQ_DOUBLE_S64 ] = "EQ_DOUBLE_S64",
	[ FILTER_OP_NE_DOUBLE_S64 ] = "NE_DOUBLE_S64",
	[ FILTER_OP_GT_DOUBLE_S64 ] = "GT_DOUBLE_S64",
	[ FILTER_OP_LT_DOUBLE_S64 ] = "LT_DOUBLE_S64",
	[ FILTER_OP_GE_DOUBLE_S64 ] = "GE_DOUBLE_S64",
	[ FILTER_OP_LE_DOUBLE_S64 ] = "LE_DOUBLE_S64",

	[ FILTER_OP_EQ_S64_DOUBLE ] = "EQ_S64_DOUBLE",
	[ FILTER_OP_NE_S64_DOUBLE ] = "NE_S64_DOUBLE",
	[ FILTER_OP_GT_S64_DOUBLE ] = "GT_S64_DOUBLE",
	[ FILTER_OP_LT_S64_DOUBLE ] = "LT_S64_DOUBLE",
	[ FILTER_OP_GE_S64_DOUBLE ] = "GE_S64_DOUBLE",
	[ FILTER_OP_LE_S64_DOUBLE ] = "LE_S64_DOUBLE",

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

	/* cast */
	[ FILTER_OP_CAST_TO_S64 ] = "CAST_TO_S64",
	[ FILTER_OP_CAST_DOUBLE_TO_S64 ] = "CAST_DOUBLE_TO_S64",
	[ FILTER_OP_CAST_NOP ] = "CAST_NOP",
};

const char *print_op(enum filter_op op)
{
	if (op >= NR_FILTER_OPS)
		return "UNKNOWN";
	else
		return opnames[op];
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
	if (field_offset > FILTER_BYTECODE_MAX_LEN - 1)
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
		dbg_printf("[lttng filter] warning: cannot link event bytecode\n");
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
			dbg_printf("[lttng filter] error linking wildcard bytecode");
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
