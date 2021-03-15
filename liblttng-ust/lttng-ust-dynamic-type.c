/*
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 * Copyright (C) 2016 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 *
 * UST dynamic type implementation.
 */

#define _LGPL_SOURCE
#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <inttypes.h>

#include <ust-helper.h>
#include <ust-dynamic-type.h>

#define ctf_enum_value(_string, _value)					\
	{								\
		.start = {						\
			.signedness = lttng_is_signed_type(__typeof__(_value)), \
			.value = lttng_is_signed_type(__typeof__(_value)) ? \
				(long long) (_value) : (_value),	\
		},							\
		.end = {						\
			.signedness = lttng_is_signed_type(__typeof__(_value)), \
			.value = lttng_is_signed_type(__typeof__(_value)) ? \
				(long long) (_value) : (_value),	\
		},							\
		.string = (_string),					\
	},

static const struct lttng_enum_entry dt_enum[_NR_LTTNG_UST_DYNAMIC_TYPES] = {
	[LTTNG_UST_DYNAMIC_TYPE_NONE] = ctf_enum_value("_none", 0)
	[LTTNG_UST_DYNAMIC_TYPE_S8] = ctf_enum_value("_int8", 1)
	[LTTNG_UST_DYNAMIC_TYPE_S16] = ctf_enum_value("_int16", 2)
	[LTTNG_UST_DYNAMIC_TYPE_S32] = ctf_enum_value("_int32", 3)
	[LTTNG_UST_DYNAMIC_TYPE_S64] = ctf_enum_value("_int64", 4)
	[LTTNG_UST_DYNAMIC_TYPE_U8] = ctf_enum_value("_uint8", 5)
	[LTTNG_UST_DYNAMIC_TYPE_U16] = ctf_enum_value("_uint16", 6)
	[LTTNG_UST_DYNAMIC_TYPE_U32] = ctf_enum_value("_uint32", 7)
	[LTTNG_UST_DYNAMIC_TYPE_U64] = ctf_enum_value("_uint64", 8)
	[LTTNG_UST_DYNAMIC_TYPE_FLOAT] = ctf_enum_value("_float", 9)
	[LTTNG_UST_DYNAMIC_TYPE_DOUBLE] = ctf_enum_value("_double", 10)
	[LTTNG_UST_DYNAMIC_TYPE_STRING] = ctf_enum_value("_string", 11)
};

static const struct lttng_enum_desc dt_enum_desc = {
	.name = "dynamic_type_enum",
	.entries = dt_enum,
	.nr_entries = LTTNG_ARRAY_SIZE(dt_enum),
};

const struct lttng_ust_event_field *dt_var_fields[_NR_LTTNG_UST_DYNAMIC_TYPES] = {
	[LTTNG_UST_DYNAMIC_TYPE_NONE] = __LTTNG_COMPOUND_LITERAL(struct lttng_ust_event_field, {
		.struct_size = sizeof(struct lttng_ust_event_field),
		.name = "none",
		.type = {
			.atype = atype_struct_nestable,
			.u.struct_nestable.nr_fields = 0,	/* empty struct. */
			.u.struct_nestable.alignment = 0,
		},
		.nowrite = 0,
	}),
	[LTTNG_UST_DYNAMIC_TYPE_S8] = __LTTNG_COMPOUND_LITERAL(struct lttng_ust_event_field, {
		.struct_size = sizeof(struct lttng_ust_event_field),
		.name = "int8",
		.type = __type_integer(int8_t, BYTE_ORDER, 10, none),
		.nowrite = 0,
	}),
	[LTTNG_UST_DYNAMIC_TYPE_S16] = __LTTNG_COMPOUND_LITERAL(struct lttng_ust_event_field, {
		.struct_size = sizeof(struct lttng_ust_event_field),
		.name = "int16",
		.type = __type_integer(int16_t, BYTE_ORDER, 10, none),
		.nowrite = 0,
	}),
	[LTTNG_UST_DYNAMIC_TYPE_S32] = __LTTNG_COMPOUND_LITERAL(struct lttng_ust_event_field, {
		.struct_size = sizeof(struct lttng_ust_event_field),
		.name = "int32",
		.type = __type_integer(int32_t, BYTE_ORDER, 10, none),
		.nowrite = 0,
	}),
	[LTTNG_UST_DYNAMIC_TYPE_S64] = __LTTNG_COMPOUND_LITERAL(struct lttng_ust_event_field, {
		.struct_size = sizeof(struct lttng_ust_event_field),
		.name = "int64",
		.type = __type_integer(int64_t, BYTE_ORDER, 10, none),
		.nowrite = 0,
	}),
	[LTTNG_UST_DYNAMIC_TYPE_U8] = __LTTNG_COMPOUND_LITERAL(struct lttng_ust_event_field, {
		.struct_size = sizeof(struct lttng_ust_event_field),
		.name = "uint8",
		.type = __type_integer(uint8_t, BYTE_ORDER, 10, none),
		.nowrite = 0,
	}),
	[LTTNG_UST_DYNAMIC_TYPE_U16] = __LTTNG_COMPOUND_LITERAL(struct lttng_ust_event_field, {
		.struct_size = sizeof(struct lttng_ust_event_field),
		.name = "uint16",
		.type = __type_integer(uint16_t, BYTE_ORDER, 10, none),
		.nowrite = 0,
	}),
	[LTTNG_UST_DYNAMIC_TYPE_U32] = __LTTNG_COMPOUND_LITERAL(struct lttng_ust_event_field, {
		.struct_size = sizeof(struct lttng_ust_event_field),
		.name = "uint32",
		.type = __type_integer(uint32_t, BYTE_ORDER, 10, none),
		.nowrite = 0,
	}),
	[LTTNG_UST_DYNAMIC_TYPE_U64] = __LTTNG_COMPOUND_LITERAL(struct lttng_ust_event_field, {
		.struct_size = sizeof(struct lttng_ust_event_field),
		.name = "uint64",
		.type = __type_integer(uint64_t, BYTE_ORDER, 10, none),
		.nowrite = 0,
	}),
	[LTTNG_UST_DYNAMIC_TYPE_FLOAT] = __LTTNG_COMPOUND_LITERAL(struct lttng_ust_event_field, {
		.struct_size = sizeof(struct lttng_ust_event_field),
		.name = "float",
		.type = __type_float(float),
		.nowrite = 0,
	}),
	[LTTNG_UST_DYNAMIC_TYPE_DOUBLE] = __LTTNG_COMPOUND_LITERAL(struct lttng_ust_event_field, {
		.struct_size = sizeof(struct lttng_ust_event_field),
		.name = "double",
		.type = __type_float(double),
		.nowrite = 0,
	}),
	[LTTNG_UST_DYNAMIC_TYPE_STRING] = __LTTNG_COMPOUND_LITERAL(struct lttng_ust_event_field, {
		.struct_size = sizeof(struct lttng_ust_event_field),
		.name = "string",
		.type = {
			.atype = atype_string,
			.u.string.encoding = lttng_encode_UTF8,
		},
		.nowrite = 0,
	}),
};

static const struct lttng_ust_event_field dt_enum_field = {
	.name = NULL,
	.type.atype = atype_enum_nestable,
	.type.u.enum_nestable.desc = &dt_enum_desc,
	.type.u.enum_nestable.container_type =
		__LTTNG_COMPOUND_LITERAL(struct lttng_type,
			__type_integer(char, BYTE_ORDER, 10, none)),
	.nowrite = 0,
};

const struct lttng_ust_event_field *lttng_ust_dynamic_type_field(int64_t value)
{
	if (value >= _NR_LTTNG_UST_DYNAMIC_TYPES || value < 0)
		return NULL;
	return dt_var_fields[value];
}

int lttng_ust_dynamic_type_choices(size_t *nr_choices, const struct lttng_ust_event_field ***choices)
{
	*nr_choices = _NR_LTTNG_UST_DYNAMIC_TYPES;
	*choices = dt_var_fields;
	return 0;
}

const struct lttng_ust_event_field *lttng_ust_dynamic_type_tag_field(void)
{
	return &dt_enum_field;
}
