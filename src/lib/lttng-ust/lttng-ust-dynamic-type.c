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

#include "common/macros.h"
#include "common/dynamic-type.h"

#define ctf_enum_value(_string, _value)					\
	LTTNG_UST_COMPOUND_LITERAL(struct lttng_ust_enum_entry, {		\
		.struct_size = sizeof(struct lttng_ust_enum_entry),		\
		.start = {						\
			.signedness = lttng_ust_is_signed_type(__typeof__(_value)), \
			.value = lttng_ust_is_signed_type(__typeof__(_value)) ? \
				(long long) (_value) : (_value),	\
		},							\
		.end = {						\
			.signedness = lttng_ust_is_signed_type(__typeof__(_value)), \
			.value = lttng_ust_is_signed_type(__typeof__(_value)) ? \
				(long long) (_value) : (_value),	\
		},							\
		.string = (_string),					\
	}),

static const struct lttng_ust_enum_entry *dt_enum[_NR_LTTNG_UST_DYNAMIC_TYPES] = {
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

static struct lttng_ust_enum_desc dt_enum_desc = {
	.name = "dynamic_type_enum",
	.entries = dt_enum,
	.nr_entries = LTTNG_ARRAY_SIZE(dt_enum),
};

const struct lttng_ust_event_field *dt_var_fields[_NR_LTTNG_UST_DYNAMIC_TYPES] = {
	[LTTNG_UST_DYNAMIC_TYPE_NONE] = LTTNG_UST_COMPOUND_LITERAL(const struct lttng_ust_event_field, {
		.struct_size = sizeof(struct lttng_ust_event_field),
		.name = "none",
		.type = (struct lttng_ust_type_common *) LTTNG_UST_COMPOUND_LITERAL(struct lttng_ust_type_struct, {
			.parent = {
				.type = lttng_ust_type_struct,
			},
			.struct_size = sizeof(struct lttng_ust_type_struct),
			.nr_fields = 0,	/* empty struct */
			.alignment = 0,
		}),
		.nowrite = 0,
	}),
	[LTTNG_UST_DYNAMIC_TYPE_S8] = LTTNG_UST_COMPOUND_LITERAL(const struct lttng_ust_event_field, {
		.struct_size = sizeof(struct lttng_ust_event_field),
		.name = "int8",
		.type = lttng_ust_type_integer_define(int8_t, LTTNG_UST_BYTE_ORDER, 10),
		.nowrite = 0,
	}),
	[LTTNG_UST_DYNAMIC_TYPE_S16] = LTTNG_UST_COMPOUND_LITERAL(const struct lttng_ust_event_field, {
		.struct_size = sizeof(struct lttng_ust_event_field),
		.name = "int16",
		.type = lttng_ust_type_integer_define(int16_t, LTTNG_UST_BYTE_ORDER, 10),
		.nowrite = 0,
	}),
	[LTTNG_UST_DYNAMIC_TYPE_S32] = LTTNG_UST_COMPOUND_LITERAL(const struct lttng_ust_event_field, {
		.struct_size = sizeof(struct lttng_ust_event_field),
		.name = "int32",
		.type = lttng_ust_type_integer_define(int32_t, LTTNG_UST_BYTE_ORDER, 10),
		.nowrite = 0,
	}),
	[LTTNG_UST_DYNAMIC_TYPE_S64] = LTTNG_UST_COMPOUND_LITERAL(const struct lttng_ust_event_field, {
		.struct_size = sizeof(struct lttng_ust_event_field),
		.name = "int64",
		.type = lttng_ust_type_integer_define(int64_t, LTTNG_UST_BYTE_ORDER, 10),
		.nowrite = 0,
	}),
	[LTTNG_UST_DYNAMIC_TYPE_U8] = LTTNG_UST_COMPOUND_LITERAL(const struct lttng_ust_event_field, {
		.struct_size = sizeof(struct lttng_ust_event_field),
		.name = "uint8",
		.type = lttng_ust_type_integer_define(uint8_t, LTTNG_UST_BYTE_ORDER, 10),
		.nowrite = 0,
	}),
	[LTTNG_UST_DYNAMIC_TYPE_U16] = LTTNG_UST_COMPOUND_LITERAL(const struct lttng_ust_event_field, {
		.struct_size = sizeof(struct lttng_ust_event_field),
		.name = "uint16",
		.type = lttng_ust_type_integer_define(uint16_t, LTTNG_UST_BYTE_ORDER, 10),
		.nowrite = 0,
	}),
	[LTTNG_UST_DYNAMIC_TYPE_U32] = LTTNG_UST_COMPOUND_LITERAL(const struct lttng_ust_event_field, {
		.struct_size = sizeof(struct lttng_ust_event_field),
		.name = "uint32",
		.type = lttng_ust_type_integer_define(uint32_t, LTTNG_UST_BYTE_ORDER, 10),
		.nowrite = 0,
	}),
	[LTTNG_UST_DYNAMIC_TYPE_U64] = LTTNG_UST_COMPOUND_LITERAL(const struct lttng_ust_event_field, {
		.struct_size = sizeof(struct lttng_ust_event_field),
		.name = "uint64",
		.type = lttng_ust_type_integer_define(uint64_t, LTTNG_UST_BYTE_ORDER, 10),
		.nowrite = 0,
	}),
	[LTTNG_UST_DYNAMIC_TYPE_FLOAT] = LTTNG_UST_COMPOUND_LITERAL(const struct lttng_ust_event_field, {
		.struct_size = sizeof(struct lttng_ust_event_field),
		.name = "float",
		.type = lttng_ust_type_float_define(float),
		.nowrite = 0,
	}),
	[LTTNG_UST_DYNAMIC_TYPE_DOUBLE] = LTTNG_UST_COMPOUND_LITERAL(const struct lttng_ust_event_field, {
		.struct_size = sizeof(struct lttng_ust_event_field),
		.name = "double",
		.type = lttng_ust_type_float_define(double),
		.nowrite = 0,
	}),
	[LTTNG_UST_DYNAMIC_TYPE_STRING] = LTTNG_UST_COMPOUND_LITERAL(const struct lttng_ust_event_field, {
		.struct_size = sizeof(struct lttng_ust_event_field),
		.name = "string",
		.type = (struct lttng_ust_type_common *) LTTNG_UST_COMPOUND_LITERAL(struct lttng_ust_type_string, {
			.parent = {
				.type = lttng_ust_type_string,
			},
			.struct_size = sizeof(struct lttng_ust_type_string),
			.encoding = lttng_ust_string_encoding_UTF8,
		}),
		.nowrite = 0,
	}),
};

static const struct lttng_ust_event_field dt_enum_field = {
	.struct_size = sizeof(struct lttng_ust_event_field),
	.name = NULL,
	.type = (struct lttng_ust_type_common *) LTTNG_UST_COMPOUND_LITERAL(struct lttng_ust_type_enum, {
		.parent = {
			.type = lttng_ust_type_enum,
		},
		.struct_size = sizeof(struct lttng_ust_type_enum),
		.desc = &dt_enum_desc,
		.container_type = lttng_ust_type_integer_define(char, LTTNG_UST_BYTE_ORDER, 10),
	}),
	.nowrite = 0,
};

const struct lttng_ust_event_field *lttng_ust_dynamic_type_field(int64_t value)
{
	if (value >= _NR_LTTNG_UST_DYNAMIC_TYPES || value < 0)
		return NULL;
	return dt_var_fields[value];
}

int lttng_ust_dynamic_type_choices(size_t *nr_choices, const struct lttng_ust_event_field * const **choices)
{
	*nr_choices = _NR_LTTNG_UST_DYNAMIC_TYPES;
	*choices = dt_var_fields;
	return 0;
}

const struct lttng_ust_event_field *lttng_ust_dynamic_type_tag_field(void)
{
	return &dt_enum_field;
}
