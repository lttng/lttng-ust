/*
 * lttng-ust-dynamic-type.c
 *
 * UST dynamic type implementation.
 *
 * Copyright (C) 2016 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
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

#define _GNU_SOURCE
#define _LGPL_SOURCE
#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <inttypes.h>

#include <helper.h>
#include <lttng/ust-dynamic-type.h>

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

const struct lttng_event_field dt_var_fields[_NR_LTTNG_UST_DYNAMIC_TYPES] = {
	[LTTNG_UST_DYNAMIC_TYPE_NONE] = {
		.name = "none",
		.type = {
			.atype = atype_struct,
			.u._struct.nr_fields = 0,	/* empty struct. */
		},
		.nowrite = 0,
	},
	[LTTNG_UST_DYNAMIC_TYPE_S8] = {
		.name = "int8",
		.type = __type_integer(int8_t, BYTE_ORDER, 10, none),
		.nowrite = 0,
	},
	[LTTNG_UST_DYNAMIC_TYPE_S16] = {
		.name = "int16",
		.type = __type_integer(int16_t, BYTE_ORDER, 10, none),
		.nowrite = 0,
	},
	[LTTNG_UST_DYNAMIC_TYPE_S32] = {
		.name = "int32",
		.type = __type_integer(int32_t, BYTE_ORDER, 10, none),
		.nowrite = 0,
	},
	[LTTNG_UST_DYNAMIC_TYPE_S64] = {
		.name = "int64",
		.type = __type_integer(int64_t, BYTE_ORDER, 10, none),
		.nowrite = 0,
	},
	[LTTNG_UST_DYNAMIC_TYPE_U8] = {
		.name = "uint8",
		.type = __type_integer(uint8_t, BYTE_ORDER, 10, none),
		.nowrite = 0,
	},
	[LTTNG_UST_DYNAMIC_TYPE_U16] = {
		.name = "uint16",
		.type = __type_integer(uint16_t, BYTE_ORDER, 10, none),
		.nowrite = 0,
	},
	[LTTNG_UST_DYNAMIC_TYPE_U32] = {
		.name = "uint32",
		.type = __type_integer(uint32_t, BYTE_ORDER, 10, none),
		.nowrite = 0,
	},
	[LTTNG_UST_DYNAMIC_TYPE_U64] = {
		.name = "uint64",
		.type = __type_integer(uint64_t, BYTE_ORDER, 10, none),
		.nowrite = 0,
	},
	[LTTNG_UST_DYNAMIC_TYPE_FLOAT] = {
		.name = "float",
		.type = __type_float(float),
		.nowrite = 0,
	},
	[LTTNG_UST_DYNAMIC_TYPE_DOUBLE] = {
		.name = "double",
		.type = __type_float(double),
		.nowrite = 0,
	},
	[LTTNG_UST_DYNAMIC_TYPE_STRING] = {
		.name = "string",
		.type = {
			.atype = atype_string,
			.u.basic.string.encoding = lttng_encode_UTF8,
		},
		.nowrite = 0,
	},
};

static const struct lttng_event_field dt_enum_field = {
	.name = NULL,
	.type.atype = atype_enum,
	.type.u.basic.enumeration.desc = &dt_enum_desc,
	.type.u.basic.enumeration.container_type = {
		.size = sizeof(char) * CHAR_BIT,
		.alignment = lttng_alignof(char) * CHAR_BIT,
		.signedness = lttng_is_signed_type(char),
		.reverse_byte_order = 0,
		.base = 10,
		.encoding = lttng_encode_none,
	},
	.nowrite = 0,
};

const struct lttng_event_field *lttng_ust_dynamic_type_field(int64_t value)
{
	if (value >= _NR_LTTNG_UST_DYNAMIC_TYPES || value < 0)
		return NULL;
	return &dt_var_fields[value];
}

int lttng_ust_dynamic_type_choices(size_t *nr_choices, const struct lttng_event_field **choices)
{
	*nr_choices = _NR_LTTNG_UST_DYNAMIC_TYPES;
	*choices = dt_var_fields;
	return 0;
}

const struct lttng_event_field *lttng_ust_dynamic_type_tag_field(void)
{
	return &dt_enum_field;
}
