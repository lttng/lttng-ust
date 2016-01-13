/*
 * Copyright (C) 2016  Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; version 2.1 of
 * the License.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301 USA
 */

#include <stdio.h>
#include <unistd.h>
#include <string.h>

/* Internal UST API: ust-variant.h */
#include <lttng/ust-variant.h>
#include <lttng/ust-events.h>
#include <helper.h>

#define NR_ENTRIES	5

static const struct lttng_enum_entry myentries[NR_ENTRIES] = {
	[0] = {
		.start = 0,
		.end = 0,
		.string = "_mystring",
	},
	[1] = {
		.start = 1,
		.end = 1,
		.string = "_myint32",
	},
	[2] = {
		.start = 2,
		.end = 2,
		.string = "_myuint16",
	},
	[3] = {
		.start = 3,
		.end = 3,
		.string = "_mychar",
	},
	[4] = {
		.start = 4,
		.end = 4,
		.string = "_mylonglong",
	},
};

static const struct lttng_enum_desc myenum_desc = {
	.name = "myenum",
	.entries = myentries,
	.nr_entries = LTTNG_ARRAY_SIZE(myentries),
};

const struct lttng_event_field myvarfields[NR_ENTRIES] = {
	[0] = {
		.name = "mystring",
		.type = {
			.atype = atype_string,
			.u.basic.string.encoding = lttng_encode_UTF8,
		},
		.nowrite = 0,
	},
	[1] = {
		.name = "myint32",
		.type = __type_integer(int32_t, BYTE_ORDER, 10, none),
		.nowrite = 0,
	},
	[2] = {
		.name = "myuint16",
		.type = __type_integer(uint16_t, BYTE_ORDER, 10, none),
		.nowrite = 0,
	},
	[3] = {
		.name = "mychar",
		.type = __type_integer(char, BYTE_ORDER, 10, none),
		.nowrite = 0,
	},
	[4] = {
		.name = "mylonglong",
		.type = __type_integer(long long, BYTE_ORDER, 10, none),
		.nowrite = 0,
	},
};

static const struct lttng_event_field *get_field(const struct lttng_ust_type_variant *variant,
		int64_t value)
{
	if (value >= NR_ENTRIES || value < 0)
		return NULL;
	return &myvarfields[value];
}

static int get_choices(const struct lttng_ust_type_variant *variant,
		size_t *nr_choices, const struct lttng_event_field **choices)
{
	*nr_choices = NR_ENTRIES;
	*choices = myvarfields;
	return 0;
}

static const struct lttng_event_field myfields[];

static const struct lttng_ust_type_variant myvariant = {
	.tag = &myfields[0],
	.get_field = get_field,
	.get_choices = get_choices,
	.free_priv = NULL,
	.priv = NULL,
};

/* dummy event */

static void __event_probe__myprobe___myevent(void * __tp_data)
{
}

static const struct lttng_event_field myfields[] = {
	[0] = {
		.name = "mytag",
		.type.atype = atype_enum,
		.type.u.basic.enumeration.desc = &myenum_desc,
		.type.u.basic.enumeration.container_type = {
			.size = sizeof(char) * CHAR_BIT,
			.alignment = lttng_alignof(char) * CHAR_BIT,
			.signedness = lttng_is_signed_type(char),
			.reverse_byte_order = 0,
			.base = 10,
			.encoding = lttng_encode_none,
		},
		.nowrite = 0,
	},
	[1] = {
		.name = "myfield",
		.type = {
			.atype = atype_variant,
			.u.variant = &myvariant,
		},
		.nowrite = 0,
	},
};

static const struct lttng_event_desc myevent_desc = {
	.name = "myprobe:myevent",
	.probe_callback = (void (*)(void)) &__event_probe__myprobe___myevent,
	.ctx = NULL,
	.fields = myfields,
	.nr_fields = LTTNG_ARRAY_SIZE(myfields),
	.loglevel = NULL,
	.signature = "mysig",
	.u = {
		.ext = {
			.model_emf_uri = NULL,
		},
	},
};

static const struct lttng_event_desc *event_desc_array[] = {
	[0] = &myevent_desc,
};

/* Dummy probe. */

static struct lttng_probe_desc __probe_desc___myprobe = {
	.provider = "myprobe",
	.event_desc = event_desc_array,
	.nr_events = LTTNG_ARRAY_SIZE(event_desc_array),
	.head = { NULL, NULL },
	.lazy_init_head = { NULL, NULL },
	.lazy = 0,
	.major = LTTNG_UST_PROVIDER_MAJOR,
	.minor = LTTNG_UST_PROVIDER_MINOR,
};

int main(int argc, char **argv)
{
	int ret;

	ret = lttng_probe_register(&__probe_desc___myprobe);
	if (ret)
		abort();
	sleep(5);
	lttng_probe_unregister(&__probe_desc___myprobe);

	return 0;
}
