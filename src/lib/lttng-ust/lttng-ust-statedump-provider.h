/*
 * SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2013 Paul Woegerer <paul_woegerer@mentor.com>
 * Copyright (C) 2015 Antoine Busque <abusque@efficios.com>
 */

#undef LTTNG_UST_TRACEPOINT_PROVIDER
#define LTTNG_UST_TRACEPOINT_PROVIDER lttng_ust_statedump

#if !defined(_TRACEPOINT_LTTNG_UST_STATEDUMP_H) || defined(LTTNG_UST_TRACEPOINT_HEADER_MULTI_READ)
#define _TRACEPOINT_LTTNG_UST_STATEDUMP_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>
#include <stdint.h>
#include <unistd.h>
#include <lttng/ust-events.h>

#define LTTNG_UST_STATEDUMP_PROVIDER
#include <lttng/tracepoint.h>

LTTNG_UST_TRACEPOINT_EVENT(lttng_ust_statedump, start,
	LTTNG_UST_TP_ARGS(struct lttng_ust_session *, session),
	LTTNG_UST_TP_FIELDS(
		lttng_ust_field_unused(session)
	)
)

LTTNG_UST_TRACEPOINT_EVENT(lttng_ust_statedump, bin_info,
	LTTNG_UST_TP_ARGS(
		struct lttng_ust_session *, session,
		void *, baddr,
		const char*, path,
		uint64_t, memsz,
		uint8_t, is_pic,
		uint8_t, has_build_id,
		uint8_t, has_debug_link
	),
	LTTNG_UST_TP_FIELDS(
		lttng_ust_field_unused(session)
		lttng_ust_field_integer_hex(void *, baddr, baddr)
		lttng_ust_field_integer(uint64_t, memsz, memsz)
		lttng_ust_field_string(path, path)
		lttng_ust_field_integer(uint8_t, is_pic, is_pic)
		lttng_ust_field_integer(uint8_t, has_build_id, has_build_id)
		lttng_ust_field_integer(uint8_t, has_debug_link, has_debug_link)
	)
)

LTTNG_UST_TRACEPOINT_EVENT(lttng_ust_statedump, build_id,
	LTTNG_UST_TP_ARGS(
		struct lttng_ust_session *, session,
		void *, baddr,
		uint8_t *, build_id,
		size_t, build_id_len
	),
	LTTNG_UST_TP_FIELDS(
		lttng_ust_field_unused(session)
		lttng_ust_field_integer_hex(void *, baddr, baddr)
		lttng_ust_field_sequence_hex(uint8_t, build_id, build_id,
			size_t, build_id_len)
	)
)

LTTNG_UST_TRACEPOINT_EVENT(lttng_ust_statedump, debug_link,
	LTTNG_UST_TP_ARGS(
		struct lttng_ust_session *, session,
		void *, baddr,
		char *, filename,
		uint32_t, crc
	),
	LTTNG_UST_TP_FIELDS(
		lttng_ust_field_unused(session)
		lttng_ust_field_integer_hex(void *, baddr, baddr)
		lttng_ust_field_integer(uint32_t, crc, crc)
		lttng_ust_field_string(filename, filename)
	)
)

LTTNG_UST_TRACEPOINT_EVENT(lttng_ust_statedump, procname,
	LTTNG_UST_TP_ARGS(
		struct lttng_ust_session *, session,
		char *, name
	),
	LTTNG_UST_TP_FIELDS(
		lttng_ust_field_unused(session)
		lttng_ust_field_array_text(char, procname, name, LTTNG_UST_ABI_PROCNAME_LEN)
	)
)

LTTNG_UST_TRACEPOINT_EVENT(lttng_ust_statedump, end,
	LTTNG_UST_TP_ARGS(struct lttng_ust_session *, session),
	LTTNG_UST_TP_FIELDS(
		lttng_ust_field_unused(session)
	)
)

#endif /* _TRACEPOINT_LTTNG_UST_STATEDUMP_H */

#undef LTTNG_UST_TRACEPOINT_INCLUDE
#define LTTNG_UST_TRACEPOINT_INCLUDE "./lttng-ust-statedump-provider.h"

/* This part must be outside ifdef protection */
#include <lttng/tracepoint-event.h>

#ifdef __cplusplus
}
#endif
