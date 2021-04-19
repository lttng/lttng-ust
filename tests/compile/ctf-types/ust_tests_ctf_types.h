/*
 * SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2014 Geneviève Bastien <gbastien@versatic.net>
 */

#undef TRACEPOINT_PROVIDER
#define TRACEPOINT_PROVIDER ust_tests_ctf_types

#if !defined(_TRACEPOINT_UST_TESTS_CTF_TYPES_H) || defined(TRACEPOINT_HEADER_MULTI_READ)
#define _TRACEPOINT_UST_TESTS_CTF_TYPES_H

#include <lttng/tracepoint.h>

TRACEPOINT_ENUM(ust_tests_ctf_types, testenum,
	TP_ENUM_VALUES(
		ctf_enum_value("even", 0)
		ctf_enum_value("uneven", 1)
		ctf_enum_range("twoto4", 2, 4)
		ctf_enum_value("five\"extra\\test", 5)
	)
)

TRACEPOINT_ENUM(ust_tests_ctf_types, testenum2,
	TP_ENUM_VALUES(
		ctf_enum_value("zero", 0)
		ctf_enum_value("five", 5)
		ctf_enum_range("ten_to_twenty", 10, 20)
	)
)

/*
 * Enumeration field is used twice to make sure the type declaration
 * is entered only once in the metadata file.
 */
LTTNG_UST_TRACEPOINT_EVENT(ust_tests_ctf_types, tptest,
	LTTNG_UST_TP_ARGS(int, anint, int, enumval, int, enumval2),
	LTTNG_UST_TP_FIELDS(
		ctf_integer(int, intfield, anint)
		ctf_enum(ust_tests_ctf_types, testenum, int, enumfield, enumval)
		ctf_enum(ust_tests_ctf_types, testenum, long long,
				enumfield_bis, enumval)
		ctf_enum(ust_tests_ctf_types, testenum2, unsigned int,
				enumfield_third, enumval2)
	)
)

/*
 * Another tracepoint using the types to make sure each type is entered
 * only once in the metadata file.
 */
LTTNG_UST_TRACEPOINT_EVENT(ust_tests_ctf_types, tptest_bis,
	LTTNG_UST_TP_ARGS(int, anint, int, enumval),
	LTTNG_UST_TP_FIELDS(
		ctf_integer(int, intfield, anint)
		ctf_enum(ust_tests_ctf_types, testenum, unsigned char,
			enumfield, enumval)
	)
)

#endif /* _TRACEPOINT_UST_TESTS_CTF_TYPES_H */

#undef TRACEPOINT_INCLUDE
#define TRACEPOINT_INCLUDE "./ust_tests_ctf_types.h"

/* This part must be outside ifdef protection */
#include <lttng/tracepoint-event.h>
