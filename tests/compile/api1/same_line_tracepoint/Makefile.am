# SPDX-FileCopyrightText: 2023 EfficiOS, Inc
#
# SPDX-License-Identifier: LGPL-2.1-only

AM_CPPFLAGS += -I$(srcdir)

noinst_PROGRAMS = same_line_tracepoint same_line_tracepoint_compatapi1

same_line_tracepoint_SOURCES = same_line_tracepoint.c ust_tests_sameline.h
same_line_tracepoint_LDADD = \
	$(top_builddir)/src/lib/lttng-ust/liblttng-ust.la \
	$(DL_LIBS)

# Compile without API0 compat macros
same_line_tracepoint_compatapi1_SOURCES = same_line_tracepoint.c ust_tests_sameline.h
same_line_tracepoint_compatapi1_CFLAGS = -DLTTNG_UST_COMPAT_API_VERSION=1 $(AM_CFLAGS)
same_line_tracepoint_compatapi1_LDADD = \
	$(top_builddir)/src/lib/lttng-ust/liblttng-ust.la \
	$(DL_LIBS)

EXTRA_DIST = README.md
