# SPDX-License-Identifier: LGPL-2.1-only

AM_CPPFLAGS += -I$(srcdir) -Wsystem-headers

noinst_PROGRAMS = same_line_tracepoint
same_line_tracepoint_SOURCES = same_line_tracepoint.c ust_tests_sameline.h
same_line_tracepoint_LDADD = $(top_builddir)/liblttng-ust/liblttng-ust.la $(DL_LIBS)

EXTRA_DIST = README
