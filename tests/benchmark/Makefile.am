# SPDX-FileCopyrightText: 2023 EfficiOS, Inc
#
# SPDX-License-Identifier: LGPL-2.1-only

AM_CPPFLAGS += -I$(srcdir)

noinst_PROGRAMS = bench1 bench2
bench1_SOURCES = bench.c tp.c ust_tests_benchmark.h
bench1_LDADD = \
	$(top_builddir)/src/lib/lttng-ust/liblttng-ust.la \
	$(DL_LIBS)

bench2_SOURCES = bench.c tp.c ust_tests_benchmark.h
bench2_CFLAGS = -DTRACING $(AM_CFLAGS)
bench2_LDADD = \
	$(top_builddir)/src/lib/lttng-ust/liblttng-ust.la \
	$(DL_LIBS)

dist_noinst_SCRIPTS = test_benchmark ptime

EXTRA_DIST = README.md
