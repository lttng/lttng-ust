# SPDX-FileCopyrightText: 2023 EfficiOS, Inc
#
# SPDX-License-Identifier: LGPL-2.1-only

AM_CPPFLAGS += -I$(top_srcdir)/tests/utils

noinst_LTLIBRARIES = libgcc-wh.la
libgcc_wh_la_SOURCES = libgcc-wh1.c libgcc-wh2.c libgcc-wh.h

noinst_PROGRAMS = test_gcc_weak_hidden
test_gcc_weak_hidden_SOURCES = main.c b.c b.h
test_gcc_weak_hidden_LDADD = $(top_builddir)/tests/utils/libtap.a \
	$(builddir)/libgcc-wh.la
