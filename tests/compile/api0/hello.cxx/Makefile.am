# SPDX-FileCopyrightText: 2023 EfficiOS, Inc
#
# SPDX-License-Identifier: LGPL-2.1-only

AM_CPPFLAGS += -I$(srcdir)

noinst_PROGRAMS = hello
hello_SOURCES = hello.cpp tp-cpp.cpp ust_tests_hello.h
hello_LDADD = $(top_builddir)/src/lib/lttng-ust/liblttng-ust.la $(DL_LIBS)

EXTRA_DIST = README.md
