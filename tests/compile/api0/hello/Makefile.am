# SPDX-FileCopyrightText: 2023 EfficiOS, Inc
#
# SPDX-License-Identifier: LGPL-2.1-only

AM_CPPFLAGS += -I$(srcdir)

noinst_PROGRAMS = hello
hello_SOURCES = hello.c tp.c ust_tests_hello.h
hello_LDADD = $(top_builddir)/src/lib/lttng-ust/liblttng-ust.la $(DL_LIBS)
hello_CFLAGS = -Werror=old-style-definition $(AM_CFLAGS)

EXTRA_DIST = \
	Makefile.example.bsd \
	Makefile.example.linux \
	README.md
