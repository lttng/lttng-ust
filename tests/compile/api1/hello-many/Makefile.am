# SPDX-FileCopyrightText: 2023 EfficiOS, Inc
#
# SPDX-License-Identifier: LGPL-2.1-only

AM_CPPFLAGS += -I$(srcdir)

noinst_PROGRAMS = hello-many hello-many-compatapi1

hello_many_SOURCES = hello-many.c tp.c ust_tests_hello_many.h
hello_many_CFLAGS = -Werror=old-style-definition $(AM_CFLAGS)
hello_many_LDADD = \
	$(top_builddir)/src/lib/lttng-ust/liblttng-ust.la \
	$(DL_LIBS)

# Compile without API0 compat macros
hello_many_compatapi1_SOURCES = hello-many.c tp.c ust_tests_hello_many.h
hello_many_compatapi1_CFLAGS = -Werror=old-style-definition -DLTTNG_UST_COMPAT_API_VERSION=1 $(AM_CFLAGS)
hello_many_compatapi1_LDADD = \
	$(top_builddir)/src/lib/lttng-ust/liblttng-ust.la \
	$(DL_LIBS)

EXTRA_DIST = README.md
