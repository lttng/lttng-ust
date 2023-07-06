# SPDX-FileCopyrightText: 2023 EfficiOS, Inc
#
# SPDX-License-Identifier: LGPL-2.1-only

AM_CPPFLAGS += -I$(srcdir)

noinst_PROGRAMS = hello hello-compatapi1

hello_SOURCES = hello.c tp.c ust_tests_hello.h
hello_CFLAGS = -Werror=old-style-definition $(AM_CFLAGS)
hello_LDADD = \
	$(top_builddir)/src/lib/lttng-ust/liblttng-ust.la \
	$(DL_LIBS)

# Compile without API0 compat macros
hello_compatapi1_SOURCES = hello.c tp.c ust_tests_hello.h
hello_compatapi1_CFLAGS = -Werror=old-style-definition -DLTTNG_UST_COMPAT_API_VERSION=1 $(AM_CFLAGS)
hello_compatapi1_LDADD = \
	$(top_builddir)/src/lib/lttng-ust/liblttng-ust.la \
	$(DL_LIBS)
