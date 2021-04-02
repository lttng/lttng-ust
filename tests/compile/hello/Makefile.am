# SPDX-License-Identifier: LGPL-2.1-only

AM_CPPFLAGS += -I$(srcdir) -Wsystem-headers

noinst_PROGRAMS = hello
hello_SOURCES = hello.c tp.c ust_tests_hello.h
hello_CFLAGS = -Werror=old-style-definition $(AM_CFLAGS)
hello_LDADD = \
	$(top_builddir)/src/liblttng-ust/liblttng-ust.la \
	$(DL_LIBS)

EXTRA_DIST = README
