# SPDX-License-Identifier: LGPL-2.1-only

AM_CPPFLAGS += -I$(srcdir) -Wsystem-headers

noinst_PROGRAMS = hello
hello_SOURCES = hello.c tp.c ust_tests_hello.h
hello_LDADD = $(top_builddir)/liblttng-ust/liblttng-ust.la $(DL_LIBS)
hello_CFLAGS = -Werror=old-style-definition $(AM_CFLAGS)

EXTRA_DIST = README
