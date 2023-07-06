# SPDX-FileCopyrightText: 2023 EfficiOS, Inc
#
# SPDX-License-Identifier: LGPL-2.1-only

AM_CPPFLAGS += -I$(top_srcdir)/tests/utils -I$(srcdir)

noinst_LTLIBRARIES = \
	libfakeust0.la \
	libone.la \
	libzero.la

libfakeust0_la_SOURCES = fake-ust.c fake-ust.h
libfakeust0_la_LDFLAGS = -module -shared -avoid-version -rpath $(abs_builddir)/.libs/

libzero_la_SOURCES = libzero.c libzero.h
libzero_la_LDFLAGS = -module -shared -avoid-version -rpath $(abs_builddir)/.libs/
libzero_la_LIBADD = libfakeust0.la

libone_la_SOURCES = libone.c libone.h
libone_la_LDFLAGS = -module -shared -avoid-version -rpath $(abs_builddir)/.libs/
libone_la_LIBADD = $(top_builddir)/src/lib/lttng-ust/liblttng-ust.la

noinst_PROGRAMS = \
	app_noust \
	app_noust_dlopen \
	app_noust_indirect_abi0 \
	app_noust_indirect_abi0_abi1 \
	app_noust_indirect_abi1 \
	app_ust \
	app_ust_dlopen \
	app_ust_indirect_abi0 \
	app_ust_indirect_abi0_abi1 \
	app_ust_indirect_abi1

app_ust_SOURCES = app_ust.c tp.c ust_tests_hello.h
app_ust_LDADD = \
	$(top_builddir)/src/lib/lttng-ust/liblttng-ust.la \
	$(DL_LIBS)

app_ust_indirect_abi0_SOURCES = app_ust.c tp.c ust_tests_hello.h
app_ust_indirect_abi0_CFLAGS = -DUSE_LIBZERO $(AM_CFLAGS)
app_ust_indirect_abi0_LDADD = \
	$(top_builddir)/src/lib/lttng-ust/liblttng-ust.la \
	libzero.la \
	$(DL_LIBS)

app_ust_indirect_abi1_SOURCES = app_ust.c tp.c ust_tests_hello.h
app_ust_indirect_abi1_CFLAGS = -DUSE_LIBONE $(AM_CFLAGS)
app_ust_indirect_abi1_LDADD = \
	$(top_builddir)/src/lib/lttng-ust/liblttng-ust.la \
	libone.la \
	$(DL_LIBS)

app_ust_indirect_abi0_abi1_SOURCES = app_ust.c tp.c ust_tests_hello.h
app_ust_indirect_abi0_abi1_CFLAGS = -DUSE_LIBZERO -DUSE_LIBONE $(AM_CFLAGS)
app_ust_indirect_abi0_abi1_LDADD = \
	$(top_builddir)/src/lib/lttng-ust/liblttng-ust.la \
	libzero.la \
	libone.la \
	$(DL_LIBS)

app_ust_dlopen_SOURCES = app_ust_dlopen.c tp.c ust_tests_hello.h
app_ust_dlopen_LDADD = \
	$(top_builddir)/src/lib/lttng-ust/liblttng-ust.la \
	$(DL_LIBS)

app_noust_SOURCES = app_noust.c

app_noust_indirect_abi0_SOURCES = app_noust.c
app_noust_indirect_abi0_CFLAGS = -DUSE_LIBZERO $(AM_CFLAGS)
app_noust_indirect_abi0_LDADD = libzero.la

app_noust_indirect_abi1_SOURCES = app_noust.c
app_noust_indirect_abi1_CFLAGS = -DUSE_LIBONE $(AM_CFLAGS)
app_noust_indirect_abi1_LDADD = libone.la

app_noust_indirect_abi0_abi1_SOURCES = app_noust.c
app_noust_indirect_abi0_abi1_CFLAGS = -DUSE_LIBZERO -DUSE_LIBONE $(AM_CFLAGS)
app_noust_indirect_abi0_abi1_LDADD = libzero.la libone.la

app_noust_dlopen_SOURCES = app_noust_dlopen.c
app_noust_dlopen_LDADD = \
	$(DL_LIBS)

dist_noinst_SCRIPTS = test_abi0_conflict
