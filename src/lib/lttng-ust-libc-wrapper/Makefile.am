# SPDX-FileCopyrightText: 2023 EfficiOS, Inc
#
# SPDX-License-Identifier: LGPL-2.1-only

AM_CFLAGS += -I$(srcdir)

lib_LTLIBRARIES = liblttng-ust-libc-wrapper.la

liblttng_ust_libc_wrapper_la_SOURCES = \
	lttng-ust-malloc.c \
	ust_libc.h

liblttng_ust_libc_wrapper_la_LIBADD = \
	$(top_builddir)/src/lib/lttng-ust/liblttng-ust.la \
	$(DL_LIBS)

liblttng_ust_libc_wrapper_la_LDFLAGS = -version-info $(LTTNG_UST_LIBRARY_VERSION)

dist_noinst_SCRIPTS = run
EXTRA_DIST = README.md
