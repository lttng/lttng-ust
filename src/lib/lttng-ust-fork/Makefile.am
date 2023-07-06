# SPDX-FileCopyrightText: 2023 EfficiOS, Inc
#
# SPDX-License-Identifier: LGPL-2.1-only

lib_LTLIBRARIES = liblttng-ust-fork.la
liblttng_ust_fork_la_SOURCES = ustfork.c
liblttng_ust_fork_la_LIBADD = \
	$(top_builddir)/src/lib/lttng-ust/liblttng-ust.la \
	$(DL_LIBS)

liblttng_ust_fork_la_CFLAGS = -DUST_COMPONENT=liblttng-ust-fork $(AM_CFLAGS)

liblttng_ust_fork_la_LDFLAGS = -version-info $(LTTNG_UST_LIBRARY_VERSION)
