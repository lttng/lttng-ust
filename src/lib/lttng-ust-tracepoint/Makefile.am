# SPDX-FileCopyrightText: 2023 EfficiOS, Inc
#
# SPDX-License-Identifier: LGPL-2.1-only

lib_LTLIBRARIES = liblttng-ust-tracepoint.la

liblttng_ust_tracepoint_la_SOURCES = \
	tracepoint.c \
	tracepoint.h \
	tracepoint-weak-test.c

liblttng_ust_tracepoint_la_LIBADD = \
	$(top_builddir)/src/lib/lttng-ust-common/liblttng-ust-common.la \
	$(top_builddir)/src/common/libcommon.la \
	$(DL_LIBS)

liblttng_ust_tracepoint_la_LDFLAGS = -no-undefined -version-info $(LTTNG_UST_LIBRARY_VERSION)
liblttng_ust_tracepoint_la_CFLAGS = -DUST_COMPONENT="liblttng_ust_tracepoint" $(AM_CFLAGS)
