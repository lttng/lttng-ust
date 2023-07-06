# SPDX-FileCopyrightText: 2023 EfficiOS, Inc
#
# SPDX-License-Identifier: LGPL-2.1-only

AM_CPPFLAGS += -I$(top_srcdir)/liblttng-ust-comm

lib_LTLIBRARIES = liblttng-ust-ctl.la

liblttng_ust_ctl_la_SOURCES = ustctl.c
liblttng_ust_ctl_la_LDFLAGS = \
	-version-info $(LTTNG_UST_CTL_LIBRARY_VERSION)

liblttng_ust_ctl_la_LIBADD = \
	$(top_builddir)/src/lib/lttng-ust-common/liblttng-ust-common.la \
	$(top_builddir)/src/common/libringbuffer.la \
	$(top_builddir)/src/common/libringbuffer-clients.la \
	$(top_builddir)/src/common/libcounter.la \
	$(top_builddir)/src/common/libcounter-clients.la \
	$(top_builddir)/src/common/libustcomm.la \
	$(top_builddir)/src/common/libcommon.la \
	$(DL_LIBS)
