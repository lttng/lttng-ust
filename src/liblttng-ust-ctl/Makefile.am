# SPDX-License-Identifier: LGPL-2.1-only

AM_CPPFLAGS += -I$(top_srcdir)/liblttng-ust-comm
AM_CFLAGS += -fno-strict-aliasing

lib_LTLIBRARIES = liblttng-ust-ctl.la

liblttng_ust_ctl_la_SOURCES = ustctl.c
liblttng_ust_ctl_la_LDFLAGS = \
	-version-info $(LTTNG_UST_CTL_LIBRARY_VERSION)

liblttng_ust_ctl_la_LIBADD = \
	$(top_builddir)/src/liblttng-ust-comm/liblttng-ust-comm.la \
	$(top_builddir)/src/liblttng-ust/liblttng-ust-support.la \
	$(top_builddir)/src/snprintf/libustsnprintf.la \
	$(DL_LIBS)
