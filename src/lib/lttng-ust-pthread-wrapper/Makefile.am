# SPDX-FileCopyrightText: 2023 EfficiOS, Inc
#
# SPDX-License-Identifier: LGPL-2.1-only

AM_CFLAGS += -I$(srcdir)

lib_LTLIBRARIES = liblttng-ust-pthread-wrapper.la

liblttng_ust_pthread_wrapper_la_SOURCES = \
	lttng-ust-pthread.c \
	ust_pthread.h

liblttng_ust_pthread_wrapper_la_LIBADD = \
	$(top_builddir)/src/lib/lttng-ust/liblttng-ust.la \
	$(DL_LIBS)

liblttng_ust_pthread_wrapper_la_LDFLAGS = -version-info $(LTTNG_UST_LIBRARY_VERSION)
