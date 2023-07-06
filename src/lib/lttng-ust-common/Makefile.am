# SPDX-FileCopyrightText: 2023 EfficiOS, Inc
#
# SPDX-License-Identifier: LGPL-2.1-only

lib_LTLIBRARIES = liblttng-ust-common.la

liblttng_ust_common_la_SOURCES = \
	clock.c \
	clock.h \
	fd-tracker.c \
	fd-tracker.h \
	getcpu.c \
	getcpu.h \
	ust-common.c \
	lttng-ust-urcu.c \
	lttng-ust-urcu-pointer.c \
	ust-cancelstate.c

liblttng_ust_common_la_LIBADD = \
	$(top_builddir)/src/common/libcommon.la \
	$(DL_LIBS)

liblttng_ust_common_la_LDFLAGS = -no-undefined -version-info $(LTTNG_UST_LIBRARY_VERSION)

