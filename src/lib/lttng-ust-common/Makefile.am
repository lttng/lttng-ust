# SPDX-License-Identifier: LGPL-2.1-only

lib_LTLIBRARIES = liblttng-ust-common.la

liblttng_ust_common_la_SOURCES = \
	fd-tracker.c \
	fd-tracker.h \
	ust-common.c \
	lttng-ust-urcu.c \
	lttng-ust-urcu-pointer.c

liblttng_ust_common_la_LIBADD = \
	$(top_builddir)/src/common/libcommon.la

liblttng_ust_common_la_LDFLAGS = -no-undefined -version-info $(LTTNG_UST_LIBRARY_VERSION)

