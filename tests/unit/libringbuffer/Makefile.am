# SPDX-FileCopyrightText: 2023 EfficiOS, Inc
#
# SPDX-License-Identifier: LGPL-2.1-only

AM_CPPFLAGS += -I$(top_srcdir)/tests/utils

noinst_PROGRAMS = test_shm
test_shm_SOURCES = shm.c
test_shm_LDADD = \
	$(top_builddir)/src/common/libringbuffer.la \
	$(top_builddir)/src/lib/lttng-ust-common/liblttng-ust-common.la \
	$(top_builddir)/src/common/libcommon.la \
	$(top_builddir)/tests/utils/libtap.a
