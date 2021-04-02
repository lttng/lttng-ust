# SPDX-License-Identifier: LGPL-2.1-only

AM_CPPFLAGS += -I$(top_srcdir)/tests/utils

noinst_PROGRAMS = test_shm
test_shm_SOURCES = shm.c
test_shm_LDADD = \
	$(top_builddir)/src/libringbuffer/libringbuffer.la \
	$(top_builddir)/src/liblttng-ust-comm/liblttng-ust-comm.la \
	$(top_builddir)/src/common/libcommon.la \
	$(top_builddir)/tests/utils/libtap.a
