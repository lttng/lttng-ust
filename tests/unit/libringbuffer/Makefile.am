# SPDX-License-Identifier: LGPL-2.1-only

AM_CPPFLAGS += -I$(top_srcdir)/include -I$(top_srcdir)/ -I$(top_srcdir)/tests/utils

noinst_PROGRAMS = test_shm
test_shm_SOURCES = shm.c
test_shm_LDADD = \
	$(top_builddir)/libringbuffer/libringbuffer.la \
	$(top_builddir)/liblttng-ust-comm/liblttng-ust-comm.la \
	$(top_builddir)/snprintf/libustsnprintf.la \
	$(top_builddir)/tests/utils/libtap.a
