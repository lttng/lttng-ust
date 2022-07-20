# SPDX-License-Identifier: LGPL-2.1-only

AM_CPPFLAGS += -I$(top_srcdir)/tests/utils

noinst_PROGRAMS = test_smp
test_smp_SOURCES = test_smp.c
test_smp_LDADD = \
	$(top_builddir)/src/common/libcommon.la \
	$(top_builddir)/tests/utils/libtap.a
