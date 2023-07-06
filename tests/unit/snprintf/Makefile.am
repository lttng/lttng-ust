# SPDX-FileCopyrightText: 2023 EfficiOS, Inc
#
# SPDX-License-Identifier: LGPL-2.1-only

AM_CPPFLAGS += -I$(top_srcdir)/tests/utils

noinst_PROGRAMS = test_snprintf
test_snprintf_SOURCES = snprintf.c
test_snprintf_LDADD = \
	$(top_builddir)/src/common/libsnprintf.la \
	$(top_builddir)/tests/utils/libtap.a

EXTRA_DIST = README.md
