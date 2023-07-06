# SPDX-FileCopyrightText: 2023 EfficiOS, Inc
#
# SPDX-License-Identifier: LGPL-2.1-only

AM_CPPFLAGS += -I$(top_srcdir)/tests/utils

noinst_PROGRAMS = test_ust_error
test_ust_error_SOURCES = ust-error.c
test_ust_error_LDADD = \
	$(top_builddir)/src/lib/lttng-ust/liblttng-ust.la \
	$(top_builddir)/tests/utils/libtap.a
