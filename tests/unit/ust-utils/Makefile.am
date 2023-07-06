# SPDX-FileCopyrightText: 2023 EfficiOS, Inc
#
# SPDX-License-Identifier: LGPL-2.1-only

AM_CPPFLAGS += -I$(top_srcdir)/tests/utils

noinst_PROGRAMS = test_ust_utils
test_ust_utils_SOURCES = ust-utils.c ust-utils-common.h
test_ust_utils_LDADD = \
	$(top_builddir)/src/lib/lttng-ust/liblttng-ust.la \
	$(top_builddir)/tests/utils/libtap.a

if HAVE_CXX
noinst_PROGRAMS += test_ust_utils_cxx
test_ust_utils_cxx_SOURCES = ust-utils-cxx.cpp ust-utils-common.h
test_ust_utils_cxx_LDADD = \
	$(top_builddir)/src/lib/lttng-ust/liblttng-ust.la \
	$(top_builddir)/tests/utils/libtap.a
endif
