# SPDX-FileCopyrightText: 2023 EfficiOS, Inc
#
# SPDX-License-Identifier: LGPL-2.1-only

AM_CPPFLAGS += -I$(top_srcdir)/liblttng-ust -I$(top_srcdir)/tests/utils

noinst_PROGRAMS = test_pthread_name
test_pthread_name_SOURCES = pthread_name.c
test_pthread_name_LDADD = $(top_builddir)/tests/utils/libtap.a
