# SPDX-FileCopyrightText: 2023 EfficiOS, Inc
#
# SPDX-License-Identifier: LGPL-2.1-only

AM_CPPFLAGS += -I$(top_srcdir)/tests/utils

noinst_PROGRAMS = test_msgpack
test_msgpack_SOURCES = test_msgpack.c
test_msgpack_LDADD = \
	$(top_builddir)/src/common/libmsgpack.la \
	$(top_builddir)/tests/utils/libtap.a

test_msgpack_CFLAGS = $(AM_CFLAGS)
