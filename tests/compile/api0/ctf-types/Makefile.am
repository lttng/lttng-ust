# SPDX-FileCopyrightText: 2023 EfficiOS, Inc
#
# SPDX-License-Identifier: LGPL-2.1-only

AM_CPPFLAGS += -I$(srcdir)

noinst_PROGRAMS = ctf-types
ctf_types_SOURCES = ctf-types.c tp.c ust_tests_ctf_types.h
ctf_types_LDADD = $(top_builddir)/src/lib/lttng-ust/liblttng-ust.la $(DL_LIBS)
ctf_types_CFLAGS = -Werror=old-style-definition $(AM_CFLAGS)
