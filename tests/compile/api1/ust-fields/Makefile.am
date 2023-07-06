# SPDX-FileCopyrightText: 2023 EfficiOS, Inc
#
# SPDX-License-Identifier: LGPL-2.1-only

AM_CPPFLAGS += -I$(srcdir)

noinst_PROGRAMS = ust-fields ust-fields-compatapi1

ust_fields_SOURCES = ust-fields.c tp.c ust_tests_ust_fields.h
ust_fields_CFLAGS = -Werror=old-style-definition $(AM_CFLAGS)
ust_fields_LDADD = \
	$(top_builddir)/src/lib/lttng-ust/liblttng-ust.la \
	$(DL_LIBS)

ust_fields_compatapi1_SOURCES = ust-fields.c tp.c ust_tests_ust_fields.h
ust_fields_compatapi1_CFLAGS = -Werror=old-style-definition -DLTTNG_UST_COMPAT_API_VERSION=1 $(AM_CFLAGS)
ust_fields_compatapi1_LDADD = \
	$(top_builddir)/src/lib/lttng-ust/liblttng-ust.la \
	$(DL_LIBS)

EXTRA_DIST = README.md
