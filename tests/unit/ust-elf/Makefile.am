# SPDX-FileCopyrightText: 2023 EfficiOS, Inc
#
# SPDX-License-Identifier: LGPL-2.1-only

AM_CPPFLAGS += -I$(top_srcdir)/tests/utils

noinst_PROGRAMS = ust-elf
ust_elf_SOURCES = ust-elf.c
ust_elf_LDADD = \
	$(top_builddir)/src/common/libcommon.la \
	$(top_builddir)/src/lib/lttng-ust-common/liblttng-ust-common.la \
	$(top_builddir)/tests/utils/libtap.a

dist_check_SCRIPTS = test_ust_elf

# Directories added to EXTRA_DIST will be recursively copied to the distribution.
EXTRA_DIST = \
	$(srcdir)/data \
	README.md
