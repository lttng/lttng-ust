# SPDX-FileCopyrightText: 2023 EfficiOS, Inc
#
# SPDX-License-Identifier: LGPL-2.1-only

AM_CPPFLAGS += -I$(top_srcdir)/tests/utils

noinst_PROGRAMS = \
	get_cpu_mask_from_sysfs \
	get_max_cpuid_from_sysfs \
	test_get_max_cpuid_from_mask \
	test_get_possible_cpus_array_len

dist_noinst_SCRIPTS = \
	test_get_cpu_mask_from_sysfs \
	test_get_max_cpuid_from_sysfs

get_cpu_mask_from_sysfs_SOURCES = get_cpu_mask_from_sysfs.c
get_cpu_mask_from_sysfs_LDADD = \
	$(top_builddir)/src/common/libcommon.la

get_max_cpuid_from_sysfs_SOURCES = get_max_cpuid_from_sysfs.c
get_max_cpuid_from_sysfs_LDADD = \
	$(top_builddir)/src/common/libcommon.la

test_get_max_cpuid_from_mask_SOURCES = test_get_max_cpuid_from_mask.c
test_get_max_cpuid_from_mask_LDADD = \
	$(top_builddir)/src/common/libcommon.la \
	$(top_builddir)/tests/utils/libtap.a

test_get_possible_cpus_array_len_SOURCES = test_get_possible_cpus_array_len.c
test_get_possible_cpus_array_len_LDADD = \
	$(top_builddir)/src/common/libcommon.la \
	$(top_builddir)/tests/utils/libtap.a
