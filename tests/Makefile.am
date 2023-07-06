# SPDX-FileCopyrightText: 2023 EfficiOS, Inc
#
# SPDX-License-Identifier: LGPL-2.1-only

SUBDIRS = utils unit compile benchmark regression

LOG_DRIVER_FLAGS = --merge --comments
LOG_DRIVER = env AM_TAP_AWK='$(AWK)' \
	UST_TESTS_SRCDIR='$(abs_top_srcdir)/tests' \
	UST_TESTS_BUILDDIR='$(abs_top_builddir)/tests' \
	$(SHELL) $(srcdir)/utils/tap-driver.sh

# Unit tests

TESTS = \
	unit/libringbuffer/test_shm \
	unit/gcc-weak-hidden/test_gcc_weak_hidden \
	unit/libcommon/test_get_cpu_mask_from_sysfs \
	unit/libcommon/test_get_max_cpuid_from_mask \
	unit/libcommon/test_get_max_cpuid_from_sysfs \
	unit/libcommon/test_get_possible_cpus_array_len \
	unit/libmsgpack/test_msgpack \
	unit/pthread_name/test_pthread_name \
	unit/snprintf/test_snprintf \
	unit/ust-elf/test_ust_elf \
	unit/ust-error/test_ust_error \
	unit/ust-utils/test_ust_utils

if HAVE_CXX
TESTS += \
	unit/ust-utils/test_ust_utils_cxx
endif

# Regression tests

TESTS += \
	regression/abi0-conflict/test_abi0_conflict

EXTRA_DIST = README.md

check-loop:
	while [ 0 ]; do \
		$(MAKE) $(AM_MAKEFLAGS) check; \
		if [ "$$?" != "0" ]; then \
			break; \
		fi \
	done

.PHONY: check-loop
