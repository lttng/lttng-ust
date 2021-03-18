# SPDX-License-Identifier: LGPL-2.1-only

SUBDIRS = utils unit compile benchmark

LOG_DRIVER_FLAGS = --merge --comments
LOG_DRIVER = env AM_TAP_AWK='$(AWK)' \
	UST_TESTS_SRCDIR='$(abs_top_srcdir)/tests' \
	UST_TESTS_BUILDDIR='$(abs_top_builddir)/tests' \
	$(SHELL) $(srcdir)/utils/tap-driver.sh

TESTS = \
	unit/libringbuffer/test_shm \
	unit/gcc-weak-hidden/test_gcc_weak_hidden \
	unit/libmsgpack/test_msgpack \
	unit/pthread_name/test_pthread_name \
	unit/snprintf/test_snprintf \
	unit/ust-elf/test_ust_elf

EXTRA_DIST = README

check-loop:
	while [ 0 ]; do \
		$(MAKE) $(AM_MAKEFLAGS) check; \
		if [ "$$?" != "0" ]; then \
			break; \
		fi \
	done

.PHONY: check-loop
