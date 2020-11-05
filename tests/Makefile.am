SUBDIRS = utils unit compile benchmark

LOG_DRIVER_FLAGS='--merge'
LOG_DRIVER = env AM_TAP_AWK='$(AWK)' $(SHELL) \
	$(srcdir)/utils/tap-driver.sh

TESTS = \
	unit/libringbuffer/test_shm \
	unit/gcc-weak-hidden/test_gcc_weak_hidden \
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
