SUBDIRS = utils hello same_line_tracepoint snprintf benchmark ust-elf \
		ctf-types test-app-ctx gcc-weak-hidden

if CXX_WORKS
SUBDIRS += hello.cxx
endif

LOG_DRIVER_FLAGS='--merge'
LOG_DRIVER = env AM_TAP_AWK='$(AWK)' $(SHELL) \
	$(top_srcdir)/config/tap-driver.sh

TESTS = snprintf/test_snprintf \
	ust-elf/test_ust_elf \
	gcc-weak-hidden/test_gcc_weak_hidden

check-loop:
	while [ 0 ]; do \
		$(MAKE) $(AM_MAKEFLAGS) check; \
		if [ "$$?" != "0" ]; then \
			break; \
		fi \
	done

.PHONY: check-loop
