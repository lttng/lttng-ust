SUBDIRS = utils hello same_line_tracepoint snprintf benchmark

if CXX_WORKS
SUBDIRS += hello.cxx
endif

if BUILD_JNI_INTERFACE
SUBDIRS += java-jul
endif

SCRIPT_LIST = test_loop run.sh unit_tests

dist_noinst_SCRIPTS = $(SCRIPT_LIST)

all-local:
	@if [ x"$(srcdir)" != x"$(builddir)" ]; then \
		for script in $(SCRIPT_LIST); do \
			cp -f $(srcdir)/$$script $(builddir); \
		done; \
	fi

clean-local:
	@if [ x"$(srcdir)" != x"$(builddir)" ]; then \
		for script in $(SCRIPT_LIST); do \
			rm -f $(builddir)/$$script; \
		done; \
	fi

check-am:
	./run.sh unit_tests
