SUBDIRS = utils hello same_line_tracepoint snprintf benchmark

if CXX_WORKS
SUBDIRS += hello.cxx
endif

dist_noinst_SCRIPTS = test_loop run.sh unit_tests

check-am:
	./run.sh unit_tests
