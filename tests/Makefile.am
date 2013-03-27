SUBDIRS = . hello hello-static-lib same_line_tracepoint snprintf

if CXX_WORKS
SUBDIRS += hello.cxx
endif

dist_noinst_SCRIPTS = test_loop run.sh trace_matches unit_tests

noinst_LIBRARIES = libtap.a

libtap_a_SOURCES = tap.c tap.h

check-am:
	./run.sh unit_tests
