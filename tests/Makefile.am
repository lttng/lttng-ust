SUBDIRS = . hello hello-static-lib same_line_tracepoint snprintf
#ust-basic-tracing ust-multi-test
#SUBDIRS = . hello2 basic basic_long simple_include snprintf test-nevents test-libustinstr-malloc dlopen same_line_marker trace_event register_test tracepoint libustctl_function_tests exit-fast

if CXX_WORKS
SUBDIRS += hello.cxx
endif

dist_noinst_SCRIPTS = test_loop runtests trace_matches

noinst_LIBRARIES = libtap.a

libtap_a_SOURCES = \
	tap.c \
	tap.h
