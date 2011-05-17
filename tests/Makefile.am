SUBDIRS = . hello hello2 basic basic_long fork simple_include snprintf test-nevents test-libustinstr-malloc dlopen same_line_marker trace_event register_test tracepoint libustctl_function_tests exit-fast

dist_noinst_SCRIPTS = test_loop runtests trace_matches

lib_LTLIBRARIES = libtap.la

libtap_la_SOURCES = \
	tap.c \
	tap.h

libtap_la_LDFLAGS = -no-undefined -version-info 0:0:0

libtap_la_LIBADD = \
	-lpthread