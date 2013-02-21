SUBDIRS = . hello hello-static-lib same_line_tracepoint snprintf

if CXX_WORKS
SUBDIRS += hello.cxx
endif

dist_noinst_SCRIPTS = test_loop runtests trace_matches

noinst_LIBRARIES = libtap.a

libtap_a_SOURCES = \
	tap.c \
	tap.h
