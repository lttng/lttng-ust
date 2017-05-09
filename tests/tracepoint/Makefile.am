SUBDIRS = benchmark

AM_CPPFLAGS = -I$(top_srcdir)/include

#noinst_PROGRAMS = tracepoint_test
#tracepoint_test_SOURCES = tracepoint_test.c tracepoint_test.h
#tracepoint_test_LDADD = $(top_builddir)/libust/libust.la $(top_builddir)/libust-initializer.o

#FIXME: this test is broken:
#ust/tests/tracepoint/tracepoint_test.c:64: undefined reference to
#`register_trace_ust_event_msg'
#CFLAGS_tracepoint_test.o = -I$(src) $(AM_CFLAGS)
noinst_SCRIPTS = run
EXTRA_DIST = run
