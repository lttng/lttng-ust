AM_CPPFLAGS = -I$(top_srcdir)/include

noinst_PROGRAMS = trace_event_test
trace_event_test_SOURCES = trace_event_test.c trace_event_test.h
trace_event_test_LDADD = $(top_builddir)/libust/libust.la $(top_builddir)/libust-initializer.o

CFLAGS_trace_event_test.o = -I$(src)
noinst_SCRIPTS = run
EXTRA_DIST = run
