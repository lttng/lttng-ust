AM_CPPFLAGS = -I$(top_srcdir)/include

noinst_PROGRAMS = tracepoint_test
tracepoint_test_SOURCES = tracepoint_test.c tracepoint_test.h
tracepoint_test_LDADD = $(top_builddir)/libust/libust.la $(top_builddir)/libust-initializer.o

CFLAGS_tracepoint_test.o = -I$(src)
noinst_SCRIPTS = run
EXTRA_DIST = run
