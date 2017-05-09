AM_CPPFLAGS = -I$(top_srcdir)/include

noinst_PROGRAMS = tracepoint_benchmark
tracepoint_benchmark_SOURCES = tracepoint_benchmark.c tracepoint_benchmark.h
tracepoint_benchmark_LDADD = $(top_builddir)/libust/libust.la $(top_builddir)/libust-initializer.o -lpthread

CFLAGS_tracepoint_benchmark.o = -I$(src) -g $(AM_CFLAGS)
