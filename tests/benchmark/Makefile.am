AM_CPPFLAGS += -I$(srcdir) -Wsystem-headers

noinst_PROGRAMS = bench1 bench2
bench1_SOURCES = bench.c tp.c ust_tests_benchmark.h
bench1_LDADD = $(top_builddir)/liblttng-ust/liblttng-ust.la $(DL_LIBS)

bench2_SOURCES = bench.c tp.c ust_tests_benchmark.h
bench2_LDADD = $(top_builddir)/liblttng-ust/liblttng-ust.la $(DL_LIBS)
bench2_CFLAGS = -DTRACING $(AM_CFLAGS)

dist_noinst_SCRIPTS = test_benchmark ptime

EXTRA_DIST = README
