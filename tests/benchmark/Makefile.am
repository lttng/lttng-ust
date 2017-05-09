AM_CPPFLAGS = -I$(top_srcdir)/include -I$(top_builddir)/include -Wsystem-headers

noinst_PROGRAMS = bench1 bench2
bench1_SOURCES = bench.c tp.c ust_tests_benchmark.h
bench1_LDADD = $(top_builddir)/liblttng-ust/liblttng-ust.la
bench2_SOURCES = bench.c tp.c ust_tests_benchmark.h
bench2_LDADD = $(top_builddir)/liblttng-ust/liblttng-ust.la
bench2_CFLAGS = -DTRACING $(AM_CFLAGS)

dist_noinst_SCRIPTS = test_benchmark ptime

extra_DIST = README

if LTTNG_UST_BUILD_WITH_LIBDL
bench1_LDADD += -ldl
bench2_LDADD += -ldl
endif
if LTTNG_UST_BUILD_WITH_LIBC_DL
bench1_LDADD += -lc
bench2_LDADD += -lc
endif
