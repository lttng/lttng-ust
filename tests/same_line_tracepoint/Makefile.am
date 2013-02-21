AM_CPPFLAGS = -I$(top_srcdir)/include -I$(top_builddir)/include -Wsystem-headers

noinst_PROGRAMS = same_line_tracepoint
same_line_tracepoint_SOURCES = same_line_tracepoint.c ust_tests_sameline.h
same_line_tracepoint_LDADD = $(top_builddir)/liblttng-ust/liblttng-ust.la

if LTTNG_UST_BUILD_WITH_LIBDL
same_line_tracepoint_LDADD += -ldl
endif
if LTTNG_UST_BUILD_WITH_LIBC_DL
same_line_tracepoint_LDADD += -lc
endif
