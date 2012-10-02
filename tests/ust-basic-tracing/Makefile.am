AM_CPPFLAGS = -I$(top_srcdir)/include -I$(top_builddir)/include -I$(top_srcdir)/libust 

noinst_PROGRAMS = ust-basic-tracing
ust_basic_tracing_SOURCES = ust-basic-tracing.c
ust_basic_tracing_LDADD = $(top_builddir)/liblttng-ust-comm/liblttng-ust-comm.la \
	$(top_builddir)/libringbuffer/libringbuffer.la \
	$(top_builddir)/snprintf/libustsnprintf.la
