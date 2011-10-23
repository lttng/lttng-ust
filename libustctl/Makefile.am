AM_CPPFLAGS = -I$(top_srcdir)/include -I$(top_srcdir)/liblttng-ust-comm
AM_CFLAGS = -fno-strict-aliasing

lib_LTLIBRARIES = libustctl.la

libustctl_la_SOURCES = ustctl.c

libustctl_la_LIBADD = $(top_builddir)/liblttng-ust-comm/liblttng-ust-comm.la \
	$(top_builddir)/libringbuffer/libringbuffer.la \
	$(top_builddir)/snprintf/libustsnprintf.la
