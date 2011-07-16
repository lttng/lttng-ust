AM_CPPFLAGS = -I$(top_srcdir)/include
AM_CFLAGS = -fno-strict-aliasing

lib_LTLIBRARIES = libust.la

libust_la_SOURCES = \
	tracepoint.c \
	trace_event.c \
	ltt-tracer.h \
	ltt-tracer-core.h

#removed: buffers.c buffers.h

libust_la_LDFLAGS = -no-undefined -version-info 0:0:0

libust_la_LIBADD = \
	-lpthread \
	-lrt \
	$(top_builddir)/snprintf/libustsnprintf.la

libust_la_CFLAGS = -DUST_COMPONENT="libust" -fno-strict-aliasing
