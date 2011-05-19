AM_CPPFLAGS = -I$(top_srcdir)/include -I$(top_srcdir)/libustcomm
AM_CFLAGS = -fno-strict-aliasing

lib_LTLIBRARIES = libust.la

libust_la_SOURCES = \
	marker.c \
	tracepoint.c \
	trace_event.c \
	channels.c \
	channels.h \
	marker-control.c \
	marker-control.h \
	buffers.c \
	buffers.h \
	tracer.c \
	tracer.h \
	tracercore.c \
	tracercore.h \
	serialize.c \
	tracectl.c \
	tracerconst.h \
	type-serializer.h \
	type-serializer.c

libust_la_LDFLAGS = -no-undefined -version-info 0:0:0

libust_la_LIBADD = \
	-lpthread \
	-lrt \
	$(top_builddir)/snprintf/libustsnprintf.la \
	$(top_builddir)/libustcomm/libustcomm.la

libust_la_CFLAGS = -DUST_COMPONENT="libust" -fno-strict-aliasing
