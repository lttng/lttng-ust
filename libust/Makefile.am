AM_CPPFLAGS = -I$(top_srcdir)/include -I$(top_srcdir)/libustcomm

lib_LTLIBRARIES = libust.la
libust_la_SOURCES = \
	marker.c \
	tracepoint.c \
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
	$(top_builddir)/libustcomm/ustcomm.c \
	tracerconst.h \
	header-inline.h
libust_la_LDFLAGS = -no-undefined -version-info 0:0:0
libust_la_LIBADD = -lpthread $(top_builddir)/snprintf/libustsnprintf.la
libust_la_CFLAGS = -DUST_COMPONENT="libust"
