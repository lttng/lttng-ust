AM_CPPFLAGS = -I$(top_srcdir)/include
AM_CFLAGS = -fno-strict-aliasing

lib_LTLIBRARIES = libringbuffer.la

libringbuffer_la_SOURCES = \
	ring_buffer_backend.c \
	ring_buffer_frontend.c \
	ring_buffer_abi.c

libringbuffer_la_LDFLAGS = -no-undefined -version-info 0:0:0

libringbuffer_la_LIBADD = \
	-lpthread \
	-lrt \
	$(top_builddir)/snprintf/libustsnprintf.la

libringbuffer_la_CFLAGS = -DUST_COMPONENT="libringbuffer" -fno-strict-aliasing
