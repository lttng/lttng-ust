AM_CPPFLAGS = -I$(top_srcdir)/include
AM_CFLAGS = -fno-strict-aliasing

noinst_LTLIBRARIES = libringbuffer.la

noinst_HEADERS = \
	smp.h

libringbuffer_la_SOURCES = \
	shm.c \
	smp.c \
	ring_buffer_backend.c \
	ring_buffer_frontend.c

libringbuffer_la_LDFLAGS = -no-undefined -version-info 0:0:0

libringbuffer_la_LIBADD = \
	-lpthread \
	-lrt

libringbuffer_la_CFLAGS = -DUST_COMPONENT="libringbuffer" -fno-strict-aliasing
