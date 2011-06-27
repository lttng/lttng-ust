AM_CPPFLAGS = -I$(top_srcdir)/include
AM_CFLAGS = -fno-strict-aliasing

lib_LTLIBRARIES = libringbuffer.la

libringbuffer_la_SOURCES = \
	ring_buffer_backend.c \
	ring_buffer_frontend.c \
	ring_buffer_iterator.c \
	ring_buffer_vfs.c \
	ring_buffer_splice.c \
	ring_buffer_mmap.c \
	../libprio_heap/lttng_prio_heap.c

libringbuffer_la_LDFLAGS = -no-undefined -version-info 0:0:0

libringbuffer_la_LIBADD = \
	-lpthread \
	-lrt \
	$(top_builddir)/snprintf/libustsnprintf.la

libringbuffer_la_CFLAGS = -DUST_COMPONENT="libringbuffer" -fno-strict-aliasing
