AM_CPPFLAGS = -I$(top_srcdir)/include
AM_CFLAGS = -fno-strict-aliasing

lib_LTLIBRARIES = libust.la

libust_la_SOURCES = \
	tracepoint.c \
	ltt-tracer.h \
	ltt-tracer-core.h \
	ltt-ring-buffer-client.h \
	ltt-ring-buffer-client-discard.c \
	ltt-ring-buffer-client-overwrite.c \
	ltt-ring-buffer-metadata-client.h \
	ltt-ring-buffer-metadata-client.c \
	ltt-events.c \
	ltt-probes.c \
	lttng-ust-abi.c \
	lttng-ust-comm.c \
	ust-core.c \
	probes/lttng-probe-ust.c \
	probes/lttng-probe-ust.h \
	lttng-context-vtid.c \
	lttng-context-vpid.c \
	lttng-context-pthread-id.c \
	lttng-context-procname.c \
	ltt-context.c

libust_la_LDFLAGS = -no-undefined -version-info 0:0:0

libust_la_LIBADD = \
	-lpthread \
	-lrt \
	-luuid \
	$(top_builddir)/snprintf/libustsnprintf.la \
	$(top_builddir)/libringbuffer/libringbuffer.la \
	$(top_builddir)/liblttng-ust-comm/liblttng-ust-comm.la

libust_la_CFLAGS = -DUST_COMPONENT="libust" -fno-strict-aliasing
