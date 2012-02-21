AM_CPPFLAGS = -I$(top_srcdir)/include
AM_CFLAGS = -fno-strict-aliasing

noinst_LTLIBRARIES = liblttng-ust-runtime.la liblttng-ust-support.la

lib_LTLIBRARIES = liblttng-ust-tracepoint.la liblttng-ust.la

liblttng_ust_tracepoint_la_SOURCES = \
	tracepoint.c \
	tracepoint-internal.h \
	ltt-tracer-core.h \
	jhash.h \
	error.h
liblttng_ust_tracepoint_la_LIBADD = \
	-lurcu-bp
liblttng_ust_tracepoint_la_LDFLAGS = -no-undefined -version-info $(LTTNG_UST_LIBRARY_VERSION)
liblttng_ust_tracepoint_la_CFLAGS = -DUST_COMPONENT="liblttng_ust_tracepoint" -fno-strict-aliasing

liblttng_ust_runtime_la_SOURCES = \
	lttng-ust-comm.c \
	lttng-ust-abi.c \
	ltt-probes.c \
	probes/lttng-probe-ust.c \
	probes/lttng-probe-ust.h \
	lttng-context-vtid.c \
	lttng-context-vpid.c \
	lttng-context-pthread-id.c \
	lttng-context-procname.c \
	ltt-context.c \
	ltt-events.c \
	tracepoint-internal.h \
	clock.h \
	compat.h \
	wait.h \
	jhash.h \
	error.h \
	lttng-ust-uuid.h

liblttng_ust_support_la_SOURCES = \
	ltt-tracer.h \
	ltt-tracer-core.h \
	ust-core.c \
	ltt-ring-buffer-client.h \
	ltt-ring-buffer-client-discard.c \
	ltt-ring-buffer-client-overwrite.c \
	ltt-ring-buffer-metadata-client.h \
	ltt-ring-buffer-metadata-client.c

liblttng_ust_la_SOURCES =

liblttng_ust_la_LDFLAGS = -no-undefined -version-info $(LTTNG_UST_LIBRARY_VERSION)

liblttng_ust_support_la_LIBADD = \
	$(top_builddir)/libringbuffer/libringbuffer.la

liblttng_ust_la_LIBADD = \
	-lpthread \
	-lrt \
	-llttng-ust-tracepoint \
	$(top_builddir)/snprintf/libustsnprintf.la \
	$(top_builddir)/liblttng-ust-comm/liblttng-ust-comm.la \
	liblttng-ust-runtime.la liblttng-ust-support.la

if LTTNG_UST_BUILD_WITH_LIBUUID
liblttng_ust_la_LIBADD += -luuid
endif
if LTTNG_UST_BUILD_WITH_LIBC_UUID
liblttng_ust_la_LIBADD += -lc
endif

liblttng_ust_la_CFLAGS = -DUST_COMPONENT="liblttng_ust" -fno-strict-aliasing
