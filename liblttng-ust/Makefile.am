AM_CPPFLAGS = -I$(top_srcdir)/include -I$(top_builddir)/include
AM_CFLAGS = -fno-strict-aliasing

noinst_LTLIBRARIES = liblttng-ust-runtime.la liblttng-ust-support.la

lib_LTLIBRARIES = liblttng-ust-tracepoint.la liblttng-ust.la

liblttng_ust_tracepoint_la_SOURCES = \
	tracepoint.c \
	tracepoint-internal.h \
	lttng-tracer-core.h \
	jhash.h \
	error.h
liblttng_ust_tracepoint_la_LIBADD = \
	-lurcu-bp \
	$(top_builddir)/snprintf/libustsnprintf.la
liblttng_ust_tracepoint_la_LDFLAGS = -no-undefined -version-info $(LTTNG_UST_LIBRARY_VERSION)
liblttng_ust_tracepoint_la_CFLAGS = -DUST_COMPONENT="liblttng_ust_tracepoint" -fno-strict-aliasing

liblttng_ust_runtime_la_SOURCES = \
	lttng-ust-comm.c \
	lttng-ust-abi.c \
	lttng-probes.c \
	lttng-context-vtid.c \
	lttng-context-vpid.c \
	lttng-context-pthread-id.c \
	lttng-context-procname.c \
	lttng-context-ip.c \
	lttng-context.c \
	lttng-events.c \
	lttng-filter.c \
	lttng-filter.h \
	lttng-filter-validator.c \
	lttng-filter-specialize.c \
	lttng-filter-interpreter.c \
	filter-bytecode.h \
	lttng-hash-helper.h \
	tracepoint-internal.h \
	clock.h \
	compat.h \
	wait.h \
	jhash.h \
	lttng-ust-uuid.h \
	error.h

liblttng_ust_support_la_SOURCES = \
	lttng-tracer.h \
	lttng-tracer-core.h \
	ust-core.c \
	lttng-ring-buffer-client.h \
	lttng-ring-buffer-client-discard.c \
	lttng-ring-buffer-client-discard-rt.c \
	lttng-ring-buffer-client-overwrite.c \
	lttng-ring-buffer-client-overwrite-rt.c \
	lttng-ring-buffer-metadata-client.h \
	lttng-ring-buffer-metadata-client.c

liblttng_ust_la_SOURCES =

liblttng_ust_la_LDFLAGS = -no-undefined -version-info $(LTTNG_UST_LIBRARY_VERSION)

liblttng_ust_support_la_LIBADD = \
	$(top_builddir)/libringbuffer/libringbuffer.la

liblttng_ust_la_LIBADD = \
	-lpthread \
	-lrt \
	-lurcu-cds \
	$(top_builddir)/snprintf/libustsnprintf.la \
	$(top_builddir)/liblttng-ust-comm/liblttng-ust-comm.la \
	liblttng-ust-tracepoint.la \
	liblttng-ust-runtime.la liblttng-ust-support.la

liblttng_ust_la_CFLAGS = -DUST_COMPONENT="liblttng_ust" -fno-strict-aliasing
