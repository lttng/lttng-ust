AM_CFLAGS += -I$(srcdir) -fno-strict-aliasing

noinst_LTLIBRARIES = liblttng-ust-runtime.la liblttng-ust-support.la

lib_LTLIBRARIES = liblttng-ust-common.la liblttng-ust-tracepoint.la liblttng-ust.la

liblttng_ust_common_la_SOURCES = \
	lttng-ust-urcu.c \
	lttng-ust-urcu-pointer.c

liblttng_ust_common_la_LDFLAGS = -no-undefined -version-info $(LTTNG_UST_LIBRARY_VERSION)

liblttng_ust_tracepoint_la_SOURCES = \
	tracepoint.c \
	tracepoint-weak-test.c \
	tracepoint-internal.h \
	lttng-tracer-core.h \
	jhash.h \
	error.h

liblttng_ust_tracepoint_la_LIBADD = \
	liblttng-ust-common.la \
	$(top_builddir)/snprintf/libustsnprintf.la \
	$(DL_LIBS)

liblttng_ust_tracepoint_la_LDFLAGS = -no-undefined -version-info $(LTTNG_UST_LIBRARY_VERSION)
liblttng_ust_tracepoint_la_CFLAGS = -DUST_COMPONENT="liblttng_ust_tracepoint" $(AM_CFLAGS)

liblttng_ust_runtime_la_SOURCES = \
	bytecode.h \
	lttng-ust-comm.c \
	lttng-ust-abi.c \
	lttng-probes.c \
	lttng-bytecode.c \
	lttng-bytecode.h \
	lttng-bytecode-validator.c \
	lttng-bytecode-specialize.c \
	lttng-bytecode-interpreter.c \
	lttng-context-provider.c \
	lttng-context-vtid.c \
	lttng-context-vpid.c \
	lttng-context-pthread-id.c \
	lttng-context-procname.c \
	lttng-context-ip.c \
	lttng-context-cpu-id.c \
	lttng-context-cgroup-ns.c \
	lttng-context-ipc-ns.c \
	lttng-context-mnt-ns.c \
	lttng-context-net-ns.c \
	lttng-context-pid-ns.c \
	lttng-context-time-ns.c \
	lttng-context-user-ns.c \
	lttng-context-uts-ns.c \
	lttng-context-vuid.c \
	lttng-context-veuid.c \
	lttng-context-vsuid.c \
	lttng-context-vgid.c \
	lttng-context-vegid.c \
	lttng-context-vsgid.c \
	lttng-context.c \
	lttng-events.c \
	lttng-hash-helper.h \
	lttng-ust-elf.c \
	lttng-ust-statedump.c \
	lttng-ust-statedump.h \
	lttng-ust-statedump-provider.h \
	ust_lib.c \
	ust_lib.h \
	context-internal.h \
	context-provider-internal.h \
	tracepoint-internal.h \
	ust-events-internal.h \
	clock.h \
	compat.h \
	wait.h \
	jhash.h \
	lttng-ust-uuid.h \
	error.h \
	tracef.c \
	lttng-ust-tracef-provider.h \
	tracelog.c \
	lttng-ust-tracelog-provider.h \
	getenv.h \
	string-utils.c \
	string-utils.h \
	event-notifier-notification.c \
	ns.h \
	creds.h \
	rculfhash.c \
	rculfhash.h \
	rculfhash-internal.h \
	rculfhash-mm-chunk.c \
	rculfhash-mm-mmap.c \
	rculfhash-mm-order.c \
	compat_futex.c \
	futex.h

if HAVE_PERF_EVENT
liblttng_ust_runtime_la_SOURCES += \
	lttng-context-perf-counters.c \
	perf_event.h
endif

liblttng_ust_support_la_SOURCES = \
	lttng-tracer.h \
	lttng-tracer-core.h \
	ust-core.c \
	getenv.h \
	getenv.c \
	lttng-ust-dynamic-type.c \
	lttng-rb-clients.h \
	lttng-ring-buffer-client.h \
	lttng-ring-buffer-client-discard.c \
	lttng-ring-buffer-client-discard-rt.c \
	lttng-ring-buffer-client-overwrite.c \
	lttng-ring-buffer-client-overwrite-rt.c \
	lttng-ring-buffer-metadata-client.h \
	lttng-ring-buffer-metadata-client.c \
	lttng-counter-client-percpu-32-modular.c \
	lttng-counter-client-percpu-64-modular.c \
	lttng-clock.c lttng-getcpu.c

liblttng_ust_la_SOURCES =

liblttng_ust_la_LDFLAGS = -no-undefined -version-info $(LTTNG_UST_LIBRARY_VERSION)

liblttng_ust_support_la_LIBADD = \
	$(top_builddir)/libringbuffer/libringbuffer.la \
	$(top_builddir)/libcounter/libcounter.la

liblttng_ust_la_LIBADD = \
	-lrt \
	liblttng-ust-common.la \
	$(top_builddir)/snprintf/libustsnprintf.la \
	$(top_builddir)/liblttng-ust-comm/liblttng-ust-comm.la \
	liblttng-ust-tracepoint.la \
	liblttng-ust-runtime.la liblttng-ust-support.la \
	$(top_builddir)/libmsgpack/libmsgpack.la \
	$(DL_LIBS)

liblttng_ust_la_CFLAGS = -DUST_COMPONENT="liblttng_ust" $(AM_CFLAGS)
