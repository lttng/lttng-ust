# SPDX-License-Identifier: LGPL-2.1-only

AM_CFLAGS += -I$(srcdir)

lib_LTLIBRARIES = liblttng-ust.la

noinst_LTLIBRARIES = \
	liblttng-ust-runtime.la \
	liblttng-ust-support.la

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
	lttng-ust-statedump.c \
	lttng-ust-statedump.h \
	lttng-ust-statedump-provider.h \
	futex.c \
	futex.h \
	ust_lib.c \
	ust_lib.h \
	context-internal.h \
	context-provider-internal.h \
	events.h \
	clock.h \
	lttng-ust-uuid.h \
	tracef.c \
	lttng-ust-tracef-provider.h \
	tracelog.c \
	lttng-ust-tracelog-provider.h \
	event-notifier-notification.c \
	rculfhash.c \
	rculfhash.h \
	rculfhash-internal.h \
	rculfhash-mm-chunk.c \
	rculfhash-mm-mmap.c \
	rculfhash-mm-order.c \
	strerror.c

if HAVE_PERF_EVENT
liblttng_ust_runtime_la_SOURCES += \
	lttng-context-perf-counters.c \
	perf_event.h
endif

liblttng_ust_support_la_SOURCES = \
	lttng-tracer.h \
	lttng-tracer-core.h \
	ust-core.c \
	lttng-rb-clients.h \
	lttng-ring-buffer-client-template.h \
	lttng-ring-buffer-client-discard.c \
	lttng-ring-buffer-client-discard-rt.c \
	lttng-ring-buffer-client-overwrite.c \
	lttng-ring-buffer-client-overwrite-rt.c \
	lttng-ring-buffer-metadata-client-template.h \
	lttng-ring-buffer-metadata-client.c \
	lttng-counter-client.h \
	lttng-counter-client-percpu-32-modular.c \
	lttng-counter-client-percpu-64-modular.c \
	lttng-clock.c \
	getcpu.c getcpu.h

liblttng_ust_la_SOURCES =

liblttng_ust_la_LDFLAGS = -no-undefined -version-info $(LTTNG_UST_LIBRARY_VERSION)

liblttng_ust_support_la_LIBADD = \
	$(top_builddir)/src/common/libringbuffer.la \
	$(top_builddir)/src/common/libcounter.la

liblttng_ust_la_LIBADD = \
	-lrt \
	$(top_builddir)/src/lib/lttng-ust-common/liblttng-ust-common.la \
	$(top_builddir)/src/common/libustcomm.la \
	$(top_builddir)/src/common/libcommon.la \
	$(top_builddir)/src/lib/lttng-ust-tracepoint/liblttng-ust-tracepoint.la \
	liblttng-ust-runtime.la liblttng-ust-support.la \
	$(DL_LIBS)

liblttng_ust_la_CFLAGS = -DUST_COMPONENT="liblttng_ust" $(AM_CFLAGS)
