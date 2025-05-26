# SPDX-FileCopyrightText: 2023 EfficiOS, Inc
#
# SPDX-License-Identifier: LGPL-2.1-only

AUTOMAKE_OPTIONS = subdir-objects

###                        ###
### Global private headers ###
###                        ###

noinst_HEADERS = \
	align.h \
	bitfield.h \
	bitmap.h \
	clock.h \
	creds.h \
	err-ptr.h \
	events.h \
	getcpu.h \
	hash.h \
	jhash.h \
	logging.h \
	macros.h \
	ns.h \
	patient.h \
	procname.h \
	safe-snprintf.h \
	tracepoint.h \
	tracer.h \
	wait.h

noinst_HEADERS += \
	compat/dlfcn.h \
	compat/errno.h \
	compat/mmap.h \
	compat/pthread.h \
	compat/tid.h

# These headers should be moved to the public headers when tested and
# documented. The symbols are still part of the ABI.

# Used by the Java jni interface.
noinst_HEADERS += \
	ust-context-provider.h

###                      ###
##  Convenience libraries ##
###                      ###

noinst_LTLIBRARIES = \
	libcounter.la \
	libcounter-clients.la \
	libmsgpack.la \
	libringbuffer.la \
	libringbuffer-clients.la \
	libsnprintf.la \
	libcommon.la \
	libustcomm.la

# counter
libcounter_la_SOURCES = \
	counter/counter-api.h \
	counter/counter.c \
	counter/counter-config.h \
	counter/counter.h \
	counter/counter-internal.h \
	counter/counter-types.h \
	counter/shm.c \
	counter/shm.h \
	counter/shm_internal.h \
	counter/shm_types.h

libcounter_la_LIBADD = -lrt

if ENABLE_NUMA
libcounter_la_LIBADD += -lnuma
endif

libcounter_la_CFLAGS = -DUST_COMPONENT="libcounter" $(AM_CFLAGS)

# counter-clients
libcounter_clients_la_SOURCES = \
	counter-clients/clients.c \
	counter-clients/clients.h \
	counter-clients/percpu-32-modular.c \
	counter-clients/percpu-64-modular.c

libcounter_clients_la_CFLAGS = -DUST_COMPONENT="libcounter-clients" $(AM_CFLAGS)

# msgpack
libmsgpack_la_SOURCES = \
	msgpack/msgpack.c \
	msgpack/msgpack.h

libmsgpack_la_CFLAGS = -DUST_COMPONENT="libmsgpack" $(AM_CFLAGS)

# ringbuffer
libringbuffer_la_SOURCES = \
	ringbuffer/api.h \
	ringbuffer/backend.h \
	ringbuffer/backend_internal.h \
	ringbuffer/backend_types.h \
	ringbuffer/frontend_api.h \
	ringbuffer/frontend.h \
	ringbuffer/frontend_internal.h \
	ringbuffer/frontend_types.h \
	ringbuffer/nohz.h \
	ringbuffer/rb-init.h \
	ringbuffer/ring_buffer_backend.c \
	ringbuffer/ringbuffer-config.h \
	ringbuffer/ring_buffer_frontend.c \
	ringbuffer/shm.c \
	ringbuffer/shm.h \
	ringbuffer/shm_internal.h \
	ringbuffer/shm_types.h \
	ringbuffer/vatomic.h

libringbuffer_la_LIBADD = \
	-lrt

if ENABLE_NUMA
libringbuffer_la_LIBADD += -lnuma
endif

libringbuffer_la_CFLAGS = -DUST_COMPONENT="libringbuffer" $(AM_CFLAGS)

# ringbuffer-client
libringbuffer_clients_la_SOURCES = \
	ringbuffer-clients/clients.c \
	ringbuffer-clients/clients.h \
	ringbuffer-clients/discard.c \
	ringbuffer-clients/discard-rt.c \
	ringbuffer-clients/discard-channel.c \
	ringbuffer-clients/discard-channel-rt.c \
	ringbuffer-clients/metadata.c \
	ringbuffer-clients/metadata-template.h \
	ringbuffer-clients/overwrite.c \
	ringbuffer-clients/overwrite-rt.c \
	ringbuffer-clients/overwrite-channel.c \
	ringbuffer-clients/overwrite-channel-rt.c \
	ringbuffer-clients/template.h

libringbuffer_clients_la_CFLAGS = -DUST_COMPONENT="libringbuffer-clients" $(AM_CFLAGS)

# snprintf
libsnprintf_la_SOURCES = \
	snprintf/fflush.c \
	snprintf/fileext.h \
	snprintf/floatio.h \
	snprintf/fvwrite.c \
	snprintf/fvwrite.h \
	snprintf/local.h \
	snprintf/mbrtowc_sb.c \
	snprintf/snprintf.c \
	snprintf/various.h \
	snprintf/vfprintf.c \
	snprintf/wcio.h \
	snprintf/wsetup.c

# Common library
libcommon_la_SOURCES = \
	core.c \
	dynamic-type.c \
	dynamic-type.h \
	elf.c \
	elf.h \
	events.c \
	getenv.c \
	getenv.h \
	logging.c \
	logging.h \
	smp.c \
	smp.h \
	populate.c \
	populate.h \
	strutils.c \
	strutils.h \
	utils.c \
	utils.h \
	patient.c

libcommon_la_LIBADD = \
	libmsgpack.la \
	libsnprintf.la

libustcomm_la_SOURCES = \
	ustcomm.c \
	ustcomm.h

EXTRA_DIST = snprintf/README.md
