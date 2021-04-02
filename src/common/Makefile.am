# SPDX-License-Identifier: LGPL-2.1-only

AUTOMAKE_OPTIONS = subdir-objects

###                        ###
### Global private headers ###
###                        ###

noinst_HEADERS = \
	align.h \
	bitfield.h \
	bitmap.h \
	dynamic-type.h \
	elf.h \
	logging.h \
	macros.h \
	patient.h \
	safe-snprintf.h \
	ustcomm.h

noinst_HEADERS += \
	compat/dlfcn.h \
	compat/tid.h

# These headers should be moved to the public headers when tested and
# documented. The symbols are still part of the ABI.

# Used by the Java jni interface.
noinst_HEADERS += \
	ust-context-provider.h

# Used by liblttng-ust-fd
noinst_HEADERS += \
	ust-fd.h

###                      ###
##  Convenience libraries ##
###                      ###

noinst_LTLIBRARIES = \
	libcounter.la \
	msgpack/libmsgpack.la \
	libringbuffer.la \
	snprintf/libsnprintf.la \
	libcommon.la

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
	counter/shm_types.h \
	counter/smp.c \
	counter/smp.h

libcounter_la_LIBADD = -lrt

if ENABLE_NUMA
libcounter_la_LIBADD += -lnuma
endif

libcounter_la_CFLAGS = -DUST_COMPONENT="libcounter" $(AM_CFLAGS)

# msgpack
msgpack_libmsgpack_la_SOURCES = \
	msgpack/msgpack.c \
	msgpack/msgpack.h

msgpack_libmsgpack_la_CFLAGS = -DUST_COMPONENT="libmsgpack" $(AM_CFLAGS)

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
	ringbuffer/getcpu.h \
	ringbuffer/mmap.h \
	ringbuffer/nohz.h \
	ringbuffer/rb-init.h \
	ringbuffer/ring_buffer_backend.c \
	ringbuffer/ringbuffer-config.h \
	ringbuffer/ring_buffer_frontend.c \
	ringbuffer/shm.c \
	ringbuffer/shm.h \
	ringbuffer/shm_internal.h \
	ringbuffer/shm_types.h \
	ringbuffer/smp.c \
	ringbuffer/smp.h \
	ringbuffer/vatomic.h

libringbuffer_la_LIBADD = \
	-lrt

if ENABLE_NUMA
libringbuffer_la_LIBADD += -lnuma
endif

libringbuffer_la_CFLAGS = -DUST_COMPONENT="libringbuffer" $(AM_CFLAGS)

# snprintf
snprintf_libsnprintf_la_SOURCES = \
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
	logging.c \
	logging.h \
	patient.c

libcommon_la_LIBADD = \
	msgpack/libmsgpack.la \
	snprintf/libsnprintf.la

EXTRA_DIST = snprintf/README
