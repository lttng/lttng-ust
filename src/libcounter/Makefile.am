# SPDX-License-Identifier: LGPL-2.1-only

AM_CFLAGS += -fno-strict-aliasing

noinst_LTLIBRARIES = libcounter.la

libcounter_la_SOURCES = \
	counter.c smp.c smp.h shm.c shm.h shm_internal.h shm_types.h \
	counter-api.h counter.h counter-internal.h counter-types.h \
	counter-config.h

libcounter_la_LIBADD = \
	-lpthread \
	-lrt

if ENABLE_NUMA
libcounter_la_LIBADD += -lnuma
endif

libcounter_la_CFLAGS = -DUST_COMPONENT="libcounter" $(AM_CFLAGS)
