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
	msgpack/libmsgpack.la \
	snprintf/libsnprintf.la \
	libcommon.la

# msgpack
msgpack_libmsgpack_la_SOURCES = \
	msgpack/msgpack.c \
	msgpack/msgpack.h

msgpack_libmsgpack_la_CFLAGS = -DUST_COMPONENT="libmsgpack" $(AM_CFLAGS)

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
