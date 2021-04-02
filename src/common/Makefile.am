# SPDX-License-Identifier: LGPL-2.1-only

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
