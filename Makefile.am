ACLOCAL_AMFLAGS = -I config

SUBDIRS = . include doc snprintf libringbuffer liblttng-ust-comm \
		liblttng-ust \
		liblttng-ust-ctl \
		liblttng-ust-fork \
		tests

if BUILD_JNI_INTERFACE
SUBDIRS += liblttng-ust-java
endif

#temporarily disabled
# liblttng-ust-malloc

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = lttng-ust.pc
