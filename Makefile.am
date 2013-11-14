ACLOCAL_AMFLAGS = -I config

SUBDIRS = . include snprintf libringbuffer liblttng-ust-comm \
		liblttng-ust \
		liblttng-ust-ctl \
		liblttng-ust-fork \
		liblttng-ust-baddr \
		liblttng-ust-dl \
		liblttng-ust-libc-wrapper \
		liblttng-ust-cyg-profile \
		tools \
		doc

if BUILD_JNI_INTERFACE
SUBDIRS += liblttng-ust-java liblttng-ust-jul
endif

SUBDIRS += tests

#temporarily disabled
# liblttng-ust-malloc

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = lttng-ust.pc

dist_doc_DATA = README ChangeLog

dist_noinst_DATA = CodingStyle
