ACLOCAL_AMFLAGS = -I config

SUBDIRS = . include snprintf libringbuffer liblttng-ust-comm \
		liblttng-ust \
		liblttng-ust-ctl \
		liblttng-ust-fork \
		liblttng-ust-libc-wrapper \
		tools \
		tests \
		doc

#disabled for 2.0
#if BUILD_JNI_INTERFACE
#SUBDIRS += liblttng-ust-java
#endif

#temporarily disabled
# liblttng-ust-malloc

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = lttng-ust.pc

dist_doc_DATA = README ChangeLog
