ACLOCAL_AMFLAGS = -I m4

SUBDIRS = . include snprintf libringbuffer liblttng-ust-comm \
		liblttng-ust \
		liblttng-ust-ctl \
		liblttng-ust-fd \
		liblttng-ust-fork \
		liblttng-ust-libc-wrapper \
		liblttng-ust-cyg-profile \
		tools

if HAVE_DLINFO
SUBDIRS += liblttng-ust-dl
endif

if BUILD_JNI_INTERFACE
SUBDIRS += liblttng-ust-java
endif

if BUILD_JAVA_AGENT
SUBDIRS += liblttng-ust-java-agent
endif

if BUILD_PYTHON_AGENT
SUBDIRS += python-lttngust \
		liblttng-ust-python-agent
endif

SUBDIRS += tests doc

#temporarily disabled
# liblttng-ust-malloc

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = lttng-ust.pc

dist_doc_DATA = README.md ChangeLog

dist_noinst_DATA = CodingStyle

check-loop:
	cd tests && $(MAKE) $(AM_MAKEFLAGS) check-loop
.PHONY: check-loop
