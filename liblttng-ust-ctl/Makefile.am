AM_CPPFLAGS = -I$(top_srcdir)/include -I$(top_srcdir)/liblttng-ust-comm -I$(top_builddir)/include
AM_CFLAGS += -fno-strict-aliasing

lib_LTLIBRARIES = liblttng-ust-ctl.la

liblttng_ust_ctl_la_SOURCES = ustctl.c ust-ctl-private.h
liblttng_ust_ctl_la_LDFLAGS = \
	-version-info $(LTTNG_UST_CTL_LIBRARY_VERSION)

liblttng_ust_ctl_la_LIBADD = \
	$(top_builddir)/liblttng-ust-comm/liblttng-ust-comm.la \
	$(top_builddir)/liblttng-ust/liblttng-ust-support.la \
	$(top_builddir)/snprintf/libustsnprintf.la \
	-ldl
