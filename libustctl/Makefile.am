AM_CPPFLAGS = -I$(top_srcdir)/include -I$(top_srcdir)/libustcomm
AM_CFLAGS = -fno-strict-aliasing

lib_LTLIBRARIES = libustctl.la

libustctl_la_SOURCES = \
	libustctl.c

libustctl_la_LDFLAGS = -no-undefined -version-info 0:0:0

libustctl_la_LIBADD = \
	$(top_builddir)/libustcomm/libustcomm.la

libustctl_la_CFLAGS = -DUST_COMPONENT="libustctl" -fno-strict-aliasing
