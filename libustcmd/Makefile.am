AM_CPPFLAGS = -I$(top_srcdir)/include -I$(top_srcdir)/libustcomm
AM_CFLAGS = -fno-strict-aliasing

lib_LTLIBRARIES = libustcmd.la

libustcmd_la_SOURCES = \
	ustcmd.c

libustcmd_la_LDFLAGS = -no-undefined -version-info 0:0:0

libustcmd_la_LIBADD = \
	$(top_builddir)/libustcomm/libustcomm.la

libustcmd_la_CFLAGS = -DUST_COMPONENT="libustcmd" -fno-strict-aliasing
