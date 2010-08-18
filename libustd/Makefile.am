AM_CPPFLAGS = -I$(top_srcdir)/libust -I$(top_srcdir)/libustcomm \
	-I$(top_srcdir)/include
AM_CFLAGS = -fno-strict-aliasing

lib_LTLIBRARIES = libustd.la

libustd_la_SOURCES = libustd.c lowlevel.c lowlevel.h

libustd_la_LDFLAGS = -no-undefined -version-info 0:0:0

libustd_la_LIBADD = \
	-lpthread \
	$(top_builddir)/snprintf/libustsnprintf.la \
	$(top_builddir)/libustcomm/libustcomm.la

libustd_la_CFLAGS = -fno-strict-aliasing

