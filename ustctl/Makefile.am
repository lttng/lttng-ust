AM_CPPFLAGS = -I$(top_srcdir)/include -I$(top_srcdir)/libustcomm \
	-I$(top_srcdir)/libustcmd $(KCOMPAT_CFLAGS)
AM_CFLAGS = -fno-strict-aliasing

bin_PROGRAMS = ustctl

ustctl_SOURCES = \
	ustctl.c

ustctl_CFLAGS = -DUST_COMPONENT=ustctl -fno-strict-aliasing

ustctl_LDADD = \
	$(top_builddir)/snprintf/libustsnprintf.la \
	$(top_builddir)/libustcomm/libustcomm.la \
	$(top_builddir)/libustcmd/libustcmd.la
