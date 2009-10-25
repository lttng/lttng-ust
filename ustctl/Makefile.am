AM_CPPFLAGS = -I$(top_builddir)/include -I$(top_builddir)/libustcomm \
	-I$(top_builddir)/libustcmd $(KCOMPAT_CFLAGS)

bin_PROGRAMS = ustctl
ustctl_SOURCES = ustctl.c $(top_builddir)/libustcomm/ustcomm.c $(top_builddir)/libustcomm/ustcomm.h $(top_builddir)/libustcmd/ustcmd.c $(top_builddir)/libustcmd/ustcmd.h
ustctl_CFLAGS = -DUST_COMPONENT=ustctl

