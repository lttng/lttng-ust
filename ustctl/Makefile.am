bin_PROGRAMS = ustctl
ustctl_SOURCES = ustctl.c $(top_builddir)/libustcomm/ustcomm.c $(top_builddir)/libustcomm/ustcomm.h $(top_builddir)/libustcmd/ustcmd.c $(top_builddir)/libustcmd/ustcmd.h $(top_builddir)/share/usterr.h
ustctl_CFLAGS = -DUST_COMPONENT=ust

INCLUDES = $(KCOMPAT_CFLAGS)
INCLUDES += -I$(top_builddir)/libustcomm
INCLUDES += -I$(top_builddir)/libustcmd
INCLUDES += -I$(top_builddir)/share
