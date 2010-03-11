AM_CPPFLAGS = -I$(top_srcdir)/include -I$(top_srcdir)/libustcomm \
	-I$(top_srcdir)/libustcmd $(KCOMPAT_CFLAGS)

bin_PROGRAMS = ustctl

ustctl_SOURCES = \
	ustctl.c \
	$(top_srcdir)/libustcmd/ustcmd.c \
	$(top_srcdir)/libustcmd/ustcmd.h

ustctl_CFLAGS = -DUST_COMPONENT=ustctl

ustctl_LDADD = \
	$(top_builddir)/snprintf/libustsnprintf.la \
	$(top_builddir)/libustcomm/libustcomm.la
