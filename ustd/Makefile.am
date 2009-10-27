AM_CPPFLAGS = -I$(top_builddir)/libust -I$(top_builddir)/libustcomm \
	-I$(top_builddir)/include

bin_PROGRAMS = ustd
ustd_SOURCES = lowlevel.c ustd.c ustd.h $(top_builddir)/libustcomm/ustcomm.c $(top_builddir)/libustcomm/ustcomm.h
ustd_LDFLAGS = -lpthread
ustd_CFLAGS = -DUST_COMPONENT=ustd
