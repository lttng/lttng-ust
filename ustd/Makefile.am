INCLUDES = -I$(top_builddir)/share -I$(top_builddir)/libust \
	 -I$(top_builddir)/libustcomm $(KCOMPAT_CFLAGS)

bin_PROGRAMS = ustd
ustd_SOURCES = lowlevel.c localerr.h ustd.c ustd.h $(top_builddir)/libustcomm/ustcomm.c $(top_builddir)/libustcomm/ustcomm.h
ustd_LDFLAGS = -lpthread
